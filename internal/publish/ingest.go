package publish

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"

	"github.com/thapr0digy/portwarden/internal/ingest"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/spool"
	"github.com/thapr0digy/portwarden/internal/tamper"
)

// IngestConfig is Signal's ingest door (README "Pushing to Signal").
type IngestConfig struct {
	// URL is https://<overlay address>:<port>; Pin its SPKI pin (signal admin ingest pin).
	URL, Pin string
	// KeyFile is the host's nkey user seed: the one portwarden natsauth minted (Signal
	// registers its public half with import-nkeys), or one created here for a join code.
	KeyFile string
	// KeyID is the key id Signal assigned to the key. "" reads KeyIDFile; when that does
	// not exist either, the sender enrols with the join code in JoinCodeFile and writes
	// the assigned key id to KeyIDFile.
	KeyID, KeyIDFile, JoinCodeFile string
	// Hostname names the host at enrolment.
	Hostname string
}

const (
	// ingestRequestTimeout bounds one request (a 4 MiB body over the overlay).
	ingestRequestTimeout = 30 * time.Second
	// ingestMaxBackoff caps the wait between failed attempts.
	ingestMaxBackoff = 5 * time.Minute
	// ingestBatchBytes bounds the spooled bytes in one batch: the encoded batch stays
	// under the door's 4 MiB body even if gzip gained nothing.
	ingestBatchBytes = 3 << 20
)

// ingestTransport sends batches to Signal's ingest door. Only the sender goroutine uses it,
// except health, which the tamper check reads.
type ingestTransport struct {
	c                    *ingest.Client
	hostID, agentVersion string
	keyID, keyIDFile     string
	enrolment            ingest.Enrolment // its JoinCode is cleared once spent

	// maxEvents and maxBytes are the batch limits: the schema's, lowered by a LIMITS
	// directive; split, when not 0, is a smaller count to try after a batch was too large.
	maxEvents, maxBytes, split int
	failures                   int // consecutive failures, for the backoff
	resyncWanted               bool

	health ingestHealth
}

func newIngest(cfg Config) (*ingestTransport, error) {
	ic := cfg.Ingest
	t := &ingestTransport{
		hostID: cfg.HostID, agentVersion: strings.ReplaceAll(cfg.AgentVersion, "/", "_"),
		keyID: ic.KeyID, keyIDFile: ic.KeyIDFile,
		maxEvents: validate.Default.MaxBatchEvents, maxBytes: ingestBatchBytes,
	}
	if t.keyID == "" {
		kid, err := readKeyID(ic.KeyIDFile)
		if err != nil {
			return nil, err
		}
		t.keyID = kid
	}
	if t.keyID == "" {
		if ic.JoinCodeFile == "" || ic.KeyIDFile == "" {
			return nil, errors.New("publish: Signal needs the host's key id (KeyID or KeyIDFile) or a join code to enrol with (JoinCodeFile and KeyIDFile)")
		}
		code, err := os.ReadFile(ic.JoinCodeFile)
		if err != nil {
			return nil, fmt.Errorf("publish: join code: %w", err)
		}
		t.enrolment = ingest.Enrolment{JoinCode: strings.TrimSpace(string(code)), MachineID: cfg.HostID, Hostname: ic.Hostname}
		if t.enrolment.JoinCode == "" {
			return nil, fmt.Errorf("publish: join code file %s is empty", ic.JoinCodeFile)
		}
	}
	key, err := hostKey(ic.KeyFile, t.keyID == "")
	if err != nil {
		return nil, err
	}
	t.c, err = ingest.New(ingest.Config{URL: ic.URL, Pin: ic.Pin, Key: key, LocalAddr: cfg.LocalAddr})
	if err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}
	return t, nil
}

// hostKey reads the host's seed; a missing one is created when the host is about to enrol
// (a registered key must already exist: a new one would not be Signal's).
func hostKey(path string, enrolling bool) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("publish: the host key file is required for Signal")
	}
	key, err := natsauth.ReadUserKey(path)
	if errors.Is(err, fs.ErrNotExist) && enrolling {
		kp, cerr := natsauth.CreateUserSeed(path)
		if cerr != nil {
			return nil, fmt.Errorf("publish: create host key: %w", cerr)
		}
		kp.Wipe()
		slog.Info("created a host key for enrolment with Signal", "key_file", path)
		key, err = natsauth.ReadUserKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("publish: host key: %w", err)
	}
	return key, nil
}

// readKeyID returns the key id stored in path, "" when there is no such file.
func readKeyID(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("publish: key id: %w", err)
	}
	kid := strings.TrimSpace(string(b))
	if kid == "" || len(kid) > 128 || strings.ContainsAny(kid, "\"\\\r\n") {
		return "", fmt.Errorf("publish: key id file %s does not hold a key id", path)
	}
	return kid, nil
}

func writeKeyID(path, kid string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(kid+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (t *ingestTransport) batchLimits() (int, int) {
	if t.split > 0 {
		return t.split, t.maxBytes
	}
	return t.maxEvents, t.maxBytes
}

// maxMessage is one event's cap at the door.
func (t *ingestTransport) maxMessage() int64 { return int64(validate.Default.MaxEventBytes) }

func (t *ingestTransport) resync() bool {
	r := t.resyncWanted
	t.resyncWanted = false
	return r
}

func (t *ingestTransport) close() {}

func (t *ingestTransport) deliver(ctx context.Context, msgs []spool.Msg) delivery {
	ctx, cancel := context.WithTimeout(ctx, ingestRequestTimeout)
	defer cancel()
	if t.keyID == "" {
		return t.enrol(ctx)
	}
	events := make([]*eventsv1.Event, 0, len(msgs))
	for _, m := range msgs {
		ev, err := signalEvent(m, t.hostID, t.agentVersion)
		if err != nil {
			if len(events) == 0 {
				return delivery{undeliverable: true, err: err}
			}
			break // send what converts; this one is the head next time
		}
		events = append(events, ev)
	}
	a, err := t.c.Batch(ctx, t.keyID, &eventsv1.Batch{Events: events})
	if errors.Is(err, ingest.ErrTooLarge) {
		return t.tooLarge(len(events), err)
	}
	if err != nil {
		t.noteTransportError(err)
		return t.retry(err, 0)
	}
	d := t.answer(a, len(events))
	t.directives(a.Resp.GetDirectives(), &d)
	return d
}

// answer maps the door's status to what happens to the batch (appsec-signal
// docs/notes/ingest-push.md, "The request, in order").
func (t *ingestTransport) answer(a ingest.Answer, n int) delivery {
	code := a.Code()
	err := fmt.Errorf("signal answered %d %s", a.Status, code)
	switch {
	case a.Status == http.StatusOK:
		t.failures, t.split = 0, 0
		t.health.set("", "")
		for _, r := range a.Resp.GetRejected() {
			slog.Warn("signal quarantined an event (it is not resent)", "event_id", r.GetId(), "code", r.GetCode(), "reason", r.GetReason())
		}
		return delivery{sent: n}
	case a.Status == http.StatusUnauthorized:
		// unknown_key, bad_signature, bad_digest, clock_skew: the key or the clock is
		// wrong. Retrying is right (a key added at the door works at once).
		t.health.set(code, "Signal refuses this host's requests ("+code+"): check the key id, the registered key and the clock")
		return t.retry(err, 0)
	case a.Status == http.StatusForbidden:
		t.health.set(code, "Signal refuses this host ("+code+")")
		return t.retry(err, 0)
	case a.Status == http.StatusTooManyRequests || a.Status == http.StatusServiceUnavailable:
		return t.retry(err, a.RetryAfter)
	case a.Status == http.StatusUnsupportedMediaType || (a.Status == http.StatusBadRequest && code == "bad_encoding"):
		t.health.set(code, "Signal cannot read this host's requests ("+code+"): its door and this agent disagree on the encoding")
		return t.retry(err, 0)
	case a.Status == http.StatusRequestEntityTooLarge:
		return t.tooLarge(n, err)
	case a.Status == http.StatusBadRequest || a.Status == http.StatusUnprocessableEntity:
		// The batch as a whole is refused: find the event that does it by halving.
		return t.tooLarge(n, err)
	}
	return t.retry(err, a.RetryAfter)
}

// tooLarge splits a refused batch; a single event that is still refused can never be sent.
func (t *ingestTransport) tooLarge(n int, err error) delivery {
	if n <= 1 {
		t.split = 0
		return delivery{undeliverable: true, err: err}
	}
	t.split = n / 2
	return delivery{err: err, wait: time.Millisecond}
}

// retry waits at least wait (a Retry-After), and at least the jittered exponential backoff.
func (t *ingestTransport) retry(err error, wait time.Duration) delivery {
	t.failures++
	return delivery{err: err, wait: max(wait, backoff(t.failures))}
}

// backoff is the delay before attempt n+1 after n consecutive failures: exponential from
// reconnectWait, capped at ingestMaxBackoff, with full jitter in its upper half.
func backoff(n int) time.Duration {
	d := reconnectWait << min(n-1, 16)
	if d <= 0 || d > ingestMaxBackoff {
		d = ingestMaxBackoff
	}
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter, not a secret
}

func (t *ingestTransport) noteTransportError(err error) {
	var pe *ingest.PinError
	if errors.As(err, &pe) {
		t.health.set("pin_mismatch", "the ingest server's key does not match --ingest-pin: "+pe.Got)
	}
}

// directives applies what the door asked for. Nothing in them can make the agent do more
// than slow down, stop, send smaller batches or send a snapshot it would send anyway.
func (t *ingestTransport) directives(ds []*eventsv1.Directive, d *delivery) {
	for _, dir := range ds {
		switch dir.GetKind() {
		case eventsv1.Directive_RESYNC_SNAPSHOT, eventsv1.Directive_RESYNC_PROXIES:
			// A snapshot carries every proxy's route set after it, so one answers both.
			t.resyncWanted = true
		case eventsv1.Directive_BACKOFF:
			if after := time.Until(dir.GetAfter().AsTime()); after > 0 {
				d.wait = max(d.wait, min(after, time.Hour))
			}
		case eventsv1.Directive_LIMITS:
			if n := int(dir.GetMaxEvents()); n > 0 {
				t.maxEvents = min(n, validate.Default.MaxBatchEvents)
			}
			if b := int(dir.GetMaxBytes()); b > 0 {
				t.maxBytes = min(b, ingestBatchBytes)
			}
		case eventsv1.Directive_STOP:
			// A 403's own code (principal_disabled) says more than "stop".
			t.health.setUnlessRefused("stop", "Signal told this host to stop sending ("+dir.GetReason()+"); events stay in the spool until a restart")
			d.halt = true
			if d.err == nil {
				d.err = errors.New("signal sent STOP")
			}
		}
	}
}

// enrol registers the host's key with the join code and keeps the key id Signal assigned.
func (t *ingestTransport) enrol(ctx context.Context) delivery {
	kid, a, err := t.c.Enroll(ctx, t.enrolment)
	if err != nil {
		t.noteTransportError(err)
		return t.retry(fmt.Errorf("enrol: %w", err), 0)
	}
	code := a.Code()
	switch a.Status {
	case http.StatusCreated:
	case http.StatusForbidden, http.StatusConflict:
		// bad_token (unknown, spent or expired) or duplicate_host: neither changes without
		// an operator, so the run stops sending; a restart with a new code tries again.
		t.health.set(code, "Signal refused enrolment ("+code+"). If an earlier enrolment's answer was lost, this host's key may already be registered: "+
			"find its key id in Signal Settings -> Ingest or with `signal admin ingest principal list`, then pass --ingest-key-id or write it to "+t.keyIDFile)
		return delivery{halt: true, err: fmt.Errorf("enrol: signal answered %d %s", a.Status, code)}
	default:
		return t.retry(fmt.Errorf("enrol: signal answered %d %s", a.Status, code), a.RetryAfter)
	}
	t.keyID, t.enrolment.JoinCode = kid, ""
	t.failures = 0
	t.health.set("", "")
	if err := writeKeyID(t.keyIDFile, kid); err != nil {
		// This run sends; the next one cannot (the join code is spent) until the key id is
		// written to the file by hand.
		slog.Error("enrolled with Signal but could not store the key id", "key_id", kid, "key_id_file", t.keyIDFile, "err", err)
	} else {
		slog.Info("enrolled with Signal", "key_id", kid, "key_id_file", t.keyIDFile)
	}
	return delivery{}
}

// ingestHealth is the door's latest refusal ("" when it accepts), read by the tamper check.
type ingestHealth struct {
	mu           sync.Mutex
	code, detail string
}

func (h *ingestHealth) set(code, detail string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if code != "" && code != h.code {
		slog.Error("signal ingest refused", "code", code, "detail", detail)
	}
	h.code, h.detail = code, detail
}

func (h *ingestHealth) setUnlessRefused(code, detail string) {
	h.mu.Lock()
	refused := h.code != ""
	h.mu.Unlock()
	if !refused {
		h.set(code, detail)
	}
}

func (h *ingestHealth) flags() []tamper.Flag {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.code == "" {
		return nil
	}
	return []tamper.Flag{{Kind: tamper.KindIngestRefused, Subject: "signal", Detail: h.detail, Fingerprint: h.code}}
}

// ingestCheck raises ingest_refused while Signal refuses the host (401, 403, STOP, a failed
// enrolment, a request it cannot read) or the server's key is not the pinned one.
type ingestCheck struct{ h *ingestHealth }

func (ingestCheck) Name() string                  { return "ingest" }
func (c ingestCheck) Run() ([]tamper.Flag, error) { return c.h.flags(), nil }

// IngestCheck is the tamper check of the HTTPS sender's health; nil when sending to NATS.
func (p *Publisher) IngestCheck() tamper.Check {
	if t, ok := p.tr.(*ingestTransport); ok {
		return ingestCheck{&t.health}
	}
	return nil
}
