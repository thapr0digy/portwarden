package publish

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/spool"
)

const (
	streamName     = "ASM_EVENTS"
	publishTimeout = 2 * time.Second
	dedupeWindow   = 2 * time.Minute
	streamMaxAge   = 7 * 24 * time.Hour
	// defaultMaxPayload is NATS's default max_payload, used until the server said its own.
	defaultMaxPayload = 1 << 20
)

// natsTransport publishes to JetStream, one message at a time: JetStream dedupes a retry
// on Nats-Msg-Id (the event id).
type natsTransport struct {
	nc *nats.Conn
	js jetstream.JetStream

	// streamReady and usingExistingLogged are touched only by the sender goroutine.
	streamReady         bool
	usingExistingLogged bool

	perms permTracker
	// reconnected is set by nats.go's reconnect callback: the link was down, so a
	// consumer may have missed messages and a fresh snapshot follows.
	reconnected atomic.Bool
}

// newNATS connects (in the background: an unreachable server is not an error) and calls
// wake whenever the connection comes up, so the sender retries at once.
func newNATS(cfg Config, wake func()) (*natsTransport, error) {
	if cfg.CredsFile != "" && cfg.NkeyFile != "" {
		return nil, errors.New("publish: CredsFile and NkeyFile are exclusive")
	}
	for _, f := range []string{cfg.CredsFile, cfg.NkeyFile, cfg.CAFile, cfg.CertFile, cfg.KeyFile} {
		if err := readable(f); err != nil {
			return nil, err
		}
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("publish: CertFile and KeyFile must be set together")
	}
	t := &natsTransport{}
	opts := []nats.Option{
		nats.Name("portwarden"),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		// Turn off nats.go's own reconnect buffer so the spool is the only buffer and
		// its drop counter is true.
		nats.ReconnectBufSize(-1),
		nats.ReconnectWait(reconnectWait),
		// Reply inboxes (request replies and JetStream publish acks) live under
		// _INBOX_<host>.>, so a host user's subscribe permission can be limited to its
		// own inboxes instead of _INBOX.>, which would let it read every consumer's
		// deliveries.
		nats.CustomInboxPrefix(InboxPrefix(cfg.HostID)),
		// With RetryOnFailedConnect the first successful connect runs ConnectedCB,
		// later ones ReconnectedCB.
		nats.ConnectHandler(func(*nats.Conn) { wake() }),
		nats.ReconnectHandler(func(*nats.Conn) {
			t.reconnected.Store(true)
			wake()
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrPermissionViolation) {
				if !t.perms.record(err) {
					slog.Warn("nats permission violation", "subject", violationSubject(err), "err", err)
				}
				return
			}
			slog.Warn("nats async error", "err", err)
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Warn("nats disconnected", "err", err)
		}),
	}
	if cfg.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.CredsFile))
	}
	if cfg.NkeyFile != "" {
		nk, err := nats.NkeyOptionFromSeed(cfg.NkeyFile)
		if err != nil {
			return nil, fmt.Errorf("publish: nkey: %w", err)
		}
		opts = append(opts, nk)
	}
	if cfg.CAFile != "" {
		opts = append(opts, nats.RootCAs(cfg.CAFile))
	}
	if cfg.LocalAddr != nil {
		opts = append(opts, nats.SetCustomDialer(&localAddrDialer{
			d:      net.Dialer{Timeout: nats.DefaultTimeout},
			notify: cfg.LocalAddr,
		}))
	}
	if cfg.CertFile != "" {
		opts = append(opts, nats.ClientCert(cfg.CertFile, cfg.KeyFile))
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("publish: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("publish: jetstream: %w", err)
	}
	t.nc, t.js = nc, js
	return t, nil
}

// InboxPrefix is the reply-inbox prefix the agent uses for hostID: _INBOX_<hostID>.
func InboxPrefix(hostID string) string { return "_INBOX_" + hostID }

func (t *natsTransport) batchLimits() (int, int) { return 1, defaultMaxPayload }

func (t *natsTransport) maxMessage() int64 {
	if mp := t.nc.MaxPayload(); mp > 0 {
		return mp
	}
	return defaultMaxPayload
}

// resync reports a reconnect since the last call; the stream is looked up again then.
func (t *natsTransport) resync() bool {
	if !t.reconnected.Swap(false) {
		return false
	}
	t.streamReady = false
	return true
}

func (t *natsTransport) deliver(ctx context.Context, msgs []spool.Msg) delivery {
	if signalOnly(msgs[0].Subject) {
		// Left in the spool by a run that sent to Signal. Never published: a host's NATS
		// user may not publish that subject, and a denied publish stops the agent.
		return delivery{undeliverable: true, err: fmt.Errorf("%s goes only to Signal", msgs[0].Subject)}
	}
	err := t.sendOne(ctx, msgs[0])
	var perm *permanentError
	switch {
	case err == nil:
		return delivery{sent: 1}
	case errors.As(err, &perm):
		return delivery{undeliverable: true, denied: perm.denied, err: perm.err}
	}
	return delivery{err: err}
}

func (t *natsTransport) close() { t.nc.Close() }

func (t *natsTransport) sendOne(ctx context.Context, m spool.Msg) error {
	if !t.nc.IsConnected() {
		return nats.ErrDisconnected
	}
	if !t.streamReady {
		// Its own deadline: a denied lookup (host users) times out, and must not use up
		// the publish's time.
		ensureCtx, cancelEnsure := context.WithTimeout(ctx, publishTimeout)
		mark := t.perms.expect(streamAPIPrefix)
		err := t.ensureStream(ensureCtx)
		t.perms.expect("")
		cancelEnsure()
		if err != nil {
			if !t.ensureRefused(err, mark) {
				return fmt.Errorf("ensure stream: %w", err)
			}
			slog.Error("cannot look up or create stream; assuming an operator manages it",
				"stream", streamName, "err", err)
		}
		t.streamReady = true
	}
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	mark := t.perms.expect(m.Subject)
	msg := &nats.Msg{Subject: m.Subject, Data: m.Data}
	_, err := t.js.PublishMsg(ctx, msg, jetstream.WithMsgID(m.ID))
	t.perms.expect("")
	if err != nil {
		err = fmt.Errorf("publish %s: %w", m.Subject, err)
		if errors.Is(err, jetstream.ErrNoStreamResponse) {
			t.streamReady = false // stream vanished; re-ensure before the retry
		}
		if t.publishNeverSucceeds(err, m.Subject, mark) {
			return &permanentError{err: err, denied: t.perms.denied(mark, m.Subject)}
		}
		return err
	}
	return nil
}

// permanentError marks a failure that retrying cannot fix.
type permanentError struct {
	err    error
	denied bool // the server refused it for lack of permission
}

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// publishNeverSucceeds reports whether err means this exact message can never be
// accepted (too large, bad subject, not permitted, over the stream's message limit).
// Timeouts, no responders and disconnects are transient and return false.
func (t *natsTransport) publishNeverSucceeds(err error, subject string, permMark uint64) bool {
	if errors.Is(err, nats.ErrMaxPayload) || errors.Is(err, nats.ErrBadSubject) {
		return true
	}
	var api *jetstream.APIError
	if errors.As(err, &api) && api.ErrorCode == jetstream.JSErrCodeStreamMessageExceedsMaximum {
		return true
	}
	// The server reports a denied publish only through an async -ERR; the request itself
	// then just times out.
	return t.perms.denied(permMark, subject)
}

const streamAPIPrefix = "$JS.API.STREAM."

// ensureRefused reports whether a stream ensure failed in a way that retrying cannot fix:
// the user may not look up or create streams, or the server refuses the agent's config.
// Every other error (no leader, insufficient resources, timeouts) is transient.
func (t *natsTransport) ensureRefused(err error, permMark uint64) bool {
	return configRefused(err) || t.perms.denied(permMark, streamAPIPrefix)
}

// Error codes from nats-server v2.15.2 server/jetstream_errors_generated.go.
const (
	jsStreamInvalidConfig  jetstream.ErrorCode = 10052 // JSStreamInvalidConfigF
	jsStreamSubjectOverlap jetstream.ErrorCode = 10065 // JSStreamSubjectOverlapErr
	httpForbidden                              = 403
)

// configRefused reports whether err is the server refusing our stream definition for
// good: an invalid or overlapping configuration, a name-in-use refusal (ensureStream
// already treats that one as an existing stream), or an explicit authorization failure.
func configRefused(err error) bool {
	var api *jetstream.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode {
	case jetstream.JSErrCodeStreamNameInUse, jsStreamInvalidConfig, jsStreamSubjectOverlap:
		return true
	}
	return api.Code == httpForbidden
}

// permTracker remembers permission violations that the server reports asynchronously.
type permTracker struct {
	mu      sync.Mutex
	n       uint64
	errs    []string
	pending string // subject (or prefix) of the request in flight; "" when none
}

// expect sets the subject of the request about to be sent ("" when it is done) and
// returns the violation count to pass to denied.
func (t *permTracker) expect(subject string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = subject
	return t.n
}

// record stores a violation and reports whether it concerns the request in flight,
// whose caller reports the failure itself.
func (t *permTracker) record(err error) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n++
	t.errs = append(t.errs, err.Error())
	if len(t.errs) > 16 {
		t.errs = t.errs[1:]
	}
	return t.pending != "" && strings.Contains(err.Error(), t.pending)
}

func (t *permTracker) count() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// violationSubject extracts the quoted subject from a server permissions violation
// ("Permissions Violation for Subscription to \"_INBOX_x.*\""), or "" if there is none.
func violationSubject(err error) string {
	msg := err.Error()
	end := strings.LastIndex(msg, `"`)
	if end <= 0 {
		return ""
	}
	start := strings.LastIndex(msg[:end], `"`)
	if start < 0 {
		return ""
	}
	return msg[start+1 : end]
}

// denied reports whether a violation mentioning subject was recorded after mark.
func (t *permTracker) denied(mark uint64, subject string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	fresh := int(t.n - mark)
	if fresh > len(t.errs) {
		fresh = len(t.errs)
	}
	for _, e := range t.errs[len(t.errs)-fresh:] {
		if strings.Contains(e, subject) {
			return true
		}
	}
	return false
}

// ensureStream creates ASM_EVENTS with the agent's definition only when it does not
// exist. An existing stream is used as it is: an operator's retention, replicas or limits
// are never changed.
func (t *natsTransport) ensureStream(ctx context.Context) error {
	_, err := t.js.Stream(ctx, streamName)
	if err == nil {
		t.logUsingExisting()
		return nil
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return err
	}
	_, err = t.js.CreateStream(ctx, jetstream.StreamConfig{
		Name:       streamName,
		Subjects:   []string{"asm.>", "pwb.>"},
		Storage:    jetstream.FileStorage,
		MaxAge:     streamMaxAge,
		Duplicates: dedupeWindow,
	})
	if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
		// Someone else created it between the lookup and the create.
		t.logUsingExisting()
		return nil
	}
	if err == nil {
		slog.Info("created stream", "stream", streamName, "max_age", streamMaxAge)
	}
	return err
}

func (t *natsTransport) logUsingExisting() {
	if !t.usingExistingLogged {
		t.usingExistingLogged = true
		slog.Info("using existing stream as-is; its configuration is not changed", "stream", streamName)
	}
}

// localAddrDialer dials NATS and reports each connection's local address.
type localAddrDialer struct {
	d      net.Dialer
	notify func(netip.Addr)
}

func (l *localAddrDialer) Dial(network, address string) (net.Conn, error) {
	c, err := l.d.Dial(network, address)
	if err != nil {
		return nil, err
	}
	if ap, perr := netip.ParseAddrPort(c.LocalAddr().String()); perr == nil {
		l.notify(ap.Addr().Unmap())
	}
	return c, nil
}
