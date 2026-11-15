// Package ingest is the client for Signal's ingest door (appsec-signal
// docs/notes/ingest-push.md): POST /v1/ingest/batch and POST /v1/enroll over TLS 1.3 to
// a server whose key is pinned, every request signed with the host's Ed25519 key (RFC
// 9421 over an RFC 9530 Content-Digest, Signal's schema/sign package).
//
// It moves bytes and reports what the door answered; deciding what an answer means for
// the spool (retry, drop, resnapshot, stop) is the caller's (internal/publish).
//
// Trust: the door is reached on an overlay address and identified only by its pinned SPKI
// hash, never by a CA or a name. Nothing in an answer is executed or followed: there are
// no redirects and no proxies, the answer body is bounded, and its only effect is a
// status, a wait and the directives the caller chooses to honour.
package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/sign"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The door's routes and limits (Signal internal/ingest/push; schema/ingesttest).
const (
	BatchPath  = "/v1/ingest/batch"
	EnrollPath = "/v1/enroll"
	// MaxBody is the largest request body the door reads (compressed bytes).
	MaxBody = 4 << 20
	// MaxDecompressed is the largest batch the door expands a gzip body to.
	MaxDecompressed = 16 << 20

	contentBinary = "application/x-protobuf"
	contentJSON   = "application/json"
	// maxAnswer bounds what is read of an answer: an IngestResponse of a full batch with
	// every event rejected is well under it.
	maxAnswer = 1 << 20
	// maxRetryAfter caps a Retry-After: the door may slow the agent, but a bogus value
	// must not park it for days.
	maxRetryAfter = time.Hour
	dialTimeout   = 10 * time.Second
	pinPrefix     = "sha256/"
)

// ErrTooLarge is a batch whose compressed body is over MaxBody, or whose encoding is over
// MaxDecompressed: the caller sends fewer events.
var ErrTooLarge = errors.New("ingest: batch over the door's body limit")

// PinError is a TLS handshake with a server whose key is not the pinned one.
type PinError struct{ Got string }

func (e *PinError) Error() string {
	return "ingest: the server's key " + e.Got + " is not the pinned key"
}

// Config configures a Client.
type Config struct {
	// URL is the door, https://<overlay address>:<port>, with no path.
	URL string
	// Pin is the door's SPKI pin, "sha256/<base64>" (signal admin ingest pin).
	Pin string
	// Key signs every request. It never leaves the process.
	Key ed25519.PrivateKey
	// LocalAddr, when set, is called with the local address of each connection to the
	// door (the agent's own view of its outbound address). It must not block.
	LocalAddr func(netip.Addr)
	// Now is the clock for signatures; nil means time.Now.
	Now func() time.Time
}

// Client talks to one door. It is safe for concurrent use.
type Client struct {
	base string
	http *http.Client
	key  ed25519.PrivateKey
	now  func() time.Time
}

// Answer is the door's reply to a request.
type Answer struct {
	Status int
	// Resp is the decoded body; nil when there was none or it was not an IngestResponse.
	Resp *eventsv1.IngestResponse
	// RetryAfter is the Retry-After header, capped at an hour; 0 when absent.
	RetryAfter time.Duration
}

// Code is the answer's error code ("rate_limited", "unknown_key", ...). An error status
// whose body names no code is "http_<status>", so a refusal never reads as none; "" otherwise.
func (a Answer) Code() string {
	if code := a.Resp.GetError().GetCode(); code != "" {
		return code
	}
	if a.Status >= http.StatusBadRequest {
		return "http_" + strconv.Itoa(a.Status)
	}
	return ""
}

// New checks the configuration and returns a client. It makes no connection.
func New(cfg Config) (*Client, error) {
	base, err := doorURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	pin, err := ParsePin(cfg.Pin)
	if err != nil {
		return nil, err
	}
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("ingest: an Ed25519 private key is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	tr := &http.Transport{
		Proxy:               nil, // the overlay is direct; an environment proxy is never used
		TLSClientConfig:     pinnedTLS(pin),
		TLSHandshakeTimeout: dialTimeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err == nil && cfg.LocalAddr != nil {
				if ap, perr := netip.ParseAddrPort(c.LocalAddr().String()); perr == nil {
					cfg.LocalAddr(ap.Addr().Unmap())
				}
			}
			return c, err
		},
	}
	return &Client{
		base: base,
		key:  cfg.Key,
		now:  now,
		http: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func doorURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("ingest: URL %q is not https://<host>:<port> with no path", raw)
	}
	return "https://" + u.Host, nil
}

// ParsePin returns the 32-byte SPKI hash of a "sha256/<base64>" pin.
func ParsePin(pin string) ([]byte, error) {
	b64, ok := strings.CutPrefix(pin, pinPrefix)
	sum, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil || len(sum) != sha256.Size {
		return nil, errors.New(`ingest: the pin is not "sha256/<base64 of 32 bytes>" (signal admin ingest pin)`)
	}
	return sum, nil
}

// PinOf is the pin of a certificate's public key (SubjectPublicKeyInfo DER), as Signal
// prints it.
func PinOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return pinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// pinnedTLS is TLS 1.3 only and trusts exactly the pinned key: no CA, no name (the door is
// dialled by overlay address and its certificate is self-signed from its seed).
func pinnedTLS(pin []byte) *tls.Config {
	want := pinPrefix + base64.StdEncoding.EncodeToString(pin)
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The chain is not checked against a CA: VerifyConnection checks the pin instead,
		// on every handshake, resumed ones included.
		InsecureSkipVerify: true, //nolint:gosec // the pin below is the trust decision
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return &PinError{Got: "(none)"}
			}
			if got := PinOf(cs.PeerCertificates[0].RawSubjectPublicKeyInfo); got != want {
				return &PinError{Got: got}
			}
			return nil
		},
	}
}

// Batch sends one batch, gzipped and signed with keyID. An error is a request that got no
// answer (network, TLS, the pin) or ErrTooLarge; any answer, whatever its status, is
// returned as an Answer.
func (c *Client) Batch(ctx context.Context, keyID string, b *eventsv1.Batch) (Answer, error) {
	raw, err := proto.Marshal(b)
	if err != nil {
		return Answer{}, fmt.Errorf("ingest: encode batch: %w", err)
	}
	if len(raw) > MaxDecompressed {
		return Answer{}, ErrTooLarge
	}
	body, err := gzipped(raw)
	if err != nil {
		return Answer{}, err
	}
	if len(body) > MaxBody {
		return Answer{}, ErrTooLarge
	}
	a, _, err := c.do(ctx, BatchPath, contentBinary, "gzip", body, keyID)
	return a, err
}

func gzipped(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("ingest: gzip: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("ingest: gzip: %w", err)
	}
	return buf.Bytes(), nil
}

// Enrolment is what a host sends to enrol with a one-time join code.
type Enrolment struct {
	JoinCode, MachineID, Hostname string
}

type enrolRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"pubkey"`
	MachineID string `json:"machine_id"`
	Hostname  string `json:"hostname"`
}

type enrolResponse struct {
	PrincipalID string `json:"principal_id"`
	KeyID       string `json:"keyid"`
}

// enrolKeyID names the key in an enrolment's signature: the door does not look it up
// (the request proves possession of the key it registers) and assigns the real key id.
const enrolKeyID = "enrol"

// Enroll registers the client's key with a join code (POST /v1/enroll, signed with that
// key). On 201 it returns the key id the door assigned; any other answer comes back as
// an Answer with keyID "".
func (c *Client) Enroll(ctx context.Context, e Enrolment) (keyID string, a Answer, err error) {
	body, err := json.Marshal(enrolRequest{
		Token:     e.JoinCode,
		PublicKey: base64.StdEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey)),
		MachineID: e.MachineID,
		Hostname:  e.Hostname,
	})
	if err != nil {
		return "", Answer{}, fmt.Errorf("ingest: encode enrolment: %w", err)
	}
	a, raw, err := c.do(ctx, EnrollPath, contentJSON, "", body, enrolKeyID)
	if err != nil || a.Status != http.StatusCreated {
		return "", a, err
	}
	var out enrolResponse
	if err := json.Unmarshal(raw, &out); err != nil || !validKeyID(out.KeyID) {
		return "", a, errors.New("ingest: the enrolment answer has no usable key id")
	}
	return out.KeyID, a, nil
}

// validKeyID is what sign accepts as a keyid (non-empty, at most 128 bytes, no quote,
// backslash or line break), so a stored key id can always sign.
func validKeyID(id string) bool {
	return id != "" && len(id) <= 128 && !strings.ContainsAny(id, "\"\\\r\n")
}

func (c *Client) do(ctx context.Context, path, contentType, encoding string, body []byte, keyID string) (Answer, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return Answer{}, nil, fmt.Errorf("ingest: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	if err := sign.Sign(req, body, c.key, keyID, c.now()); err != nil {
		return Answer{}, nil, fmt.Errorf("ingest: sign: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var pe *PinError
		if errors.As(err, &pe) {
			return Answer{}, nil, pe
		}
		return Answer{}, nil, fmt.Errorf("ingest: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return Answer{}, nil, fmt.Errorf("ingest: read answer: %w", err)
	}
	a := Answer{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), c.now())}
	a.Resp = decodeAnswer(resp.Header.Get("Content-Type"), raw)
	return a, raw, nil
}

// decodeAnswer reads an IngestResponse in the form the door wrote it (binary for a binary
// request, protojson otherwise); nil when it is neither.
func decodeAnswer(contentType string, raw []byte) *eventsv1.IngestResponse {
	if len(raw) == 0 {
		return nil
	}
	resp := &eventsv1.IngestResponse{}
	var err error
	switch strings.TrimSpace(strings.Split(contentType, ";")[0]) {
	case contentBinary:
		err = proto.Unmarshal(raw, resp)
	case contentJSON:
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(raw, resp)
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	return resp
}

// retryAfter reads a Retry-After of delay-seconds or an HTTP date, capped at
// maxRetryAfter; 0 when absent or unreadable.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		d = time.Duration(min(secs, int64(maxRetryAfter/time.Second))) * time.Second
	} else if at, err := http.ParseTime(v); err == nil {
		d = at.Sub(now)
	}
	return min(max(d, 0), maxRetryAfter)
}
