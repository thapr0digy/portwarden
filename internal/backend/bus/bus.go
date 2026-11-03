// Package bus is the backend services' side of NATS: connecting as a service user,
// parsing Portwarden subjects, durable consumers, and publishing backend events (cloud
// look-up, outside checker) that are not part of a host's sequence.
package bus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"

	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// Config says how a service connects.
type Config struct {
	URL                       string
	CredsFile, NkeyFile       string
	CAFile, CertFile, KeyFile string
	Role                      natsauth.Role
	Name                      string // client name, e.g. portwarden-inventory
	// Connected, when set, is told about every reconnect (true) and disconnect (false).
	Connected func(bool)
}

// Connect connects with reconnects forever; an unreachable server at start is retried in
// the background. The reply-inbox prefix is the role's (_INBOX_<service>), which its
// permissions allow.
func Connect(cfg Config) (*nats.Conn, jetstream.JetStream, error) {
	if cfg.URL == "" {
		return nil, nil, errors.New("bus: URL is required")
	}
	if cfg.CredsFile != "" && cfg.NkeyFile != "" {
		return nil, nil, errors.New("bus: creds and nkey files are exclusive")
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, nil, errors.New("bus: client certificate and key must be set together")
	}
	for _, f := range []string{cfg.CredsFile, cfg.NkeyFile, cfg.CAFile, cfg.CertFile, cfg.KeyFile} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err != nil {
			return nil, nil, fmt.Errorf("bus: %w", err)
		}
	}
	opts := []nats.Option{
		nats.Name(cfg.Name),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		nats.ReconnectWait(time.Second),
		nats.CustomInboxPrefix(natsauth.InboxPrefix(cfg.Role, "")),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			slog.Warn("nats async error", "err", err)
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				slog.Warn("nats disconnected", "err", err)
			}
			if cfg.Connected != nil {
				cfg.Connected(false)
			}
		}),
		nats.ReconnectHandler(func(*nats.Conn) {
			slog.Info("nats reconnected")
			if cfg.Connected != nil {
				cfg.Connected(true)
			}
		}),
	}
	if cfg.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.CredsFile))
	}
	if cfg.NkeyFile != "" {
		nk, err := nats.NkeyOptionFromSeed(cfg.NkeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("bus: nkey: %w", err)
		}
		opts = append(opts, nk)
	}
	if cfg.CAFile != "" {
		opts = append(opts, nats.RootCAs(cfg.CAFile))
	}
	if cfg.CertFile != "" {
		opts = append(opts, nats.ClientCert(cfg.CertFile, cfg.KeyFile))
	}
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("bus: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, fmt.Errorf("bus: jetstream: %w", err)
	}
	return nc, js, nil
}

// Subject kinds (the part after asm.<host>.).
const (
	KindOpened            = "listener.opened"
	KindClosed            = "listener.closed"
	KindOwnerChanged      = "listener.owner_changed"
	KindExposureChanged   = "exposure.changed"
	KindExposureConfirmed = "exposure.confirmed"
	KindProxyRoutes       = "proxy.routes"
	KindSnapshot          = "snapshot"
	KindHeartbeat         = "heartbeat"
	KindHostChanged       = "host.changed"
	KindTamper            = "tamper"
)

// ParseSubject splits "asm.<host>.<kind>" into host and kind.
func ParseSubject(subject string) (host, kind string, ok bool) {
	rest, found := strings.CutPrefix(subject, "asm.")
	if !found {
		return "", "", false
	}
	host, kind, found = strings.Cut(rest, ".")
	if !found || host == "" || kind == "" {
		return "", "", false
	}
	return host, kind, true
}

// Subject builds "asm.<host>.<kind>".
func Subject(host, kind string) string { return "asm." + host + "." + kind }

// DurableOptions tune a durable pull consumer.
type DurableOptions struct {
	Filters []string
	// AckWait is how long a delivered message may stay unacked before redelivery.
	AckWait time.Duration
	// DeliverNew starts a newly created consumer at new messages instead of the stream's
	// start (used by the alerter: paging for a week of history on first start is noise).
	DeliverNew bool
	// MaxDeliver bounds deliveries of one message (default 10; svc.Consume quarantines a
	// message on its last one).
	MaxDeliver int
}

// Durable creates or updates the named durable pull consumer on ASM_EVENTS. Explicit
// acks; unlimited redeliveries (a store outage must not lose events).
func Durable(ctx context.Context, js jetstream.JetStream, name string, o DurableOptions) (jetstream.Consumer, error) {
	if o.AckWait <= 0 {
		o.AckWait = 30 * time.Second
	}
	if o.MaxDeliver <= 0 {
		o.MaxDeliver = 10
	}
	cfg := jetstream.ConsumerConfig{
		Durable:       name,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       o.AckWait,
		MaxAckPending: 1000,
		MaxDeliver:    o.MaxDeliver,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	}
	if o.DeliverNew {
		cfg.DeliverPolicy = jetstream.DeliverNewPolicy
	}
	if len(o.Filters) == 1 {
		cfg.FilterSubject = o.Filters[0]
	} else {
		cfg.FilterSubjects = o.Filters
	}
	c, err := js.Consumer(ctx, natsauth.StreamName, name)
	if err == nil {
		// Keep the existing consumer's position; the deliver policy cannot change.
		cfg.DeliverPolicy = c.CachedInfo().Config.DeliverPolicy
		cfg.OptStartTime = c.CachedInfo().Config.OptStartTime
	} else if !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return nil, fmt.Errorf("consumer %s: %w", name, err)
	}
	return js.CreateOrUpdateConsumer(ctx, natsauth.StreamName, cfg)
}

// Publisher sends events a backend service produces. Each event carries the service's
// run id and seq 0: it is not part of the host's sequence.
type Publisher struct {
	js    jetstream.JetStream
	RunID string
}

// NewPublisher returns a publisher with a fresh run id "<origin>-<ulid>".
func NewPublisher(js jetstream.JetStream, origin string) *Publisher {
	return &Publisher{js: js, RunID: origin + "-" + ulid.Make().String()}
}

// NewEventID returns a new event id (a ULID).
func NewEventID() string { return ulid.Make().String() }

// Publish sends msg with Nats-Msg-Id = id (JetStream dedupes retries) and retries a
// failure up to 3 times within ctx.
func (p *Publisher) Publish(ctx context.Context, subject, id string, msg proto.Message) error {
	_, err := p.PublishSeq(ctx, subject, id, msg)
	return err
}

// PublishSeq is Publish that also returns the message's stream sequence (from the
// JetStream ack; for a deduplicated retry, the sequence of the stored original).
func (p *Publisher) PublishSeq(ctx context.Context, subject, id string, msg proto.Message) (uint64, error) {
	data, err := proto.Marshal(msg)
	if err != nil {
		return 0, err
	}
	var last error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, errors.Join(ctx.Err(), last)
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		var ack *jetstream.PubAck
		ack, last = p.js.PublishMsg(pctx, &nats.Msg{Subject: subject, Data: data}, jetstream.WithMsgID(id))
		cancel()
		if last == nil {
			return ack.Sequence, nil
		}
	}
	return 0, fmt.Errorf("publish %s: %w", subject, last)
}

// Backend namespaces (pwb.<origin>.<host>.<kind>). No host may publish there, so the
// origin of a message is the subject's, never a field of the body.
const (
	OriginAgent    = ""
	OriginCloud    = "cloud"
	OriginVerifier = "verifier"
	OriginProbe    = "probe"
	// OriginInventory is the inventory's control namespace (M8: forgotten hosts).
	OriginInventory = "inventory"
	// KindVerdict is the kind of pwb.cloud and pwb.verifier messages; KindProbeRequest
	// of pwb.probe ones; KindForgotten of pwb.inventory ones.
	KindVerdict      = "exposure"
	KindProbeRequest = "request"
	KindForgotten    = "forgotten"
)

// ForgottenSubject is where the inventory announces that an operator forgot a host
// (a HostForgotten).
func ForgottenSubject(host string) string { return "pwb.inventory." + host + "." + KindForgotten }

// CloudSubject is where the inventory's cloud look-up publishes a host's verdicts.
func CloudSubject(host string) string { return "pwb.cloud." + host + "." + KindVerdict }

// VerifierSubject is where the verifier publishes a host's probe results.
func VerifierSubject(host string) string { return "pwb.verifier." + host + "." + KindVerdict }

// ProbeSubject is where the inventory asks the verifier to probe a host's listener.
func ProbeSubject(host string) string { return "pwb.probe." + host + "." + KindProbeRequest }

// Parsed is a subject split into origin, host and kind.
type Parsed struct{ Origin, Host, Kind string }

// Parse splits asm.<host>.<kind> (origin "") and pwb.<origin>.<host>.<kind>.
func Parse(subject string) (Parsed, bool) {
	if host, kind, ok := ParseSubject(subject); ok {
		return Parsed{Origin: OriginAgent, Host: host, Kind: kind}, true
	}
	parts := strings.Split(subject, ".")
	if len(parts) != 4 || parts[0] != "pwb" || parts[2] == "" {
		return Parsed{}, false
	}
	switch {
	case (parts[1] == OriginCloud || parts[1] == OriginVerifier) && parts[3] == KindVerdict,
		parts[1] == OriginProbe && parts[3] == KindProbeRequest,
		parts[1] == OriginInventory && parts[3] == KindForgotten:
		return Parsed{Origin: parts[1], Host: parts[2], Kind: parts[3]}, true
	}
	return Parsed{}, false
}
