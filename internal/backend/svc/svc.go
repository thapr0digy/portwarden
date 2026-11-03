// Package svc holds what the backend services share: JSON config files with durations,
// secrets read from a file or the environment, NATS settings, and the consume loop.
package svc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// Duration is a time.Duration written as "90s" in JSON.
type Duration time.Duration

// UnmarshalJSON parses a Go duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"90s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("duration %q is negative", s)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// D returns the duration, or def when unset.
func (d Duration) D(def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return time.Duration(d)
}

// NATS is the "nats" block of every service config.
type NATS struct {
	URL       string `json:"url"`
	CredsFile string `json:"creds_file"`
	NkeyFile  string `json:"nkey_file"`
	CAFile    string `json:"ca_file"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
}

// Bus converts it for bus.Connect.
func (n NATS) Bus(role natsauth.Role, name string, connected func(bool)) bus.Config {
	url := n.URL
	if url == "" {
		url = "nats://127.0.0.1:4222"
	}
	return bus.Config{URL: url, CredsFile: n.CredsFile, NkeyFile: n.NkeyFile, CAFile: n.CAFile, CertFile: n.CertFile,
		KeyFile: n.KeyFile, Role: role, Name: name, Connected: connected}
}

// Load reads a JSON config file into v, refusing unknown keys.
func Load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Secret returns the environment variable env when set, else the trimmed contents of
// file. Neither set is an error naming both.
func Secret(env, file string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v, nil
	}
	if file == "" {
		return "", fmt.Errorf("set %s or the config's file for it", env)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s is empty", file)
	}
	return v, nil
}

// Handler processes one message. A nil error acks it. An error wrapped with Permanent
// (bad data: undecodable, rejected by the store) quarantines it at once; any other error
// is transient and retried.
type Handler func(ctx context.Context, m jetstream.Msg) error

// PermanentError marks a message that can never be processed.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return "permanent: " + e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent marks err as a data error (nil stays nil).
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent reports whether err was marked Permanent.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}

// QuarantineFunc stores a message that will not be processed (subject, stream sequence,
// raw data, why). An error from it is treated as transient.
type QuarantineFunc func(ctx context.Context, m jetstream.Msg, why error) error

// ConsumeOptions bound the retries of one message.
type ConsumeOptions struct {
	// Attempts per delivery for a transient error (default 6, backoff 1 s doubling to
	// 30 s), after which the message is NAKed with NakDelay so the consumer moves on.
	Attempts int
	NakDelay time.Duration
	// MaxDeliver must equal the consumer's MaxDeliver (bus.DurableOptions, default 10): on
	// the last delivery a still-failing message is quarantined instead of dropped silently.
	MaxDeliver int
	// Quarantine stores dropped messages; nil only logs them.
	Quarantine QuarantineFunc
	// Prefetch is how many messages are pulled ahead (default 32).
	Prefetch int
}

func (o *ConsumeOptions) defaults() {
	if o.Attempts <= 0 {
		o.Attempts = 6
	}
	if o.NakDelay <= 0 {
		o.NakDelay = 30 * time.Second
	}
	if o.MaxDeliver <= 0 {
		o.MaxDeliver = DefaultMaxDeliver
	}
	if o.Prefetch <= 0 {
		o.Prefetch = 32
	}
}

// DefaultMaxDeliver is the consumers' MaxDeliver.
const DefaultMaxDeliver = 10

// Consume pulls from c and calls h for each message, one at a time. A transient failure
// is retried in place (so order holds while the cause is brief), then NAKed with a delay;
// a permanent one, or a transient one on its last delivery, is quarantined and
// terminated, so one bad message never stops the consumer. It returns when ctx ends.
func Consume(ctx context.Context, c jetstream.Consumer, h Handler, o ConsumeOptions) error {
	o.defaults()
	it, err := c.Messages(jetstream.PullMaxMessages(o.Prefetch))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		it.Stop()
	}()
	for {
		m, err := it.Next()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, jetstream.ErrMsgIteratorClosed) {
				return ctx.Err()
			}
			slog.Warn("consume: next message", "err", err)
			continue
		}
		if err := handleOne(ctx, m, h, o); err != nil {
			return err
		}
	}
}

func handleOne(ctx context.Context, m jetstream.Msg, h Handler, o ConsumeOptions) error {
	// Keep the message from being redelivered while it is handled or retried.
	stopTicker := make(chan struct{})
	defer close(stopTicker)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopTicker:
				return
			case <-t.C:
				_ = m.InProgress()
			}
		}
	}()
	delivered := uint64(1)
	if md, err := m.Metadata(); err == nil {
		delivered = md.NumDelivered
	}
	backoff := time.Second
	var err error
	for attempt := 1; attempt <= o.Attempts; attempt++ {
		err = h(ctx, m)
		if err == nil {
			if aerr := m.Ack(); aerr != nil {
				slog.Warn("consume: ack failed (the message will be redelivered and skipped)", "subject", m.Subject(), "err", aerr)
			}
			return nil
		}
		if IsPermanent(err) {
			return quarantine(ctx, m, err, o)
		}
		if attempt == o.Attempts {
			break
		}
		slog.Warn("consume: handling failed; retrying", "subject", m.Subject(), "err", err, "attempt", attempt, "in", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	if delivered >= uint64(o.MaxDeliver) {
		return quarantine(ctx, m, fmt.Errorf("gave up after %d deliveries: %w", delivered, err), o)
	}
	slog.Error("consume: message still failing; moving on, it will be redelivered", "subject", m.Subject(),
		"err", err, "delivery", delivered, "max_deliver", o.MaxDeliver, "nak_delay", o.NakDelay)
	if nerr := m.NakWithDelay(o.NakDelay); nerr != nil {
		slog.Warn("consume: nak failed", "err", nerr)
	}
	return nil
}

// quarantine stores the message and terminates it; while the store fails, it retries.
func quarantine(ctx context.Context, m jetstream.Msg, why error, o ConsumeOptions) error {
	var seq uint64
	if md, err := m.Metadata(); err == nil {
		seq = md.Sequence.Stream
	}
	slog.Error("consume: message quarantined", "subject", m.Subject(), "stream_seq", seq, "err", why)
	backoff := time.Second
	for o.Quarantine != nil {
		err := o.Quarantine(ctx, m, why)
		if err == nil {
			break
		}
		slog.Warn("consume: quarantine store failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	if err := m.Term(); err != nil {
		slog.Warn("consume: term failed", "err", err)
	}
	return nil
}

// WaitStream waits until the ASM_EVENTS stream exists (an operator creates it), logging
// once a minute.
func WaitStream(ctx context.Context, js jetstream.JetStream) (jetstream.Stream, error) {
	var logged time.Time
	for {
		s, err := js.Stream(ctx, natsauth.StreamName)
		if err == nil {
			return s, nil
		}
		if time.Since(logged) > time.Minute {
			slog.Warn("waiting for the stream", "stream", natsauth.StreamName, "err", err)
			logged = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
