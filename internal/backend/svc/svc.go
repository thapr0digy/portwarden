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
func (n NATS) Bus(role natsauth.Role, name string) bus.Config {
	url := n.URL
	if url == "" {
		url = "nats://127.0.0.1:4222"
	}
	return bus.Config{URL: url, CredsFile: n.CredsFile, NkeyFile: n.NkeyFile, CAFile: n.CAFile, CertFile: n.CertFile,
		KeyFile: n.KeyFile, Role: role, Name: name}
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

// Handler processes one message; an error means "not done, retry it".
type Handler func(ctx context.Context, m jetstream.Msg) error

// Consume pulls from c and calls h for each message in order. A message h fails on is
// retried (with backoff up to 30 s) before the next one is looked at, so order holds;
// it is acked once h succeeds. It returns when ctx ends.
func Consume(ctx context.Context, c jetstream.Consumer, h Handler) error {
	it, err := c.Messages(jetstream.PullMaxMessages(256))
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
		backoff := time.Second
		for {
			// Keep the message from being redelivered while we retry it.
			_ = m.InProgress()
			err := h(ctx, m)
			if err == nil {
				break
			}
			slog.Warn("consume: handling failed; retrying", "subject", m.Subject(), "err", err, "in", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
		}
		if err := m.Ack(); err != nil {
			slog.Warn("consume: ack failed (the message will be redelivered and skipped)", "subject", m.Subject(), "err", err)
		}
	}
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
