package svc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

func jsServer(t *testing.T) jetstream.JetStream {
	t.Helper()
	s, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, _ := jetstream.New(nc)
	if _, err := js.CreateStream(context.Background(), jetstream.StreamConfig{Name: natsauth.StreamName, Subjects: []string{"asm.>"}}); err != nil {
		t.Fatal(err)
	}
	return js
}

// A bad message (permanent error) and one that keeps failing (transient on every
// delivery) are both quarantined, and the messages after them are still handled.
func TestConsumeNeverStallsOnABadMessage(t *testing.T) {
	js := jsServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, d := range []string{"bad", "flaky", "good"} {
		if _, err := js.Publish(ctx, "asm.h."+d, []byte(d)); err != nil {
			t.Fatal(err)
		}
	}
	c, err := bus.Durable(ctx, js, "test", bus.DurableOptions{Filters: []string{"asm.>"}, MaxDeliver: 2})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var quarantined, handled []string
	done := make(chan struct{})
	go Consume(ctx, c, func(_ context.Context, m jetstream.Msg) error {
		switch string(m.Data()) {
		case "bad":
			return Permanent(errors.New("invalid byte sequence"))
		case "flaky":
			return errors.New("connection refused")
		}
		mu.Lock()
		handled = append(handled, string(m.Data()))
		mu.Unlock()
		close(done)
		return nil
	}, ConsumeOptions{Attempts: 1, NakDelay: 50 * time.Millisecond, MaxDeliver: 2, Quarantine: func(_ context.Context, m jetstream.Msg, why error) error {
		mu.Lock()
		quarantined = append(quarantined, string(m.Data()))
		mu.Unlock()
		return nil
	}})
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("the good message after a bad one was never handled")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(quarantined)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(quarantined) != 2 || quarantined[0] != "bad" || quarantined[1] != "flaky" || len(handled) != 1 {
		t.Fatalf("quarantined %v handled %v", quarantined, handled)
	}
}
