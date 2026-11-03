package bus

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

func TestParseSubject(t *testing.T) {
	for subj, want := range map[string][2]string{
		"asm.abc.listener.opened":    {"abc", "listener.opened"},
		"asm.abc.heartbeat":          {"abc", "heartbeat"},
		"asm.abc.exposure.confirmed": {"abc", "exposure.confirmed"},
	} {
		h, k, ok := ParseSubject(subj)
		if !ok || h != want[0] || k != want[1] {
			t.Errorf("%s: %q %q %v", subj, h, k, ok)
		}
	}
	for _, bad := range []string{"asm.abc", "foo.abc.heartbeat", "asm..heartbeat", "asm.abc."} {
		if _, _, ok := ParseSubject(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// StartServer runs an embedded JetStream server with the ASM_EVENTS stream (tests).
func startServer(t *testing.T) string {
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
	return s.ClientURL()
}

func TestPublishAndDurable(t *testing.T) {
	url := startServer(t)
	nc, js, err := Connect(Config{URL: url, Role: natsauth.RoleVerifier, Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	ctx := context.Background()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: natsauth.StreamName, Subjects: []string{"asm.>", "pwb.>"}}); err != nil {
		t.Fatal(err)
	}
	p := NewPublisher(js, "verifier")
	id := NewEventID()
	ev := &asmv1.ExposureConfirmation{EventId: id, HostId: "h1", RunId: p.RunID, Result: "confirmed", Origin: "verifier"}
	for range 2 { // the retry of the same id is deduplicated
		if err := p.Publish(ctx, VerifierSubject("h1"), id, ev); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Durable(ctx, js, natsauth.ConsumerVerifier, DurableOptions{Filters: []string{"pwb.verifier.*.exposure"}})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := c.Fetch(10, jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for m := range batch.Messages() {
		var got asmv1.ExposureConfirmation
		if err := proto.Unmarshal(m.Data(), &got); err != nil || got.GetResult() != "confirmed" {
			t.Fatalf("got %v err %v", &got, err)
		}
		_ = m.Ack()
		n++
	}
	if n != 1 {
		t.Fatalf("got %d messages, want 1 (dedupe)", n)
	}
	// PublishSeq reports the message's stream sequence (the forget watermark).
	seq, err := p.PublishSeq(ctx, ForgottenSubject("h1"), NewEventID(), &asmv1.HostForgotten{HostId: "h1"})
	if err != nil || seq != 2 {
		t.Fatalf("PublishSeq = %d, %v; want 2", seq, err)
	}
	// Re-creating keeps the position: nothing is redelivered.
	c, err = Durable(ctx, js, natsauth.ConsumerVerifier, DurableOptions{Filters: []string{"pwb.verifier.*.exposure"}, DeliverNew: true})
	if err != nil {
		t.Fatal(err)
	}
	batch, _ = c.Fetch(10, jetstream.FetchMaxWait(300*time.Millisecond))
	for range batch.Messages() {
		t.Fatal("redelivered after re-create")
	}
}

func TestParseBackendSubjects(t *testing.T) {
	for subj, want := range map[string]Parsed{
		"asm.h.exposure.changed": {"", "h", "exposure.changed"},
		CloudSubject("h"):        {"cloud", "h", "exposure"},
		VerifierSubject("h"):     {"verifier", "h", "exposure"},
		ProbeSubject("h"):        {"probe", "h", "request"},
		ForgottenSubject("h"):    {"inventory", "h", "forgotten"},
	} {
		got, ok := Parse(subj)
		if !ok || got != want {
			t.Errorf("%s: %+v %v", subj, got, ok)
		}
	}
	for _, bad := range []string{"pwb.agent.h.exposure", "pwb.cloud.h.other", "pwb.cloud..exposure", "pwb.cloud.h", "x.y",
		"pwb.inventory.h.exposure", "pwb.cloud.h.forgotten", "pwb.inventory..forgotten"} {
		if _, ok := Parse(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
}
