package inventory

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

// handleBudget bounds one Handle with the in-memory store. NATS caps a message at its
// max_payload (1 MiB by default); a fuzz input is smaller, so this bounds the decode.
// The seeds allocate at most 16 KiB.
var handleBudget = fuzzcheck.Budget{Time: 2 * time.Second, Base: 4 << 20, PerByte: 256}

// fuzzSubjects are the subjects the inventory consumes, plus a body naming another host
// and a subject it ignores; a fuzz input picks one by index.
var fuzzSubjects = []string{
	"asm." + host + ".listener.opened",
	"asm." + host + ".listener.closed",
	"asm." + host + ".listener.owner_changed",
	"asm." + host + ".exposure.changed",
	"asm." + host + ".exposure.confirmed",
	"asm." + host + ".proxy.routes",
	"asm." + host + ".snapshot",
	"asm." + host + ".heartbeat",
	"asm." + host + ".host.changed",
	"asm." + host + ".tamper",
	"pwb.cloud." + host + ".exposure",
	"pwb.verifier." + host + ".exposure",
	"pwb.inventory." + host + ".forgotten",
	"asm.h2.snapshot",
	"asm." + host + ".unknown",
}

func fuzzSubject(i uint8) string { return fuzzSubjects[int(i)%len(fuzzSubjects)] }

// fuzzSeeds are one well-formed message per subject, in fuzzSubjects order.
func fuzzSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	l := &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 80, Key: "1/tcp/0.0.0.0:80"}
	msgs := []proto.Message{
		opened("01A", 2),
		&asmv1.ListenerEvent{HostId: host, RunId: "01A", Seq: 3, Kind: asmv1.Kind_CLOSED, Listener: l},
		&asmv1.ListenerEvent{HostId: host, RunId: "01A", Seq: 4, Kind: asmv1.Kind_OWNER_CHANGED, Listener: l},
		&asmv1.ExposureEvent{HostId: host, RunId: "01A", Seq: 5, Listener: l},
		&asmv1.ExposureConfirmation{HostId: host},
		&asmv1.ProxyRoutes{HostId: host, RunId: "01A", Seq: 6},
		&asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1, BootId: "b1", RunNumber: 1,
			Listeners: []*asmv1.ListenerState{{Listener: l}}},
		&asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 7},
		&asmv1.HostEvent{HostId: host, RunId: "01A", Seq: 8},
		&asmv1.TamperEvent{HostId: host, RunId: "01A", Seq: 9},
		&asmv1.ExposureEvent{HostId: host, Listener: l},
		&asmv1.ExposureConfirmation{HostId: host, Listener: l},
		&asmv1.HostForgotten{HostId: host},
		&asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1},
		&asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 1},
	}
	out := make([][]byte, len(msgs))
	for i, m := range msgs {
		b, err := proto.Marshal(m)
		if err != nil {
			tb.Fatal(err)
		}
		out[i] = b
	}
	return out
}

// Any host can publish anything on its own asm.<host>.> subjects: every message must be
// handled without a panic, within budget, and every error must be permanent, so a bad
// message is quarantined and never retried forever. Each input is two messages on one
// consumer, so the second meets the cursor and run state the first left.
func FuzzHandle(f *testing.F) {
	seeds := fuzzSeeds(f)
	snap := uint8(6)
	for i, s := range seeds {
		f.Add(snap, seeds[snap], uint8(i), s)
		f.Add(uint8(i), s, uint8(i), s)
	}
	f.Fuzz(func(t *testing.T, k1 uint8, d1 []byte, k2 uint8, d2 []byte) {
		at := time.Unix(1_700_000_000, 0)
		c := &Consumer{Store: newFake(), Snapshots: &fakeSnaps{}, Now: func() time.Time { return at }}
		for i, msg := range []struct {
			subject string
			data    []byte
		}{{fuzzSubject(k1), d1}, {fuzzSubject(k2), d2}} {
			var err error
			fuzzcheck.Bounded(t, handleBudget, len(msg.data), func() {
				err = c.Handle(context.Background(), msg.subject, msg.data, Meta{StreamSeq: uint64(10 + i), StreamTime: at})
			})
			if err != nil && !svc.IsPermanent(err) {
				t.Fatalf("message %d on %s: retryable error %v (the store never fails)", i, msg.subject, err)
			}
		}
	})
}
