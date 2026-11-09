//go:build integration

package pg

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/inventory"
)

// Two stores on one database: once the second leads (the first released), every write
// of the first is refused with leader.ErrFenced and nothing it tried is stored; the new
// leader writes, and both still read.
func TestInventoryWritesAreFenced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	old := open(t)
	next, err := Open(ctx, os.Getenv("PORTWARDEN_TEST_PG"))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	cfg := svc.Leader{Poll: svc.Duration(100 * time.Millisecond), Check: svc.Duration(200 * time.Millisecond)}
	lease, err := old.Elect(ctx, cfg, &leader.State{})
	if err != nil {
		t.Fatal(err)
	}
	hb := func(at time.Time) inventory.Event {
		return inventory.Event{Meta: inventory.Meta{StreamSeq: 1, StreamTime: at},
			Msg: &asmv1.Heartbeat{HostId: h1, RunId: "r1", Seq: 1}}
	}
	if err := old.SetCursor(ctx, h1, inventory.Cursor{RunID: "r1", LastSeq: 1}); err != nil {
		t.Fatalf("the leader's own write: %v", err)
	}
	got := make(chan leader.Lease, 1)
	go func() {
		l, err := next.Elect(ctx, cfg, &leader.State{})
		if err != nil {
			t.Error(err)
		}
		got <- l
	}()
	time.Sleep(300 * time.Millisecond)
	if err := lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
	nl := <-got
	defer func() { _ = nl.Release(context.Background()) }()

	now := time.Now()
	writes := map[string]func() error{
		"Apply":           func() error { return old.Apply(ctx, hb(now)) },
		"SetCursor":       func() error { return old.SetCursor(ctx, h1, inventory.Cursor{RunID: "r2", LastSeq: 9}) },
		"SetSilent":       func() error { return old.SetSilent(ctx, h1, now) },
		"SetCloudStatus":  func() error { return old.SetCloudStatus(ctx, h1, "fenced", now) },
		"Forget":          func() error { _, err := old.Forget(ctx, h1, inventory.Mark{Seq: 5, Stream: now}); return err },
		"PruneMarks":      func() error { _, err := old.PruneMarks(ctx, now, 1); return err },
		"PruneHistory":    func() error { _, err := old.PruneHistory(ctx, now, 10); return err },
		"PruneQuarantine": func() error { _, err := old.PruneQuarantine(ctx, now, 10); return err },
		"Quarantine":      func() error { return old.Quarantine(ctx, 7, "asm.x.y", "why", nil) },
	}
	for name, w := range writes {
		if err := w(); !errors.Is(err, leader.ErrFenced) {
			t.Errorf("%s by the old leader: %v, want ErrFenced", name, err)
		}
	}
	h, ok, err := next.Host(ctx, h1)
	if err != nil || !ok || h.Silent || h.CloudStatus == "fenced" {
		t.Fatalf("after fenced writes: %+v %v %v", h, ok, err)
	}
	if _, ok, err := old.Host(ctx, h1); err != nil || !ok {
		t.Fatalf("the old store cannot read: %v %v", ok, err)
	}
	if err := next.SetSilent(ctx, h1, now); err != nil {
		t.Fatalf("the new leader's write: %v", err)
	}
}
