//go:build integration

package pgstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/alerter"
	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
)

// Two stores on one database: the first to Elect leads; once the second takes over
// (the first released), every write of the first is refused with leader.ErrFenced and
// nothing it tried is stored, while the new leader writes as usual.
func TestAlerterWritesAreFenced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	old := open(t)
	cfg := svc.Leader{Poll: svc.Duration(100 * time.Millisecond), Check: svc.Duration(200 * time.Millisecond)}
	var oldRole, newRole leader.State
	lease, err := old.Elect(ctx, cfg, &oldRole)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.InTx(ctx, func(st alerter.State) error { return st.SetPaged(ctx, "listener:h/before", time.Now()) }); err != nil {
		t.Fatalf("the leader's own write: %v", err)
	}
	next := open2(t)
	got := make(chan leader.Lease, 1)
	go func() {
		l, err := next.Elect(ctx, cfg, &newRole)
		if err != nil {
			t.Error(err)
		}
		got <- l
	}()
	time.Sleep(300 * time.Millisecond)
	if newRole.Role() != leader.Standby {
		t.Fatal("the second store led while the first held the lock")
	}
	// The old leader's lock goes, but its store keeps the lease's fence: a stale leader
	// that has not stopped yet.
	if err := lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
	nl := <-got
	defer func() { _ = nl.Release(context.Background()) }()
	if nl.Epoch() <= lease.Epoch() {
		t.Fatalf("epoch %d after %d", nl.Epoch(), lease.Epoch())
	}

	writes := map[string]func() error{
		"InTx": func() error {
			return old.InTx(ctx, func(st alerter.State) error { return st.SetPaged(ctx, "listener:h/after", time.Now()) })
		},
		"Delivered":      func() error { return old.Delivered(ctx, "x", time.Now()) },
		"Failed":         func() error { return old.Failed(ctx, "x", time.Now(), false, "boom") },
		"Failed give up": func() error { return old.Failed(ctx, "x", time.Now(), true, "boom") },
		"Prune":          func() error { return old.Prune(ctx, time.Now(), time.Hour) },
		"PruneForgotten": func() error { _, err := old.PruneForgotten(ctx, time.Now(), 1); return err },
	}
	for name, w := range writes {
		if err := w(); !errors.Is(err, leader.ErrFenced) {
			t.Errorf("%s by the old leader: %v, want ErrFenced", name, err)
		}
	}
	if err := next.InTx(ctx, func(st alerter.State) error {
		if _, ok, _ := st.LastPaged(ctx, "listener:h/after"); ok {
			t.Error("a fenced write was stored")
		}
		if _, ok, _ := st.LastPaged(ctx, "listener:h/before"); !ok {
			t.Error("the old leader's write before the handover is gone")
		}
		return st.SetPaged(ctx, "listener:h/new", time.Now())
	}); err != nil {
		t.Fatalf("the new leader's write: %v", err)
	}
}
