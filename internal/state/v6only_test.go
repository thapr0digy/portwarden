package state

import (
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

func openV6(cookie uint64, k model.ListenerKey, pid uint32, v model.V6Only) model.Observation {
	o := open(cookie, k, pid)
	o.V6Only = v
	return o
}

func TestSnapshotV6Only(t *testing.T) {
	const on, off, unknown = model.V6OnlyOn, model.V6OnlyOff, model.V6OnlyUnknown
	for _, c := range []struct {
		name  string
		flags []model.V6Only
		want  model.V6Only
	}{
		{"one v6-only socket", []model.V6Only{on}, on},
		{"one dual-stack socket", []model.V6Only{off}, off},
		{"not read", []model.V6Only{unknown}, unknown},
		{"reuseport, all v6-only", []model.V6Only{on, on}, on},
		{"a dual-stack worker takes IPv4 for the key", []model.V6Only{on, off}, off},
		{"dual-stack wins over unread", []model.V6Only{unknown, off}, off},
		{"one unread socket leaves it unknown", []model.V6Only{on, unknown}, unknown},
	} {
		tb := New(0)
		k := key("::", 8080)
		for i, f := range c.flags {
			tb.Apply(openV6(uint64(i+1), k, uint32(100+i), f))
		}
		snap := tb.Snapshot()
		if len(snap) != 1 || snap[0].V6Only != c.want {
			t.Errorf("%s: %+v, want %v", c.name, snap, c.want)
		}
	}
}

// A baseline record without the flag is completed by a later observation of the same
// socket that has it (and a known flag is never overwritten).
func TestReobservedSocketFillsV6Only(t *testing.T) {
	tb := New(0)
	k := key("::", 8080)
	tb.Apply(openV6(1, k, 100, model.V6OnlyUnknown))
	tb.Apply(openV6(1, k, 100, model.V6OnlyOn))
	if got := tb.Snapshot()[0].V6Only; got != model.V6OnlyOn {
		t.Fatalf("filled: %v", got)
	}
	tb.Apply(openV6(1, k, 100, model.V6OnlyOff))
	if got := tb.Snapshot()[0].V6Only; got != model.V6OnlyOn {
		t.Fatalf("overwritten: %v", got)
	}
}

// TakeRejudge flags a flag change that no Change reports: a socket joining or leaving,
// a reopen inside the grace, and a recheck that finds another socket; a first open or a
// final close does not need it (its Change is judged).
func TestTakeRejudge(t *testing.T) {
	k := key("::", 9443)
	tb := New(time.Hour)
	tb.Apply(openV6(1, k, 100, model.V6OnlyOn))
	if tb.TakeRejudge() {
		t.Fatal("first open")
	}
	tb.Apply(openV6(2, k, 100, model.V6OnlyOff))
	if !tb.TakeRejudge() || tb.TakeRejudge() {
		t.Fatal("dual-stack socket joined: once")
	}
	tb.Apply(closeObs(2, k))
	if !tb.TakeRejudge() {
		t.Fatal("dual-stack socket left")
	}
	tb.Apply(closeObs(1, k))
	tb.Apply(openV6(3, k, 100, model.V6OnlyOff))
	if !tb.TakeRejudge() {
		t.Fatal("reopened dual-stack inside the grace")
	}
	// A recheck that finds the socket replaced by a v6-only one (missed events).
	dump := []model.Observation{openV6(4, k, 100, model.V6OnlyOn)}
	if ch := tb.Reconcile(dump, nil, t0); len(ch) != 0 {
		t.Fatalf("same holders: %+v", ch)
	}
	if !tb.TakeRejudge() {
		t.Fatal("recheck replaced the socket")
	}
	// Expired close: the record goes; a later open is a fresh listener.
	tb.Apply(closeObs(4, k))
	tb.Expire(t0.Add(48 * time.Hour))
	tb.Apply(openV6(5, k, 100, model.V6OnlyOff))
	if tb.TakeRejudge() {
		t.Fatal("a new listener after an expired close")
	}
}
