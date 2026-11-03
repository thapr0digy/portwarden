package state

import (
	"testing"

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
