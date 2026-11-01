package state

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/thapr0digy/listener-watch/internal/model"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func key(addr string, port uint16) model.ListenerKey {
	return model.NewKey(4026531840, "tcp", netip.MustParseAddr(addr), port)
}

func open(cookie uint64, k model.ListenerKey, pid uint32) model.Observation {
	return model.Observation{
		Kind: model.Opened, Cookie: cookie, Key: k,
		Proc: model.Process{PID: pid, Comm: "svc"}, At: t0, Source: model.SourceEBPF,
	}
}

func closeObs(cookie uint64, k model.ListenerKey) model.Observation {
	return model.Observation{Kind: model.Closed, Cookie: cookie, Key: k, At: t0.Add(time.Second), Source: model.SourceEBPF}
}

func TestOpenThenClose(t *testing.T) {
	tb := New()
	k := key("0.0.0.0", 8080)

	got := tb.Apply(open(1, k, 10))
	if len(got) != 1 || got[0].Kind != model.Opened || got[0].Key != k {
		t.Fatalf("open: got %+v", got)
	}
	if len(got[0].Procs) != 1 || got[0].Procs[0].PID != 10 {
		t.Fatalf("open procs: %+v", got[0].Procs)
	}

	got = tb.Apply(closeObs(1, k))
	if len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != k {
		t.Fatalf("close: got %+v", got)
	}
	if len(tb.Snapshot()) != 0 {
		t.Fatalf("snapshot not empty after close: %+v", tb.Snapshot())
	}
}

func TestDuplicateOpenIgnored(t *testing.T) {
	tb := New()
	k := key("0.0.0.0", 8080)
	tb.Apply(open(1, k, 10))
	if got := tb.Apply(open(1, k, 10)); len(got) != 0 {
		t.Fatalf("duplicate open emitted %+v", got)
	}
}

func TestCloseUnknownCookieIgnored(t *testing.T) {
	tb := New()
	if got := tb.Apply(closeObs(99, key("0.0.0.0", 80))); len(got) != 0 {
		t.Fatalf("unknown close emitted %+v", got)
	}
}

func TestCloseUsesStoredKeyAndProcs(t *testing.T) {
	tb := New()
	k := key("10.0.0.1", 443)
	tb.Apply(open(5, k, 77))

	got := tb.Apply(model.Observation{Kind: model.Closed, Cookie: 5, Key: model.ListenerKey{}, At: t0, Source: model.SourceEBPF})
	if len(got) != 1 || got[0].Kind != model.Closed {
		t.Fatalf("got %+v", got)
	}
	if got[0].Key != k {
		t.Fatalf("key = %v, want %v", got[0].Key, k)
	}
	if len(got[0].Procs) != 1 || got[0].Procs[0].PID != 77 {
		t.Fatalf("procs = %+v", got[0].Procs)
	}
}

func TestReuseportCollapsesToOneListener(t *testing.T) {
	tb := New()
	k := key("0.0.0.0", 80)

	opened := 0
	for i := uint64(1); i <= 3; i++ {
		for _, c := range tb.Apply(open(i, k, uint32(9+i))) {
			if c.Kind == model.Opened {
				opened++
			}
		}
	}
	if opened != 1 {
		t.Fatalf("opened = %d, want 1", opened)
	}
	snap := tb.Snapshot()
	if len(snap) != 1 || len(snap[0].Procs) != 3 {
		t.Fatalf("snapshot = %+v", snap)
	}

	if got := tb.Apply(closeObs(1, k)); len(got) != 0 {
		t.Fatalf("close 1 emitted %+v", got)
	}
	if got := tb.Apply(closeObs(2, k)); len(got) != 0 {
		t.Fatalf("close 2 emitted %+v", got)
	}
	got := tb.Apply(closeObs(3, k))
	if len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != k {
		t.Fatalf("close 3: %+v", got)
	}
}

func TestSnapshotSortedAndDeduped(t *testing.T) {
	tb := New()
	kb := key("0.0.0.0", 9000)
	ka := key("0.0.0.0", 80)
	tb.Apply(open(1, kb, 30))
	tb.Apply(open(2, kb, 20))
	tb.Apply(open(3, kb, 20)) // same PID, second socket
	tb.Apply(open(4, ka, 5))

	snap := tb.Snapshot()
	if len(snap) != 2 || snap[0].Key != ka || snap[1].Key != kb {
		t.Fatalf("order: %+v", snap)
	}
	var pids []uint32
	for _, p := range snap[1].Procs {
		pids = append(pids, p.PID)
	}
	if !reflect.DeepEqual(pids, []uint32{20, 30}) {
		t.Fatalf("pids = %v, want [20 30]", pids)
	}
}

func TestOwnerlessListener(t *testing.T) {
	tb := New()
	k := key("0.0.0.0", 2049)
	o := open(1, k, 0)
	o.Proc = model.Process{}
	got := tb.Apply(o)
	if len(got) != 1 || got[0].Kind != model.Opened || len(got[0].Procs) != 0 {
		t.Fatalf("open: %+v", got)
	}
	snap := tb.Snapshot()
	if len(snap) != 1 || snap[0].Procs == nil || len(snap[0].Procs) != 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
}
