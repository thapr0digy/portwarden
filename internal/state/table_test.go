package state

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
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
	tb := New(0)
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
	tb := New(0)
	k := key("0.0.0.0", 8080)
	tb.Apply(open(1, k, 10))
	if got := tb.Apply(open(1, k, 10)); len(got) != 0 {
		t.Fatalf("duplicate open emitted %+v", got)
	}
}

func TestCloseUnknownCookieIgnored(t *testing.T) {
	tb := New(0)
	if got := tb.Apply(closeObs(99, key("0.0.0.0", 80))); len(got) != 0 {
		t.Fatalf("unknown close emitted %+v", got)
	}
}

func TestCloseUsesStoredKeyAndProcs(t *testing.T) {
	tb := New(0)
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
	tb := New(0)
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

	// Each worker leaving changes the process set: an OwnerChanged, never a Closed.
	for _, cookie := range []uint64{1, 2} {
		if got := tb.Apply(closeObs(cookie, k)); len(got) != 1 || got[0].Kind != model.OwnerChanged {
			t.Fatalf("close %d: %+v", cookie, got)
		}
	}
	got := tb.Apply(closeObs(3, k))
	if len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != k {
		t.Fatalf("close 3: %+v", got)
	}
}

func TestSnapshotSortedAndDeduped(t *testing.T) {
	tb := New(0)
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
	tb := New(0)
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

func TestDuplicateOpenFillsMissingOwner(t *testing.T) {
	tb := New(0)
	k := key("0.0.0.0", 8080)
	ownerless := open(7, k, 0)
	ownerless.Proc = model.Process{}
	tb.Apply(ownerless)

	got := tb.Apply(open(7, k, 42))
	if len(got) != 1 || got[0].Kind != model.OwnerChanged || len(got[0].Procs) != 1 || got[0].Procs[0].PID != 42 {
		t.Fatalf("got %+v, want one OwnerChanged to pid 42", got)
	}
	snap := tb.Snapshot()
	if len(snap) != 1 || len(snap[0].Procs) != 1 || snap[0].Procs[0].PID != 42 {
		t.Fatalf("snapshot = %+v, want owner pid 42", snap)
	}
}

func TestDuplicateOpenKeepsExistingOwner(t *testing.T) {
	tb := New(0)
	k := key("0.0.0.0", 8080)
	tb.Apply(open(7, k, 10))

	if got := tb.Apply(open(7, k, 42)); len(got) != 0 {
		t.Fatalf("duplicate open emitted %+v", got)
	}
	snap := tb.Snapshot()
	if len(snap) != 1 || len(snap[0].Procs) != 1 || snap[0].Procs[0].PID != 10 {
		t.Fatalf("snapshot = %+v, want owner pid 10", snap)
	}
}

func TestBaselineSocketHeldByTwoProcessesListsBoth(t *testing.T) {
	tb := New(0)
	k := key("0.0.0.0", 22)
	for _, pid := range []uint32{1, 1044} {
		o := open(5, k, pid)
		o.Source = model.SourceBaseline
		tb.Apply(o)
	}
	snap := tb.Snapshot()
	if len(snap) != 1 || len(snap[0].Procs) != 2 || snap[0].Procs[0].PID != 1 || snap[0].Procs[1].PID != 1044 {
		t.Fatalf("snapshot = %+v, want pids 1 and 1044", snap)
	}
	tb.Apply(closeObs(5, k))
	tb.Apply(open(5, k, 77))
	if snap := tb.Snapshot(); len(snap) != 1 || len(snap[0].Procs) != 1 || snap[0].Procs[0].PID != 77 {
		t.Fatalf("co-owners must not outlive the socket: %+v", snap)
	}
}

const grace = 2 * time.Second

func at(o model.Observation, d time.Duration) model.Observation {
	o.At = t0.Add(d)
	return o
}

func pids(ps []model.Process) []uint32 {
	out := []uint32{}
	for _, p := range ps {
		out = append(out, p.PID)
	}
	return out
}

func TestRestartWithinGraceIsOwnerChanged(t *testing.T) {
	tb := New(grace)
	k := key("0.0.0.0", 8080)
	if got := tb.Apply(at(open(1, k, 1), 0)); len(got) != 1 || got[0].Kind != model.Opened {
		t.Fatalf("open: %+v", got)
	}
	cl := closeObs(1, k)
	cl.At = t0
	if got := tb.Apply(cl); len(got) != 0 {
		t.Fatalf("close within grace emitted %+v", got)
	}
	got := tb.Apply(at(open(2, k, 2), 500*time.Millisecond))
	if len(got) != 1 || got[0].Kind != model.OwnerChanged {
		t.Fatalf("reopen: %+v", got)
	}
	if !reflect.DeepEqual(pids(got[0].Procs), []uint32{2}) || !reflect.DeepEqual(pids(got[0].PrevProcs), []uint32{1}) {
		t.Fatalf("procs %v prev %v", pids(got[0].Procs), pids(got[0].PrevProcs))
	}
	if got := tb.Expire(t0.Add(3 * time.Second)); len(got) != 0 {
		t.Fatalf("expire after cancel: %+v", got)
	}
	if _, ok := tb.NextDeadline(); ok {
		t.Fatal("deadline left after cancel")
	}
}

func TestReopenSameOwnerWithinGraceIsSilent(t *testing.T) {
	tb := New(grace)
	k := key("0.0.0.0", 8080)
	tb.Apply(at(open(1, k, 1), 0))
	tb.Apply(closeObs(1, k))
	if got := tb.Apply(at(open(2, k, 1), time.Second)); len(got) != 0 {
		t.Fatalf("same-owner reopen emitted %+v", got)
	}
	if got := tb.Expire(t0.Add(10 * time.Second)); len(got) != 0 {
		t.Fatalf("expire: %+v", got)
	}
}

func TestCloseAfterGraceExpires(t *testing.T) {
	tb := New(grace)
	k := key("0.0.0.0", 8080)
	tb.Apply(at(open(1, k, 1), 0))
	cl := closeObs(1, k)
	cl.At = t0
	tb.Apply(cl)

	if d, ok := tb.NextDeadline(); !ok || !d.Equal(t0.Add(grace)) {
		t.Fatalf("deadline = %v %v", d, ok)
	}
	if got := tb.Expire(t0.Add(1999 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("early expire: %+v", got)
	}
	got := tb.Expire(t0.Add(grace))
	if len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != k || !got[0].At.Equal(t0) || !reflect.DeepEqual(pids(got[0].Procs), []uint32{1}) {
		t.Fatalf("expire: %+v", got)
	}
	if got := tb.Expire(t0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("second expire: %+v", got)
	}
}

func TestExpireSortedByKey(t *testing.T) {
	tb := New(grace)
	kb, ka := key("0.0.0.0", 9000), key("0.0.0.0", 80)
	tb.Apply(open(1, kb, 1))
	tb.Apply(open(2, ka, 2))
	tb.Apply(closeObs(1, kb))
	tb.Apply(closeObs(2, ka))
	got := tb.Expire(t0.Add(time.Hour))
	if len(got) != 2 || got[0].Key != ka || got[1].Key != kb {
		t.Fatalf("expire order: %+v", got)
	}
}

func TestFillInOwnerIsOwnerChanged(t *testing.T) {
	tb := New(0)
	k := key("0.0.0.0", 8080)
	base := open(7, k, 0)
	base.Proc = model.Process{}
	base.Source = model.SourceBaseline
	tb.Apply(base)
	got := tb.Apply(open(7, k, 7))
	if len(got) != 1 || got[0].Kind != model.OwnerChanged {
		t.Fatalf("got %+v", got)
	}
	if !reflect.DeepEqual(pids(got[0].Procs), []uint32{7}) || got[0].PrevProcs == nil || len(got[0].PrevProcs) != 0 {
		t.Fatalf("procs %v prev %#v", pids(got[0].Procs), got[0].PrevProcs)
	}
}

func TestEnrichmentOfSamePIDIsOwnerChanged(t *testing.T) {
	tb := New(grace)
	k := key("0.0.0.0", 8080)
	tb.Apply(open(1, k, 5))
	tb.Apply(closeObs(1, k))
	o := open(2, k, 5)
	o.Proc.Unit = "web.service"
	got := tb.Apply(o)
	if len(got) != 1 || got[0].Kind != model.OwnerChanged {
		t.Fatalf("got %+v", got)
	}
}

func TestReuseportSecondWorkerIsOwnerChanged(t *testing.T) {
	tb := New(0)
	k := key("0.0.0.0", 80)
	tb.Apply(open(1, k, 10))
	got := tb.Apply(open(2, k, 11))
	if len(got) != 1 || got[0].Kind != model.OwnerChanged ||
		!reflect.DeepEqual(pids(got[0].Procs), []uint32{10, 11}) || !reflect.DeepEqual(pids(got[0].PrevProcs), []uint32{10}) {
		t.Fatalf("got %+v", got)
	}
	// A second socket of an already listed pid changes nothing.
	if got := tb.Apply(open(3, k, 11)); len(got) != 0 {
		t.Fatalf("same pid emitted %+v", got)
	}
	// One worker going away is an owner change too.
	got = tb.Apply(closeObs(1, k))
	if len(got) != 1 || got[0].Kind != model.OwnerChanged || !reflect.DeepEqual(pids(got[0].Procs), []uint32{11}) {
		t.Fatalf("worker close: %+v", got)
	}
}

func TestZeroGraceClosesImmediately(t *testing.T) {
	tb := New(0)
	k := key("0.0.0.0", 8080)
	tb.Apply(open(1, k, 1))
	got := tb.Apply(closeObs(1, k))
	if len(got) != 1 || got[0].Kind != model.Closed {
		t.Fatalf("got %+v", got)
	}
	if _, ok := tb.NextDeadline(); ok {
		t.Fatal("pending with zero grace")
	}
}

func TestSnapshotExcludesPending(t *testing.T) {
	tb := New(grace)
	k := key("0.0.0.0", 8080)
	tb.Apply(open(1, k, 1))
	tb.Apply(closeObs(1, k))
	if snap := tb.Snapshot(); len(snap) != 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func dumpObs(cookie uint64, k model.ListenerKey, pid uint32) model.Observation {
	o := open(cookie, k, pid)
	o.Source = model.SourceBaseline
	return o
}

func TestReconcileOpensMissedClosesStaleSkipsTouched(t *testing.T) {
	tb := New(grace)
	ka, kb, kc := key("0.0.0.0", 1), key("0.0.0.0", 2), key("0.0.0.0", 3)
	tb.Apply(open(1, ka, 1))
	tb.Apply(open(2, kb, 2))
	dump := []model.Observation{dumpObs(2, kb, 2), dumpObs(3, kc, 3)}
	rt := t0.Add(time.Minute)

	got := tb.Reconcile(dump, map[uint64]struct{}{1: {}}, rt)
	if len(got) != 1 || got[0].Kind != model.Opened || got[0].Key != kc || got[0].Source != model.SourceReconcile || !got[0].At.Equal(rt) {
		t.Fatalf("touched {1}: %+v", got)
	}
	got = tb.Reconcile(dump, nil, rt)
	if len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != ka || got[0].Source != model.SourceReconcile ||
		!reflect.DeepEqual(pids(got[0].Procs), []uint32{1}) {
		t.Fatalf("touched {}: %+v", got)
	}
	if _, ok := tb.NextDeadline(); ok {
		t.Fatal("reconcile close must not wait for grace")
	}
	if snap := tb.Snapshot(); len(snap) != 2 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestReconcileTouchedDumpEntryNotOpened(t *testing.T) {
	tb := New(0)
	kc := key("0.0.0.0", 3)
	got := tb.Reconcile([]model.Observation{dumpObs(3, kc, 3)}, map[uint64]struct{}{3: {}}, t0)
	if len(got) != 0 || len(tb.Snapshot()) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestReconcileUpdatesHolders(t *testing.T) {
	tb := New(0)
	k := key("0.0.0.0", 22)
	tb.Apply(open(5, k, 1044))
	dump := []model.Observation{dumpObs(5, k, 1), dumpObs(5, k, 1044)}
	got := tb.Reconcile(dump, nil, t0)
	if len(got) != 1 || got[0].Kind != model.OwnerChanged || got[0].Source != model.SourceReconcile ||
		!reflect.DeepEqual(pids(got[0].Procs), []uint32{1, 1044}) || !reflect.DeepEqual(pids(got[0].PrevProcs), []uint32{1044}) {
		t.Fatalf("got %+v", got)
	}
	if got := tb.Reconcile(dump, nil, t0); len(got) != 0 {
		t.Fatalf("idempotent reconcile emitted %+v", got)
	}
}

func TestReconcileOpenCancelsPending(t *testing.T) {
	tb := New(grace)
	k := key("0.0.0.0", 8080)
	tb.Apply(open(1, k, 1))
	tb.Apply(closeObs(1, k))
	got := tb.Reconcile([]model.Observation{dumpObs(2, k, 2)}, nil, t0)
	if len(got) != 1 || got[0].Kind != model.OwnerChanged {
		t.Fatalf("got %+v", got)
	}
	if got := tb.Expire(t0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("pending survived: %+v", got)
	}
}

func TestLiveCookieUnderNewKeyIsNotOwnerChanged(t *testing.T) {
	tb := New(0)
	bound := model.NewKey(4026531840, "udp", netip.MustParseAddr("0.0.0.0"), 5353)
	connected := model.NewKey(4026531840, "udp", netip.MustParseAddr("10.0.0.1"), 5353)
	tb.Apply(open(1, bound, 10))
	// The same socket re-observed under another address (bound to 0.0.0.0, then connect()ed).
	if got := tb.Apply(open(1, connected, 10)); len(got) != 0 {
		t.Fatalf("re-observed cookie emitted %+v", got)
	}
}

// retitled returns p with the non-identity fields changed: a uid drop, a new
// comm and a rewritten command line.
func retitled(p model.Process) model.Process {
	p.UID, p.Comm, p.Cmdline = 33, "nginx: worker", []string{"nginx: worker process"}
	return p
}

func TestNonIdentityChangeIsSilentButStored(t *testing.T) {
	k := key("0.0.0.0", 8080)

	t.Run("reconcile", func(t *testing.T) {
		tb := New(0)
		tb.Apply(open(1, k, 5))
		d := dumpObs(1, k, 5)
		d.Proc = retitled(d.Proc)
		if got := tb.Reconcile([]model.Observation{d}, nil, t0); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
		if snap := tb.Snapshot(); len(snap) != 1 || !snap[0].Procs[0].Equal(d.Proc) {
			t.Fatalf("snapshot = %+v, want the new holder", snap)
		}
	})
	t.Run("reopen within grace", func(t *testing.T) {
		tb := New(grace)
		tb.Apply(open(1, k, 5))
		tb.Apply(closeObs(1, k))
		o := open(2, k, 5)
		o.Proc = retitled(o.Proc)
		if got := tb.Apply(o); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
		if snap := tb.Snapshot(); len(snap) != 1 || !snap[0].Procs[0].Equal(o.Proc) {
			t.Fatalf("snapshot = %+v, want the new holder", snap)
		}
	})
}

func TestIdentityChangeIsOwnerChanged(t *testing.T) {
	k := key("0.0.0.0", 22)
	for name, change := range map[string]func(*model.Process){
		"unit":        func(p *model.Process) { p.Unit = "ssh.service" },
		"socket unit": func(p *model.Process) { p.SocketUnit = "ssh.socket" },
		"exe":         func(p *model.Process) { p.Exe = "/usr/sbin/sshd" },
		"sha256":      func(p *model.Process) { p.SHA256 = "ab" },
		"container":   func(p *model.Process) { p.Container = model.Container{Runtime: "docker", ID: "c"} },
		"cgroup":      func(p *model.Process) { p.CgroupID = 9 },
	} {
		tb := New(0)
		tb.Apply(open(1, k, 1))
		d := dumpObs(1, k, 1)
		change(&d.Proc)
		if got := tb.Reconcile([]model.Observation{d}, nil, t0); len(got) != 1 || got[0].Kind != model.OwnerChanged {
			t.Errorf("%s: got %+v", name, got)
		}
	}
}
