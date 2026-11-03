package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

type fakeSource chan model.Observation

func (f fakeSource) Events() <-chan model.Observation { return f }

// recorder is a Sink that forwards what it gets to channels, so tests wait on
// real signals instead of sleeping.
type recorder struct {
	snapshots chan []state.Listener
	changes   chan []state.Change
	exposures chan []state.ExposureChange

	mu    sync.Mutex
	order []string // "changes" / "snapshot", in call order
}

func newRecorder() *recorder {
	return &recorder{snapshots: make(chan []state.Listener, 8), changes: make(chan []state.Change, 64),
		exposures: make(chan []state.ExposureChange, 64)}
}

func (r *recorder) ExposureChanges(c []state.ExposureChange) {
	r.note("exposures")
	r.exposures <- c
}

func (r *recorder) Snapshot(l []state.Listener) {
	r.note("snapshot")
	r.snapshots <- l
}

func (r *recorder) Changes(c []state.Change) {
	r.note("changes")
	r.changes <- c
}

func (r *recorder) note(what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, what)
}

func (r *recorder) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.order)
}

func key(port uint16) model.ListenerKey {
	return model.NewKey(4026531840, "tcp", netip.MustParseAddr("0.0.0.0"), port)
}

func obs(kind model.Kind, cookie uint64, port uint16, pid uint32, src model.Source) model.Observation {
	o := model.Observation{Kind: kind, Cookie: cookie, Key: key(port), At: t0, Source: src}
	if pid != 0 {
		o.Proc = model.Process{PID: pid, Comm: "svc"}
	}
	return o
}

type harness struct {
	t       *testing.T
	src     fakeSource
	release chan struct{}
	entered chan struct{}
	rec     *recorder
	cancel  context.CancelFunc
	result  chan error

	// Every snapshot call after the first is a recheck: it signals on rechecks,
	// then returns the next reply from dumps.
	rechecks chan struct{}
	dumps    chan dump
	inFlight atomic.Int32
	maxIn    atomic.Int32
}

type dump struct {
	obs []model.Observation
	err error
}

// start runs the agent as M1 does (Options{}) with a snapshot func that blocks
// until release is closed.
func start(t *testing.T, baseline []model.Observation, snapErr error) *harness {
	t.Helper()
	return startWith(t, baseline, snapErr, Options{})
}

// startWith is start with options; recheck dumps are driven by recheck and reply.
func startWith(t *testing.T, baseline []model.Observation, snapErr error, opts Options) *harness {
	t.Helper()
	h := &harness{
		t: t, src: make(fakeSource), release: make(chan struct{}),
		entered: make(chan struct{}), rec: newRecorder(), result: make(chan error, 1),
		rechecks: make(chan struct{}), dumps: make(chan dump),
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	t.Cleanup(cancel)
	var calls atomic.Int32
	snap := func() ([]model.Observation, error) {
		if calls.Add(1) == 1 {
			close(h.entered)
			<-h.release
			return baseline, snapErr
		}
		n := h.inFlight.Add(1)
		defer h.inFlight.Add(-1)
		for {
			m := h.maxIn.Load()
			if n <= m || h.maxIn.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case h.rechecks <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case d := <-h.dumps:
			return d.obs, d.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	go func() { h.result <- Run(ctx, h.src, snap, h.rec, opts) }()
	<-h.entered
	return h
}

// recheck waits for the agent to start a recheck dump.
func (h *harness) recheck() {
	h.t.Helper()
	select {
	case <-h.rechecks:
	case <-time.After(5 * time.Second):
		h.t.Fatal("no recheck started")
	}
}

// reply hands the running recheck its dump.
func (h *harness) reply(obs []model.Observation, err error) {
	h.t.Helper()
	select {
	case h.dumps <- dump{obs, err}:
	case <-time.After(5 * time.Second):
		h.t.Fatal("recheck did not take its dump")
	}
}

// send delivers an event; the source is unbuffered, so returning means Run took it.
func (h *harness) send(o model.Observation) {
	h.t.Helper()
	select {
	case h.src <- o:
	case <-time.After(5 * time.Second):
		h.t.Fatal("event not consumed")
	}
}

func (h *harness) snapshot() []state.Listener {
	h.t.Helper()
	select {
	case s := <-h.rec.snapshots:
		return s
	case <-time.After(5 * time.Second):
		h.t.Fatal("no snapshot published")
		return nil
	}
}

func (h *harness) change() []state.Change {
	h.t.Helper()
	select {
	case c := <-h.rec.changes:
		return c
	case <-time.After(5 * time.Second):
		h.t.Fatal("no changes published")
		return nil
	}
}

// stop cancels Run and asserts it exits, then returns any changes not yet read.
func (h *harness) stop() []state.Change {
	h.t.Helper()
	h.cancel()
	select {
	case err := <-h.result:
		if err != nil {
			h.t.Fatalf("Run returned %v after cancel", err)
		}
	case <-time.After(5 * time.Second):
		h.t.Fatal("Run did not exit on cancel")
	}
	var rest []state.Change
	for {
		select {
		case c := <-h.rec.changes:
			rest = append(rest, c...)
		default:
			return rest
		}
	}
}

func TestBaselineGoesOutAsSnapshotNotOpened(t *testing.T) {
	h := start(t, []model.Observation{
		obs(model.Opened, 1, 80, 10, model.SourceBaseline),
		obs(model.Opened, 2, 443, 11, model.SourceBaseline),
	}, nil)
	close(h.release)

	if got := h.snapshot(); len(got) != 2 {
		t.Fatalf("snapshot = %+v, want 2 listeners", got)
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("baseline produced changes: %+v", rest)
	}
}

func TestOpenDuringSnapshotPublishedOnce(t *testing.T) {
	h := start(t, []model.Observation{obs(model.Opened, 7, 8080, 42, model.SourceBaseline)}, nil)
	h.send(obs(model.Opened, 7, 8080, 42, model.SourceEBPF))
	close(h.release)

	if got := h.snapshot(); len(got) != 1 || got[0].Key != key(8080) {
		t.Fatalf("snapshot = %+v, want the 8080 listener", got)
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("duplicate open produced changes: %+v", rest)
	}
}

func TestCloseDuringSnapshotLeavesNoPhantom(t *testing.T) {
	h := start(t, []model.Observation{obs(model.Opened, 9, 9000, 5, model.SourceBaseline)}, nil)
	h.send(obs(model.Closed, 9, 9000, 0, model.SourceEBPF))
	close(h.release)

	if got := h.snapshot(); len(got) != 1 {
		t.Fatalf("snapshot = %+v, want the baseline listener", got)
	}
	got := h.change()
	if len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != key(9000) {
		t.Fatalf("changes = %+v, want one Closed for 9000", got)
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("extra changes: %+v", rest)
	}
}

func TestLiveEventsFlowAfterReplay(t *testing.T) {
	h := start(t, nil, nil)
	close(h.release)
	h.snapshot()

	h.send(obs(model.Opened, 3, 3000, 8, model.SourceEBPF))
	got := h.change()
	if len(got) != 1 || got[0].Kind != model.Opened || got[0].Key != key(3000) {
		t.Fatalf("changes = %+v, want Opened 3000", got)
	}
	h.stop()
}

func TestSnapshotErrorReturned(t *testing.T) {
	boom := errors.New("diag failed")
	h := start(t, nil, boom)
	close(h.release)

	select {
	case err := <-h.result:
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want wrapping %v", err, boom)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if len(h.rec.snapshots) != 0 {
		t.Fatal("snapshot published despite error")
	}
}

// The baseline can hold a listener with no owner (MPTCP race) while the kernel
// event for the same cookie carries it. The filled-in owner is published as an
// OwnerChanged, and a later Closed carries pid 42.
func TestOwnerFromEventFillsBaselineGap(t *testing.T) {
	h := start(t, []model.Observation{obs(model.Opened, 7, 8080, 0, model.SourceBaseline)}, nil)
	h.send(obs(model.Opened, 7, 8080, 42, model.SourceEBPF))
	close(h.release)
	h.snapshot()

	got := h.change()
	if len(got) != 1 || got[0].Kind != model.OwnerChanged || len(got[0].Procs) != 1 || got[0].Procs[0].PID != 42 {
		t.Fatalf("changes = %+v, want one OwnerChanged to pid 42", got)
	}

	h.send(obs(model.Closed, 7, 8080, 0, model.SourceEBPF))
	got = h.change()
	if len(got) != 1 || got[0].Kind != model.Closed || len(got[0].Procs) != 1 || got[0].Procs[0].PID != 42 {
		t.Fatalf("changes = %+v, want one Closed carrying pid 42", got)
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("extra changes: %+v", rest)
	}
}

func TestCancelDuringSnapshotExits(t *testing.T) {
	h := start(t, nil, nil)
	h.cancel()
	close(h.release)
	select {
	case <-h.result:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit")
	}
}

// stamp marks an observation so a test can tell it went through Enrich, and how
// many times.
func stamp(o model.Observation) model.Observation {
	if !o.Proc.IsZero() {
		o.Proc.Exe = "/usr/bin/svc"
		o.Proc.Cmdline = append(slices.Clone(o.Proc.Cmdline), "enriched")
	}
	return o
}

func enrichedOnce(p model.Process) bool {
	return p.Exe == "/usr/bin/svc" && slices.Equal(p.Cmdline, []string{"enriched"})
}

func TestEnrichAppliedToBaselineAndLive(t *testing.T) {
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 80, 10, model.SourceBaseline)}, nil,
		Options{Enrich: stamp})
	h.send(obs(model.Opened, 2, 443, 11, model.SourceEBPF)) // buffered during the baseline
	close(h.release)

	snap := h.snapshot()
	if len(snap) != 1 || len(snap[0].Procs) != 1 || !enrichedOnce(snap[0].Procs[0]) {
		t.Fatalf("snapshot = %+v, want the 80 listener enriched once", snap)
	}
	got := h.change()
	if len(got) != 1 || got[0].Key != key(443) || !enrichedOnce(got[0].Procs[0]) {
		t.Fatalf("buffered changes = %+v, want Opened 443 enriched once", got)
	}

	h.send(obs(model.Opened, 3, 8080, 12, model.SourceEBPF))
	got = h.change()
	if len(got) != 1 || got[0].Key != key(8080) || !enrichedOnce(got[0].Procs[0]) {
		t.Fatalf("live changes = %+v, want Opened 8080 enriched once", got)
	}
	h.stop()
}

func TestEnrichFailureStillPublishes(t *testing.T) {
	unchanged := func(o model.Observation) model.Observation { return o }
	h := startWith(t, nil, nil, Options{Enrich: unchanged})
	close(h.release)
	h.snapshot()

	h.send(obs(model.Opened, 3, 3000, 8, model.SourceEBPF))
	got := h.change()
	if len(got) != 1 || got[0].Kind != model.Opened || got[0].Procs[0].PID != 8 || got[0].Procs[0].Exe != "" {
		t.Fatalf("changes = %+v, want Opened 3000 with an empty exe", got)
	}
	h.stop()
}

func TestGraceTimerPublishesClose(t *testing.T) {
	const grace = 50 * time.Millisecond
	h := startWith(t, nil, nil, Options{CloseGrace: grace})
	close(h.release)
	h.snapshot()

	open := obs(model.Opened, 4, 4000, 9, model.SourceEBPF)
	open.At = time.Now()
	h.send(open)
	if got := h.change(); len(got) != 1 || got[0].Kind != model.Opened {
		t.Fatalf("changes = %+v, want Opened", got)
	}

	closed := obs(model.Closed, 4, 4000, 0, model.SourceEBPF)
	closed.At = time.Now()
	h.send(closed)
	got := h.change()
	if waited := time.Since(closed.At); waited < grace {
		t.Fatalf("Closed published after %v, before the %v grace", waited, grace)
	}
	if len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != key(4000) || got[0].Procs[0].PID != 9 {
		t.Fatalf("changes = %+v, want Closed 4000 held by pid 9", got)
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("extra changes: %+v", rest)
	}
}

func TestRecheckPublishesReconcileAndSnapshot(t *testing.T) {
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 80, 10, model.SourceBaseline)}, nil,
		Options{Recheck: 10 * time.Millisecond, Enrich: stamp})
	close(h.release)
	h.snapshot()

	h.recheck()
	h.reply([]model.Observation{obs(model.Opened, 2, 443, 11, model.SourceBaseline)}, nil)

	got := h.change()
	if len(got) != 2 {
		t.Fatalf("changes = %+v, want Closed 80 and Opened 443", got)
	}
	for _, c := range got {
		if c.Source != model.SourceReconcile {
			t.Fatalf("change %+v not tagged reconcile", c)
		}
	}
	if got[0].Kind != model.Opened || got[0].Key != key(443) || !enrichedOnce(got[0].Procs[0]) ||
		got[1].Kind != model.Closed || got[1].Key != key(80) {
		t.Fatalf("changes = %+v, want Opened 443 (enriched) then Closed 80", got)
	}
	if snap := h.snapshot(); len(snap) != 1 || snap[0].Key != key(443) {
		t.Fatalf("recheck snapshot = %+v, want only 443", snap)
	}
	if calls := h.rec.calls(); !slices.Equal(calls[len(calls)-2:], []string{"changes", "snapshot"}) {
		t.Fatalf("sink calls = %v, want the reconcile changes before the snapshot", calls)
	}
	h.stop()
}

// The dump can be older than a live event that arrived while it ran, so the
// sockets that event names are left to the live stream.
func TestRecheckIgnoresSocketsTouchedDuringDump(t *testing.T) {
	const x, y = 1, 2
	h := startWith(t, []model.Observation{obs(model.Opened, y, 443, 11, model.SourceBaseline)}, nil,
		Options{Recheck: 10 * time.Millisecond})
	close(h.release)
	h.snapshot()

	h.recheck()
	h.send(obs(model.Opened, x, 80, 10, model.SourceEBPF))
	if got := h.change(); len(got) != 1 || got[0].Kind != model.Opened || got[0].Source != model.SourceEBPF {
		t.Fatalf("changes = %+v, want the live Opened 80", got)
	}
	h.send(obs(model.Closed, y, 443, 0, model.SourceEBPF))
	if got := h.change(); len(got) != 1 || got[0].Kind != model.Closed || got[0].Source != model.SourceEBPF {
		t.Fatalf("changes = %+v, want the live Closed 443", got)
	}
	h.reply([]model.Observation{obs(model.Opened, y, 443, 11, model.SourceBaseline)}, nil)

	if snap := h.snapshot(); len(snap) != 1 || snap[0].Key != key(80) {
		t.Fatalf("recheck snapshot = %+v, want only 80", snap)
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("reconcile changed touched sockets: %+v", rest)
	}
}

// With Settle, live events keep being applied for a while after the dump
// returns: a close that the dump predates is left to the live stream, and the
// reconcile waits out Settle.
func TestRecheckSettleLeavesLateCloseToLiveStream(t *testing.T) {
	const x, y = 1, 2
	const settle = 300 * time.Millisecond
	h := startWith(t, []model.Observation{
		obs(model.Opened, x, 80, 10, model.SourceBaseline),
		obs(model.Opened, y, 443, 11, model.SourceBaseline),
	}, nil, Options{Recheck: 10 * time.Millisecond, Settle: settle})
	close(h.release)
	h.snapshot()

	h.recheck()
	h.reply([]model.Observation{
		obs(model.Opened, x, 80, 10, model.SourceBaseline),
		obs(model.Opened, y, 443, 11, model.SourceBaseline),
	}, nil)
	returned := time.Now()
	time.Sleep(settle / 6) // let the loop take the dump, so the close lands inside Settle
	h.send(obs(model.Closed, y, 443, 0, model.SourceEBPF))
	if got := h.change(); len(got) != 1 || got[0].Kind != model.Closed || got[0].Key != key(443) || got[0].Source != model.SourceEBPF {
		t.Fatalf("changes = %+v, want the live Closed 443", got)
	}

	snap := h.snapshot()
	if elapsed := time.Since(returned); elapsed < settle {
		t.Fatalf("reconciled %s after the dump returned, want at least Settle (%s)", elapsed, settle)
	}
	if len(snap) != 1 || snap[0].Key != key(80) {
		t.Fatalf("recheck snapshot = %+v, want only 80", snap)
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("reconcile changed the closed socket: %+v", rest)
	}
}

func TestDropsRiseTriggersRecheck(t *testing.T) {
	var drops atomic.Uint64
	drops.Store(5)
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 80, 10, model.SourceBaseline)}, nil,
		Options{Drops: drops.Load, DropsCheck: 2 * time.Millisecond})
	close(h.release)
	h.snapshot()

	select {
	case <-h.rechecks:
		t.Fatal("recheck started without a rise in drops")
	case <-time.After(30 * time.Millisecond):
	}

	drops.Add(1)
	h.recheck()
	h.reply([]model.Observation{obs(model.Opened, 1, 80, 10, model.SourceBaseline)}, nil)
	if snap := h.snapshot(); len(snap) != 1 || snap[0].Key != key(80) {
		t.Fatalf("recheck snapshot = %+v, want 80", snap)
	}

	select {
	case <-h.rechecks:
		t.Fatal("second recheck without a further rise")
	case <-time.After(30 * time.Millisecond):
	}
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("unchanged dump produced changes: %+v", rest)
	}
}

func TestRecheckErrorKeepsRunning(t *testing.T) {
	h := startWith(t, nil, nil, Options{Recheck: 10 * time.Millisecond})
	close(h.release)
	h.snapshot()

	h.recheck()
	h.reply(nil, errors.New("diag failed"))

	h.send(obs(model.Opened, 3, 3000, 8, model.SourceEBPF))
	if got := h.change(); len(got) != 1 || got[0].Kind != model.Opened {
		t.Fatalf("changes = %+v, want Opened 3000", got)
	}

	h.recheck()
	h.reply([]model.Observation{obs(model.Opened, 3, 3000, 8, model.SourceBaseline)}, nil)
	if snap := h.snapshot(); len(snap) != 1 || snap[0].Key != key(3000) {
		t.Fatalf("recheck snapshot = %+v, want 3000", snap)
	}
	if len(h.rec.snapshots) != 0 {
		t.Fatal("the failed recheck published a snapshot")
	}
	h.stop()
}

// Rechecks due while one runs (by the interval or a rise in drops) are not
// started alongside it.
func TestOneRecheckAtATime(t *testing.T) {
	var drops atomic.Uint64
	h := startWith(t, nil, nil, Options{
		Recheck: 2 * time.Millisecond, Drops: drops.Load, DropsCheck: 2 * time.Millisecond,
	})
	close(h.release)
	h.snapshot()

	h.recheck()
	drops.Add(1)
	select {
	case <-h.rechecks:
		t.Fatal("second recheck started while the first was running")
	case <-time.After(30 * time.Millisecond):
	}
	h.reply(nil, nil)
	h.snapshot()
	h.recheck()
	if n := h.maxIn.Load(); n != 1 {
		t.Fatalf("%d recheck dumps ran at once, want 1", n)
	}
	h.reply(nil, nil)
	h.stop()
}

func TestFailedDropsRecheckRetried(t *testing.T) {
	var drops atomic.Uint64
	h := startWith(t, nil, nil, Options{Drops: drops.Load, DropsCheck: 2 * time.Millisecond})
	close(h.release)
	h.snapshot()

	drops.Add(1)
	h.recheck()
	h.reply(nil, errors.New("diag failed"))
	h.recheck()
	h.reply(nil, nil)
	h.snapshot()
	h.stop()
}

// A socket unit that systemd opened after the matcher's last list (at boot, the
// D-Bus bus is not up yet) is learned later; the next recheck must deliver it as an
// OwnerChanged, and the table must then hold the enriched owner.
func TestRecheckDeliversLateSocketUnit(t *testing.T) {
	var unitKnown atomic.Bool
	enrich := func(o model.Observation) model.Observation {
		if o.Proc.PID == 1 && unitKnown.Load() {
			o.Proc.SocketUnit, o.Proc.Unit = "ssh.socket", "ssh.service"
		}
		return o
	}
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 22, 1, model.SourceBaseline)}, nil,
		Options{Recheck: 10 * time.Millisecond, Enrich: enrich})
	close(h.release)
	if snap := h.snapshot(); len(snap) != 1 || snap[0].Procs[0].SocketUnit != "" {
		t.Fatalf("baseline snapshot = %+v, want port 22 without a socket unit", snap)
	}

	unitKnown.Store(true)
	h.recheck()
	h.reply([]model.Observation{obs(model.Opened, 1, 22, 1, model.SourceBaseline)}, nil)

	got := h.change()
	if len(got) != 1 || got[0].Kind != model.OwnerChanged || got[0].Key != key(22) ||
		got[0].Source != model.SourceReconcile {
		t.Fatalf("changes = %+v, want one reconcile OwnerChanged on 22", got)
	}
	if p := got[0].Procs; len(p) != 1 || p[0].PID != 1 || p[0].SocketUnit != "ssh.socket" || p[0].Unit != "ssh.service" {
		t.Fatalf("Procs = %+v, want pid 1 with ssh.socket / ssh.service", p)
	}
	if p := got[0].PrevProcs; len(p) != 1 || p[0].PID != 1 || p[0].SocketUnit != "" || p[0].Unit != "" {
		t.Fatalf("PrevProcs = %+v, want pid 1 without a unit", p)
	}
	if snap := h.snapshot(); len(snap) != 1 || snap[0].Procs[0].SocketUnit != "ssh.socket" {
		t.Fatalf("recheck snapshot = %+v, want the enriched owner", snap)
	}

	// A further recheck with the same answer is quiet.
	h.recheck()
	h.reply([]model.Observation{obs(model.Opened, 1, 22, 1, model.SourceBaseline)}, nil)
	h.snapshot()
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("extra changes after a steady recheck: %+v", rest)
	}
}

// The same with the activated service holding the socket too (systemd and sshd).
func TestRecheckDeliversLateSocketUnitWithCoOwner(t *testing.T) {
	var unitKnown atomic.Bool
	enrich := func(o model.Observation) model.Observation {
		if o.Proc.PID == 1 && unitKnown.Load() {
			o.Proc.SocketUnit, o.Proc.Unit = "ssh.socket", "ssh.service"
		}
		return o
	}
	holders := func() []model.Observation {
		return []model.Observation{
			obs(model.Opened, 1, 22, 500, model.SourceBaseline),
			obs(model.Opened, 1, 22, 1, model.SourceBaseline),
		}
	}
	h := startWith(t, holders(), nil, Options{Recheck: 10 * time.Millisecond, Enrich: enrich})
	close(h.release)
	h.snapshot()

	unitKnown.Store(true)
	h.recheck()
	h.reply(holders(), nil)

	got := h.change()
	if len(got) != 1 || got[0].Kind != model.OwnerChanged {
		t.Fatalf("changes = %+v, want one OwnerChanged", got)
	}
	p := got[0].Procs
	if len(p) != 2 || p[0].PID != 1 || p[0].SocketUnit != "ssh.socket" || p[1].PID != 500 || p[1].SocketUnit != "" {
		t.Fatalf("Procs = %+v, want pid 1 with ssh.socket and pid 500 unchanged", p)
	}
	if prev := got[0].PrevProcs; len(prev) != 2 || prev[0].SocketUnit != "" {
		t.Fatalf("PrevProcs = %+v, want both holders without a socket unit", prev)
	}
	h.stop()
}
