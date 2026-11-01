package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/thapr0digy/listener-watch/internal/model"
	"github.com/thapr0digy/listener-watch/internal/state"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

type fakeSource chan model.Observation

func (f fakeSource) Events() <-chan model.Observation { return f }

// recorder is a Sink that forwards what it gets to channels, so tests wait on
// real signals instead of sleeping.
type recorder struct {
	snapshots chan []state.Listener
	changes   chan []state.Change
}

func newRecorder() *recorder {
	return &recorder{snapshots: make(chan []state.Listener, 8), changes: make(chan []state.Change, 64)}
}
func (r *recorder) Snapshot(l []state.Listener) { r.snapshots <- l }
func (r *recorder) Changes(c []state.Change)    { r.changes <- c }

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
}

// start runs the agent with a snapshot func that blocks until release is closed.
func start(t *testing.T, baseline []model.Observation, snapErr error) *harness {
	t.Helper()
	h := &harness{
		t: t, src: make(fakeSource), release: make(chan struct{}),
		entered: make(chan struct{}), rec: newRecorder(), result: make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	t.Cleanup(cancel)
	snap := func() ([]model.Observation, error) {
		close(h.entered)
		<-h.release
		return baseline, snapErr
	}
	go func() { h.result <- Run(ctx, h.src, snap, h.rec) }()
	<-h.entered
	return h
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
// event for the same cookie carries it. No Opened change, and the owner is kept:
// a later Closed carries pid 42.
func TestOwnerFromEventFillsBaselineGap(t *testing.T) {
	h := start(t, []model.Observation{obs(model.Opened, 7, 8080, 0, model.SourceBaseline)}, nil)
	h.send(obs(model.Opened, 7, 8080, 42, model.SourceEBPF))
	close(h.release)
	h.snapshot()

	h.send(obs(model.Closed, 7, 8080, 0, model.SourceEBPF))
	got := h.change()
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
