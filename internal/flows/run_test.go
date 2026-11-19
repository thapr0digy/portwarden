package flows

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
)

type sinkRecorder struct {
	mu  sync.Mutex
	got []*eventsv1.HostFlows
}

func (s *sinkRecorder) HostFlows(f *eventsv1.HostFlows) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, f)
}

// fakeClock is a settable clock, safe to set while Run reads it.
type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func newClock(t time.Time) *fakeClock { return &fakeClock{at: t} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = t
}

func testConfig(clock *fakeClock, calls *int) Config {
	return Config{
		Identify: func(tgid uint32, _ uint64) Process {
			*calls++
			return Process{Exe: "/usr/bin/curl", Unit: "session-1.scope"}
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now: clock.now,
	}
}

func newTestRunner(cfg Config, sink Sink) *runner {
	return &runner{cfg: cfg, sink: sink, window: NewWindow(cfg.now()), pending: map[uint64]pending{}, processes: map[uint32]ident{}}
}

func outEvent(cookie uint64) Event {
	return Event{Kind: KindOut, Cookie: cookie, TGID: 42, Comm: "curl", Remote: netip.MustParseAddrPort("10.0.0.9:443")}
}

func head(cookie uint64, service string) Event {
	return Event{Kind: KindHead, Cookie: cookie, App: AppTLS, Service: service}
}

// A made connection is named by the first bytes that follow it, joined by cookie.
func TestRunJoinsFirstBytesByCookie(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	r := newTestRunner(testConfig(clock, &calls), sink)
	r.handle(outEvent(1))
	r.handle(outEvent(2))
	r.handle(head(2, "b.example"))
	r.handle(head(1, "a.example"))
	clock.set(t0.Add(time.Hour))
	r.flush()
	f := sink.got[0].GetFlows()
	checkValid(t, sink.got)
	if len(f) != 2 || f[0].GetServiceName() != "a.example" || f[1].GetServiceName() != "b.example" || f[0].GetExe() != "/usr/bin/curl" {
		t.Fatalf("flows = %v", f)
	}
}

// A connection whose client never sends (a server-first protocol) is still counted, unnamed,
// once its wait ends; first bytes arriving after that are not counted again.
func TestRunCountsUnnamedAfterTheWait(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	r := newTestRunner(testConfig(clock, &calls), sink)
	r.handle(outEvent(1))
	clock.set(t0.Add(headWait - time.Millisecond))
	r.expire(clock.now())
	if len(r.pending) != 1 {
		t.Fatal("expired before its wait")
	}
	clock.set(t0.Add(headWait))
	r.expire(clock.now())
	r.handle(head(1, "late.example"))
	clock.set(t0.Add(time.Hour))
	r.flush()
	f := sink.got[0].GetFlows()
	if len(f) != 1 || f[0].GetServiceName() != "" || f[0].GetAppProto() != "" || f[0].GetCount() != 1 {
		t.Fatalf("flows = %v", f)
	}
}

// Waiting connections are bounded: past maxPending a new one is counted unnamed at once.
func TestRunBoundsWaitingConnections(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	r := newTestRunner(testConfig(clock, &calls), sink)
	for c := range uint64(maxPending + 5) {
		r.handle(outEvent(c + 1))
	}
	if len(r.pending) != maxPending || len(r.window.rows) != 1 || r.window.rows[keyOf(r.conn(outEvent(1), t0))].count != 5 {
		t.Fatalf("pending %d", len(r.pending))
	}
}

// A process is read once per window, and again when its tgid comes back with another name.
func TestRunIdentifiesOncePerProcess(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	r := newTestRunner(testConfig(clock, &calls), sink)
	for c := range uint64(10) {
		r.handle(outEvent(c + 1))
	}
	reused := outEvent(11)
	reused.Comm = "wget"
	r.handle(reused)
	if calls != 2 {
		t.Errorf("identified %d times, want 2", calls)
	}
	r.flush()
	r.handle(outEvent(12))
	if calls != 3 {
		t.Errorf("identified %d times after the window, want 3", calls)
	}
}

// Inbound connections are counted at once (no first bytes are read for them).
func TestRunCountsInboundAtOnce(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	r := newTestRunner(testConfig(clock, &calls), sink)
	r.handle(Event{Kind: KindIn, TGID: 7, Comm: "nginx", LocalPort: 443, Remote: netip.MustParseAddrPort("10.0.0.7:5000")})
	if len(r.pending) != 0 || len(r.window.rows) != 1 {
		t.Fatalf("pending %d rows %d", len(r.pending), len(r.window.rows))
	}
}

// Records the kernel lost to a full buffer are counted as dropped, per window.
func TestRunCountsKernelDrops(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	cfg := testConfig(clock, &calls)
	drops := uint64(100)
	cfg.Drops = func() uint64 { return drops }
	r := newTestRunner(cfg, sink)
	r.lastDrops = cfg.Drops()
	drops = 107
	clock.set(t0.Add(time.Hour))
	r.flush()
	drops = 110
	clock.set(t0.Add(2 * time.Hour))
	r.flush()
	if sink.got[0].GetDropped() != 7 || sink.got[1].GetDropped() != 3 {
		t.Errorf("dropped %d, %d", sink.got[0].GetDropped(), sink.got[1].GetDropped())
	}
}

// Stopping counts every connection still waiting and sends the partial window.
func TestRunSendsThePartialWindowOnStop(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	cfg := testConfig(clock, &calls)
	events := make(chan Event)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, cfg, events, sink); close(done) }()
	events <- outEvent(1)
	events <- outEvent(2)
	events <- head(1, "a.example")
	clock.set(t0.Add(10 * time.Minute))
	cancel()
	<-done
	checkValid(t, sink.got)
	if len(sink.got) != 1 || len(sink.got[0].GetFlows()) != 2 || !sink.got[0].GetWindowEnd().AsTime().Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("sent %v", sink.got)
	}
}

// Probes that could not run make every window unread, never "no connections".
func TestRunUnreadable(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	cfg := testConfig(clock, &calls)
	cfg.Unreadable = "load flows programs: operation not permitted"
	ctx, cancel := context.WithCancel(context.Background())
	clock.set(t0.Add(time.Minute))
	cancel()
	Run(ctx, cfg, nil, sink)
	checkValid(t, sink.got)
	if len(sink.got) != 1 || sink.got[0].GetRead() || sink.got[0].GetUnreadable() != cfg.Unreadable {
		t.Fatalf("sent %v", sink.got)
	}
}

// When the kernel reader dies, what it saw is sent as read, and the windows after it unread.
func TestRunReaderStopped(t *testing.T) {
	clock, calls, sink := newClock(t0), 0, &sinkRecorder{}
	cfg := testConfig(clock, &calls)
	events := make(chan Event, 1)
	events <- outEvent(1)
	close(events)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, cfg, events, sink); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sink.mu.Lock()
		n := len(sink.got)
		sink.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	clock.set(t0.Add(time.Minute))
	cancel()
	<-done
	checkValid(t, sink.got)
	if len(sink.got) != 2 || !sink.got[0].GetRead() || len(sink.got[0].GetFlows()) != 1 || sink.got[1].GetRead() {
		t.Fatalf("sent %v", sink.got)
	}
}
