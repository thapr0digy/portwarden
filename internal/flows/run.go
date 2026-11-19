package flows

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
)

const (
	// DefaultWindow is how long one asm.host.flows window lasts.
	DefaultWindow = time.Hour
	// headWait is how long a made connection waits for its first bytes before it is
	// counted unnamed (a server-first protocol, or a client that never sends).
	headWait = 5 * time.Second
	// maxPending bounds the made connections waiting for their first bytes; past it a new
	// one is counted unnamed at once.
	maxPending = 16384
	// maxProcesses bounds the process cache, which is emptied at each window's end.
	maxProcesses = 4096
)

// EventKind says what a kernel Event reports.
type EventKind uint8

// The kernel's records (bpf/flows.bpf.c flow_kind).
const (
	KindOut  EventKind = 1 // a connection made
	KindIn   EventKind = 2 // a connection accepted
	KindHead EventKind = 3 // what a made connection's first bytes named
)

// Event is one record from the kernel, decoded (probes.Flows). A KindHead event carries
// only Cookie, App and Service: its bytes were sniffed and dropped in the reader.
type Event struct {
	Kind EventKind
	// Cookie joins a made connection (KindOut) to its first bytes (KindHead); 0 for KindIn.
	Cookie    uint64
	TGID      uint32
	Comm      string
	CgroupID  uint64
	LocalPort uint16
	Remote    netip.AddrPort
	App       string
	Service   string
}

// Process is what Identify reads about a connection's process.
type Process struct{ Exe, Unit string }

// Sink takes each window's events (the publisher). It must not block.
type Sink interface {
	HostFlows(*eventsv1.HostFlows)
}

// Config configures Run.
type Config struct {
	// Window is the reporting window (DefaultWindow).
	Window time.Duration
	// Identify reads a process's executable and systemd unit; called once per process and
	// window. Fields it cannot read stay "".
	Identify func(tgid uint32, cgroupID uint64) Process
	// Drops returns the kernel's running count of records lost to a full buffer; nil
	// when there is none.
	Drops func() uint64
	// Unreadable, when set, is why the connections cannot be observed: every window is
	// then sent unread with this reason.
	Unreadable string
	Log        *slog.Logger
	// now is the clock (tests).
	now func() time.Time
}

type pending struct {
	conn     Conn
	deadline time.Time
}

type runner struct {
	cfg        Config
	sink       Sink
	window     *Window
	pending    map[uint64]pending
	processes  map[uint32]ident
	lastDrops  uint64
	unreadable string
}

// ident is a cached Process, kept only while the tgid carries the same name (a reused
// tgid is identified again).
type ident struct {
	comm string
	Process
}

// Run aggregates events into windows and sends each window to sink when it ends, until
// ctx ends; then it counts the connections still waiting for their first bytes, sends the
// partial window and returns. When events closes early (the kernel reader died) the
// windows from then on are sent unread.
func Run(ctx context.Context, cfg Config, events <-chan Event, sink Sink) {
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	r := &runner{cfg: cfg, sink: sink, window: NewWindow(cfg.now()), pending: map[uint64]pending{},
		processes: map[uint32]ident{}, unreadable: cfg.Unreadable}
	if cfg.Drops != nil {
		r.lastDrops = cfg.Drops()
	}
	if r.unreadable != "" {
		events = nil
	}
	window := time.NewTicker(cfg.Window)
	defer window.Stop()
	sweep := time.NewTicker(time.Second)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			r.expire(time.Time{})
			r.flush()
			return
		case e, ok := <-events:
			if !ok {
				// What was observed until now is sent as read; the windows after it unread.
				events = nil
				r.expire(time.Time{})
				r.flush()
				r.unreadable = "the kernel connection reader stopped"
				cfg.Log.Warn("connection flows: the kernel reader stopped; windows are sent unread from now on")
				continue
			}
			r.handle(e)
		case <-sweep.C:
			r.expire(r.cfg.now())
		case <-window.C:
			r.flush()
		}
	}
}

func (r *runner) handle(e Event) {
	now := r.cfg.now()
	switch e.Kind {
	case KindOut, KindIn:
		c := r.conn(e, now)
		if e.Kind == KindIn || len(r.pending) >= maxPending {
			r.window.Add(c)
			return
		}
		r.pending[e.Cookie] = pending{conn: c, deadline: now.Add(headWait)}
	case KindHead:
		p, ok := r.pending[e.Cookie]
		if !ok {
			return // its connection already counted unnamed
		}
		delete(r.pending, e.Cookie)
		p.conn.App, p.conn.Service = e.App, e.Service
		r.window.Add(p.conn)
	}
}

// conn is e as a Conn, its process identified.
func (r *runner) conn(e Event, now time.Time) Conn {
	id, ok := r.processes[e.TGID]
	if !ok || id.comm != e.Comm {
		if len(r.processes) >= maxProcesses {
			clear(r.processes)
		}
		id = ident{comm: e.Comm, Process: r.cfg.Identify(e.TGID, e.CgroupID)}
		r.processes[e.TGID] = id
	}
	c := Conn{Direction: Out, Exe: id.Exe, Comm: e.Comm, Unit: id.Unit, Remote: e.Remote, At: now}
	if e.Kind == KindIn {
		c.Direction, c.LocalPort = In, e.LocalPort
	}
	return c
}

// expire counts, unnamed, every made connection whose first bytes did not come by its
// deadline (all of them for a zero now).
func (r *runner) expire(now time.Time) {
	for cookie, p := range r.pending {
		if now.IsZero() || !now.Before(p.deadline) {
			delete(r.pending, cookie)
			r.window.Add(p.conn)
		}
	}
}

// flush sends the window (unread when the connections cannot be observed) and starts the
// next.
func (r *runner) flush() {
	if r.cfg.Drops != nil {
		d := r.cfg.Drops()
		if d >= r.lastDrops {
			r.window.Drop(d - r.lastDrops)
		}
		r.lastDrops = d
	}
	now := r.cfg.now()
	if r.unreadable != "" {
		start := r.window.start
		*r.window = *NewWindow(now)
		r.sink.HostFlows(unreadWindow(start, now, r.unreadable))
	} else {
		for _, f := range r.window.Flush(now) {
			r.sink.HostFlows(f)
		}
	}
	clear(r.processes)
}

// maxReasonBytes is Signal's cap on HostFlows.unreadable.
const maxReasonBytes = 256

func unreadWindow(start, end time.Time, why string) *eventsv1.HostFlows {
	f := NewWindow(start).Flush(end)[0]
	f.Read, f.Unreadable = false, clip(clean(why), maxReasonBytes)
	return f
}
