// Package agent sequences startup so no listener is missed or reported twice.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

// EventSource delivers live observations from the kernel probes.
type EventSource interface {
	Events() <-chan model.Observation
}

// Snapshotter takes the baseline of currently listening sockets.
type Snapshotter func() ([]model.Observation, error)

// Sink receives what the agent publishes. Calls come from one goroutine, in order: a
// listener's Opened comes before its first ExposureChange.
type Sink interface {
	Changes([]state.Change)
	Snapshot([]state.Listener)
	ExposureChanges([]state.ExposureChange)
}

// Judge rates every listener's exposure under one reading of the host (its firewall
// and interfaces); see exposure.View. It is used from the agent loop only.
type Judge interface {
	Judge([]state.Listener) map[model.ListenerKey]model.Exposure
	// Trigger says why this judge was made (firewall, interfaces, recheck, …); it is
	// the trigger of the exposure changes a new judge causes.
	Trigger() string
}

// Options tunes the agent beyond M1. The zero value behaves as M1: no
// enrichment, no close grace, no recheck and no drop polling.
type Options struct {
	// Enrich fills in process context for every observation before the table
	// sees it; it must not block on the network. nil: identity.
	Enrich func(model.Observation) model.Observation
	// CloseGrace delays a listener's Closed so a quick restart reads as an
	// owner change. 0: close at once.
	CloseGrace time.Duration
	// Recheck is the interval between full dumps reconciled against the table.
	// 0 disables the periodic recheck.
	Recheck time.Duration
	// Drops reads the ring buffer's drop counter; a rise since the last poll
	// starts a recheck. nil: never polled.
	Drops func() uint64
	// DropsCheck is how often Drops is polled. 0: 10 s.
	DropsCheck time.Duration
	// Settle is how long live events keep being applied after a recheck dump
	// returns, before it is reconciled.
	Settle time.Duration
	// Judge rates exposure; nil leaves every listener's exposure empty and publishes
	// no ExposureChanges.
	Judge Judge
	// Judges delivers newer judges (the firewall or the interfaces changed); each one
	// re-rates every listener. Ignored without Judge.
	Judges <-chan Judge
}

const defaultDropsCheck = 10 * time.Second

// Run starts probe-first: it buffers events from src, takes the baseline, publishes
// it as one Snapshot (no Opened changes), replays the buffered events in arrival
// order, then forwards live changes until ctx is cancelled or src closes. Every
// observation passes through opts.Enrich once before the table sees it. With a
// close grace, pending closes are published when their deadline passes; with a
// recheck interval or a drops counter, it periodically reconciles a fresh dump
// from snap (see Options). A failed recheck is logged and never stops Run.
// It returns nil on cancellation or a closed source, and the baseline snapshot
// error otherwise.
func Run(ctx context.Context, src EventSource, snap Snapshotter, sink Sink, opts Options) error {
	enrich := opts.Enrich
	if enrich == nil {
		enrich = func(o model.Observation) model.Observation { return o }
	}
	var lastDrops uint64
	if opts.Drops != nil {
		lastDrops = opts.Drops()
	}

	buf := bufferEvents(ctx, src.Events())

	baseline, err := snap()
	if err != nil {
		buf.stop()
		return fmt.Errorf("baseline snapshot: %w", err)
	}
	buffered := buf.stop()

	table := state.New(opts.CloseGrace)
	for _, o := range baseline {
		table.Apply(enrich(o))
	}

	l := &loop{
		table: table, sink: sink, snap: snap, enrich: enrich, opts: opts,
		lastDrops: lastDrops, grace: stoppedTimer(), settle: stoppedTimer(),
		dumps: make(chan dumpResult, 1), judge: opts.Judge,
		levels: make(map[model.ListenerKey]model.Exposure),
	}
	// The baseline's exposures travel in its snapshot; it causes no ExposureChanges,
	// as it causes no Opened.
	if l.judge != nil {
		l.levels = l.judge.Judge(table.Snapshot())
	}
	l.snapshot()
	defer l.grace.Stop()
	defer l.settle.Stop()
	for _, o := range buffered {
		l.apply(enrich(o))
	}
	return l.run(ctx, src.Events())
}

// loop owns the table after the baseline. Only its goroutine touches it; a
// recheck dump runs in its own goroutine and hands back its result on dumps.
type loop struct {
	table  *state.Table
	sink   Sink
	snap   Snapshotter
	enrich func(model.Observation) model.Observation
	opts   Options

	// lastDrops is the drop count the last successful recheck covered;
	// dropsAtStart is the count when the running dump started.
	lastDrops, dropsAtStart uint64

	grace  *time.Timer
	graceC <-chan time.Time

	// A recheck is running while touched is non-nil: from the moment its dump
	// starts until it is reconciled, touched holds every live cookie applied.
	touched map[uint64]struct{}
	dumps   chan dumpResult
	dumped  []model.Observation
	settle  *time.Timer
	settleC <-chan time.Time

	// judge rates exposure (nil: off); levels holds each listener's last exposure,
	// kept through a pending close so a restart inside the grace is no change.
	judge  Judge
	levels map[model.ListenerKey]model.Exposure
}

type dumpResult struct {
	obs []model.Observation
	err error
}

func (l *loop) run(ctx context.Context, events <-chan model.Observation) error {
	var recheckC, dropsC <-chan time.Time
	var judges <-chan Judge
	if l.judge != nil {
		judges = l.opts.Judges
	}
	if l.opts.Recheck > 0 {
		t := time.NewTicker(l.opts.Recheck)
		defer t.Stop()
		recheckC = t.C
	}
	if l.opts.Drops != nil {
		every := l.opts.DropsCheck
		if every <= 0 {
			every = defaultDropsCheck
		}
		t := time.NewTicker(every)
		defer t.Stop()
		dropsC = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case o, ok := <-events:
			if !ok {
				return nil
			}
			if l.touched != nil {
				l.touched[o.Cookie] = struct{}{}
			}
			l.apply(l.enrich(o))
		case now := <-l.graceC:
			l.publish(l.table.Expire(now))
		case <-recheckC:
			l.startRecheck()
		case <-dropsC:
			l.checkDrops()
		case d := <-l.dumps:
			l.dumpReturned(d)
		case <-l.settleC:
			l.settleC = nil
			l.reconcile()
		case j, ok := <-judges:
			if !ok {
				judges = nil
				continue
			}
			l.judge = j
			l.rejudge(nil, j.Trigger())
		}
	}
}

func (l *loop) apply(o model.Observation) {
	l.publish(l.table.Apply(o))
}

// publish sends changes, with their listeners' exposure and any exposure change they
// cause, and re-arms the grace timer at the table's next deadline, since every table
// mutation can move it.
func (l *loop) publish(changes []state.Change) {
	if len(changes) > 0 && l.judge != nil {
		l.rejudge(changes, triggerListener)
	} else {
		publish(l.sink, changes)
	}
	deadline, ok := l.table.NextDeadline()
	if !ok {
		l.grace.Stop()
		l.graceC = nil
		return
	}
	l.grace.Reset(time.Until(deadline))
	l.graceC = l.grace.C
}

// checkDrops starts a recheck when the drop counter has risen past what the
// last successful recheck covered. A rise seen while a recheck runs is left for
// a later poll, so it is covered by a dump that starts after it, and a failed
// recheck is retried at the next poll.
func (l *loop) checkDrops() {
	if l.touched == nil && l.opts.Drops() != l.lastDrops {
		l.startRecheck()
	}
}

// startRecheck starts a dump unless one is already running.
func (l *loop) startRecheck() {
	if l.touched != nil {
		return
	}
	l.touched = make(map[uint64]struct{})
	if l.opts.Drops != nil {
		l.dropsAtStart = l.opts.Drops()
	}
	snap, dumps := l.snap, l.dumps
	go func() {
		obs, err := snap()
		dumps <- dumpResult{obs, err} // buffered: never blocks, even after Run returns
	}()
}

func (l *loop) dumpReturned(d dumpResult) {
	if d.err != nil {
		slog.Warn("recheck dump failed", "error", d.err.Error())
		l.touched = nil
		return
	}
	l.dumped = make([]model.Observation, 0, len(d.obs))
	for _, o := range d.obs {
		l.dumped = append(l.dumped, l.enrich(o))
	}
	if l.opts.Settle <= 0 {
		l.reconcile()
		return
	}
	l.settle.Reset(l.opts.Settle)
	l.settleC = l.settle.C
}

func (l *loop) reconcile() {
	changes := l.table.Reconcile(l.dumped, l.touched, time.Now())
	l.touched, l.dumped = nil, nil
	l.lastDrops = l.dropsAtStart
	l.publish(changes)
	l.snapshot()
}

// snapshot publishes the open listeners with their current exposure.
func (l *loop) snapshot() {
	listeners := l.table.Snapshot()
	for i := range listeners {
		listeners[i].Exposure = l.levels[listeners[i].Key]
	}
	l.sink.Snapshot(listeners)
}

const (
	triggerOpened   = "opened"
	triggerListener = "listener"
)

// rejudge rates every open listener, publishes changes (which may be nil) with their
// listeners' exposure, then one ExposureChange per listener that is newly opened or
// whose level moved. A listener's evidence is updated silently when only it changed.
func (l *loop) rejudge(changes []state.Change, trigger string) {
	listeners := l.table.Snapshot()
	judged := l.judge.Judge(listeners)
	now := time.Now()
	openedAt := make(map[model.ListenerKey]time.Time)
	for i, c := range changes {
		switch c.Kind {
		case model.Opened, model.OwnerChanged:
			changes[i].Exposure = judged[c.Key]
			if c.Kind == model.Opened {
				openedAt[c.Key] = c.At
			}
		case model.Closed:
			changes[i].Exposure = l.levels[c.Key]
			delete(l.levels, c.Key)
		}
	}
	publish(l.sink, changes)

	var out []state.ExposureChange
	for _, li := range listeners {
		e := judged[li.Key]
		old, had := l.levels[li.Key]
		l.levels[li.Key] = e
		if had && old.Level == e.Level {
			continue
		}
		ec := state.ExposureChange{Key: li.Key, Procs: li.Procs, Exposure: e, Previous: old, Trigger: trigger, At: now}
		if at, ok := openedAt[li.Key]; ok && !had {
			ec.Trigger, ec.At = triggerOpened, at
		}
		out = append(out, ec)
	}
	if len(out) > 0 {
		l.sink.ExposureChanges(out)
	}
}

func stoppedTimer() *time.Timer {
	t := time.NewTimer(time.Hour)
	t.Stop()
	return t
}

func publish(sink Sink, changes []state.Change) {
	if len(changes) > 0 {
		sink.Changes(changes)
	}
}

// eventBuffer collects events in a goroutine until stopped, so the source is
// drained while the baseline is being taken.
type eventBuffer struct {
	quit chan struct{}
	done chan struct{}
	once sync.Once
	got  []model.Observation
}

func bufferEvents(ctx context.Context, events <-chan model.Observation) *eventBuffer {
	b := &eventBuffer{quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(b.done)
		for {
			select {
			case <-b.quit:
				return
			case <-ctx.Done():
				return
			case o, ok := <-events:
				if !ok {
					return
				}
				b.got = append(b.got, o)
			}
		}
	}()
	return b
}

// stop ends the goroutine and returns everything it received, in arrival order.
func (b *eventBuffer) stop() []model.Observation {
	b.once.Do(func() { close(b.quit) })
	<-b.done
	return b.got
}
