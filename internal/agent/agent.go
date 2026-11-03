// Package agent sequences startup so no listener is missed or reported twice.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy"
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
	// Snapshot carries every open listener and every known proxy's route set.
	Snapshot([]state.Listener, []model.ProxyRoutes)
	ExposureChanges([]state.ExposureChange)
	// ProxyRoutes publishes route sets that changed (or were removed).
	ProxyRoutes([]model.ProxyRoutes)
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
	// Proxies delivers the proxy mapper's views; each one is joined to the listener
	// table and every proxy whose routes changed is published. nil: no proxy mapping.
	Proxies <-chan proxy.Update
	// ProxyListeners receives the open listeners after the baseline and after every
	// listener change (the mapper's input). It must not block. nil: not called.
	ProxyListeners func([]state.Listener)
	// ProxyMinInterval is the least time between two proxy.routes of one proxy; a
	// change inside it is published when it ends (removals go out at once). 0: none.
	ProxyMinInterval time.Duration
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
		levels:    make(map[model.ListenerKey]model.Exposure),
		published: make(map[string]model.ProxyRoutes),
		lastPub:   make(map[string]model.ProxyRoutes),
		lastPubAt: make(map[string]time.Time),
		pendingRt: make(map[string]string),
		handledAt: make(map[string]time.Time),
		routeT:    stoppedTimer(),
	}
	// The baseline's exposures travel in its snapshot; it causes no ExposureChanges,
	// as it causes no Opened.
	if l.judge != nil {
		l.levels = l.judge.Judge(table.Snapshot())
	}
	l.feedMapper(table.Snapshot())
	l.snapshot()
	defer l.grace.Stop()
	defer l.settle.Stop()
	defer l.routeT.Stop()
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

	// The proxy mapping: the mapper's latest view, the route sets last published per
	// proxy, the mapper time of each proxy's last handled change, and the routes ending
	// at each listener.
	proxyView proxy.Update
	// published holds each proxy's current joined route set (snapshots carry it);
	// lastPub/lastPubAt what was last sent on proxy.routes and when; pendingRt the
	// trigger of a change held back by ProxyMinInterval, sent when routeT fires.
	published map[string]model.ProxyRoutes
	lastPub   map[string]model.ProxyRoutes
	lastPubAt map[string]time.Time
	pendingRt map[string]string
	routeT    *time.Timer
	routeC    <-chan time.Time
	routeDue  time.Time
	handledAt map[string]time.Time
	behind    map[model.ListenerKey][]model.ProxyRef
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
	proxies := l.opts.Proxies
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
		case u, ok := <-proxies:
			if !ok {
				proxies = nil
				continue
			}
			l.proxyView = u
			l.publishRoutes(l.rejoin(l.table.Snapshot()))
		case now := <-l.routeC:
			l.routeC = nil
			l.publishRoutes(l.flushPending(now))
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
	var routes []model.ProxyRoutes
	if len(changes) > 0 {
		listeners := l.table.Snapshot()
		routes = l.annotateProxies(changes, listeners)
		l.feedMapper(listeners)
	}
	if len(changes) > 0 && l.judge != nil {
		l.rejudge(changes, triggerListener)
	} else {
		publish(l.sink, changes)
	}
	l.publishRoutes(routes)
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

// snapshot publishes the open listeners with their current exposure and proxy routes,
// and every proxy's route set.
func (l *loop) snapshot() {
	listeners := l.table.Snapshot()
	for i := range listeners {
		listeners[i].Exposure = l.levels[listeners[i].Key]
		listeners[i].BehindProxy = l.behind[listeners[i].Key]
	}
	l.sink.Snapshot(listeners, l.currentRoutes())
}

func (l *loop) currentRoutes() []model.ProxyRoutes {
	if len(l.published) == 0 {
		return nil
	}
	ids := make([]string, 0, len(l.published))
	for id := range l.published {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]model.ProxyRoutes, 0, len(ids))
	for _, id := range ids {
		out = append(out, l.published[id])
	}
	return out
}

func (l *loop) feedMapper(listeners []state.Listener) {
	if l.opts.ProxyListeners != nil {
		l.opts.ProxyListeners(listeners)
	}
}

// annotateProxies rejoins the proxy routes to the changed table and sets each change's
// BehindProxy (a closed listener keeps the routes it had). It returns the route sets to
// publish after the changes.
func (l *loop) annotateProxies(changes []state.Change, listeners []state.Listener) []model.ProxyRoutes {
	if l.opts.Proxies == nil {
		return nil
	}
	before := l.behind
	routes := l.rejoin(listeners)
	for i, c := range changes {
		if c.Kind == model.Closed {
			changes[i].BehindProxy = before[c.Key]
		} else {
			changes[i].BehindProxy = l.behind[c.Key]
		}
	}
	return routes
}

// rejoin joins every proxy of the mapper's view to the listeners, refreshes the
// behind_proxy index, and returns the route sets whose structure changed (with the
// mapper's trigger when the mapper changed the proxy since, "listener" otherwise) and
// the removals of proxies that are gone.
func (l *loop) rejoin(listeners []state.Listener) []model.ProxyRoutes {
	now := time.Now()
	var out []model.ProxyRoutes
	seen := make(map[string]bool, len(l.proxyView.States))
	all := make([]model.ProxyRoutes, 0, len(l.proxyView.States))
	for _, s := range l.proxyView.States {
		id := s.Instance.ID
		seen[id] = true
		joined := proxy.Cap(proxy.Join(s, listeners, l.proxyView.NetnsAddrs))
		trigger := model.ProxyTriggerListener
		if s.At.After(l.handledAt[id]) {
			trigger = s.Trigger
			l.handledAt[id] = s.At
		}
		joined.Trigger, joined.At = trigger, now
		l.published[id] = joined
		all = append(all, joined)
		prev, had := l.lastPub[id]
		if had && prev.SameStructure(joined) {
			delete(l.pendingRt, id)
			continue
		}
		if held, ok := l.pendingRt[id]; ok && trigger == model.ProxyTriggerListener {
			trigger = held // keep the more telling reason of a held-back change
		}
		if gap := l.opts.ProxyMinInterval; had && now.Sub(l.lastPubAt[id]) < gap {
			l.pendingRt[id] = trigger
			l.scheduleRoutes(l.lastPubAt[id].Add(gap))
			continue
		}
		joined.Trigger = trigger
		out = append(out, l.sent(id, joined, now))
	}
	for id, prev := range l.published {
		if seen[id] {
			continue
		}
		for _, m := range []map[string]model.ProxyRoutes{l.published, l.lastPub} {
			delete(m, id)
		}
		delete(l.lastPubAt, id)
		delete(l.pendingRt, id)
		delete(l.handledAt, id)
		out = append(out, model.ProxyRoutes{Proxy: prev.Proxy, Removed: true, Trigger: model.ProxyTriggerStopped, At: now})
	}
	l.behind = proxy.BehindProxy(all)
	slices.SortFunc(out, func(a, b model.ProxyRoutes) int { return strings.Compare(a.Proxy.ID, b.Proxy.ID) })
	return out
}

// sent records r as published for id and returns it.
func (l *loop) sent(id string, r model.ProxyRoutes, now time.Time) model.ProxyRoutes {
	l.published[id] = r
	l.lastPub[id], l.lastPubAt[id] = r, now
	delete(l.pendingRt, id)
	return r
}

func (l *loop) scheduleRoutes(at time.Time) {
	if l.routeC != nil && !at.Before(l.routeDue) {
		return
	}
	l.routeDue = at
	l.routeT.Reset(time.Until(at))
	l.routeC = l.routeT.C
}

// flushPending publishes the held-back changes whose interval has passed.
func (l *loop) flushPending(now time.Time) []model.ProxyRoutes {
	var out []model.ProxyRoutes
	for id, trigger := range l.pendingRt {
		due := l.lastPubAt[id].Add(l.opts.ProxyMinInterval)
		if now.Before(due) {
			l.scheduleRoutes(due)
			continue
		}
		cur, ok := l.published[id]
		if !ok || l.lastPub[id].SameStructure(cur) {
			delete(l.pendingRt, id)
			continue
		}
		cur.Trigger, cur.At = trigger, now
		out = append(out, l.sent(id, cur, now))
	}
	slices.SortFunc(out, func(a, b model.ProxyRoutes) int { return strings.Compare(a.Proxy.ID, b.Proxy.ID) })
	return out
}

func (l *loop) publishRoutes(routes []model.ProxyRoutes) {
	if len(routes) > 0 {
		l.sink.ProxyRoutes(routes)
	}
}

// keepThroughFailedRead keeps a listener's last known level when the new judgement was
// made without a full reading of the firewall or interfaces (e is Degraded): no level
// flaps, no exposure change is raised for a read failure, and the evidence names the
// failure. A listener with no earlier level takes the degraded judgement (bound).
func keepThroughFailedRead(old model.Exposure, had bool, e model.Exposure) model.Exposure {
	if !e.Degraded || !had || old.Level == model.ExposureUnknown {
		return e
	}
	kept := model.Exposure{Level: old.Level, Degraded: true}
	for _, ev := range old.Evidence {
		if !strings.HasPrefix(ev, "fw:unreadable") && ev != "fw:undetermined read incomplete" {
			kept.Evidence = append(kept.Evidence, ev)
		}
	}
	for _, ev := range e.Evidence {
		if strings.HasPrefix(ev, "fw:unreadable") {
			kept.Evidence = append(kept.Evidence, ev)
		}
	}
	return kept
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
	for k, e := range judged {
		old, had := l.levels[k]
		judged[k] = keepThroughFailedRead(old, had, e)
	}
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
