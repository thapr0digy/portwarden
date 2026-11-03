package verifier

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
)

// PublishFunc sends one backend event.
type PublishFunc func(ctx context.Context, subject, id string, msg proto.Message) error

// Limits bound the checker's traffic and memory.
type Limits struct {
	// GlobalPerSecond probes per second in total (burst the same).
	GlobalPerSecond float64
	// PerHostPerMinute probes per minute per host (burst the same).
	PerHostPerMinute float64
	// Concurrency is the number of workers (listeners probed at once).
	Concurrency int
	// Queue is how many listeners may wait for a worker; more are dropped and counted.
	Queue int
	// MinGap: one listener is probed at most this often.
	MinGap time.Duration
}

// Verifier runs probe requests on a fixed worker pool.
type Verifier struct {
	Scope   Scope
	Prober  Probe
	Publish PublishFunc
	RunID   string
	Checker string
	Limits  Limits
	Now     func() time.Time

	// Dropped counts requests refused because the queue was full.
	Dropped atomic.Uint64

	global    *rate.Limiter
	queue     chan job
	mu        sync.Mutex
	perHost   map[string]*rate.Limiter
	last      map[string]time.Time // host/key -> last accepted request
	busy      map[string]bool
	lastPrune time.Time
	pending   sync.WaitGroup
}

type job struct {
	host    string
	l       *asmv1.Listener
	targets []Target
}

// Probe runs one probe (Prober.Probe; a stub in tests).
type Probe func(ctx context.Context, t Target) Result

// New returns a verifier with limits defaulted (5/s global, 30/min per host, 16 workers,
// queue 1000, min gap 30 s). Start runs the workers.
func New(scope Scope, probe Probe, publish PublishFunc, runID, checker string, l Limits) *Verifier {
	if l.GlobalPerSecond <= 0 {
		l.GlobalPerSecond = 5
	}
	if l.PerHostPerMinute <= 0 {
		l.PerHostPerMinute = 30
	}
	if l.Concurrency <= 0 {
		l.Concurrency = 16
	}
	if l.Queue <= 0 {
		l.Queue = 1000
	}
	if l.MinGap <= 0 {
		l.MinGap = 30 * time.Second
	}
	return &Verifier{Scope: scope, Prober: probe, Publish: publish, RunID: runID, Checker: checker, Limits: l,
		global:  rate.NewLimiter(rate.Limit(l.GlobalPerSecond), max(1, int(l.GlobalPerSecond))),
		queue:   make(chan job, l.Queue),
		perHost: map[string]*rate.Limiter{}, last: map[string]time.Time{}, busy: map[string]bool{}}
}

// Start runs Concurrency workers until ctx ends; the returned func waits for them.
func (v *Verifier) Start(ctx context.Context) (wait func()) {
	var wg sync.WaitGroup
	for range v.Limits.Concurrency {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-v.queue:
					v.probeListener(ctx, j)
					v.done(j)
				}
			}
		})
	}
	return wg.Wait
}

// Wait waits until every accepted request has been handled (tests).
func (v *Verifier) Wait() { v.pending.Wait() }

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Request queues a probe request. It never blocks: a listener probed within MinGap or
// still queued is skipped, and a full queue drops the request (counted).
func (v *Verifier) Request(host string, r *asmv1.ProbeRequest) {
	targets, why := v.Scope.Targets(host, r)
	l := r.GetListener()
	if len(targets) == 0 {
		slog.Info("not probing", "host", host, "listener", l.GetKey(), "why", why)
		return
	}
	key := host + "/" + l.GetKey()
	now := v.now()
	v.mu.Lock()
	v.pruneLocked(now)
	if v.busy[key] || (!v.last[key].IsZero() && now.Sub(v.last[key]) < v.Limits.MinGap) {
		v.mu.Unlock()
		return
	}
	v.busy[key], v.last[key] = true, now
	v.pending.Add(1)
	v.mu.Unlock()
	select {
	case v.queue <- job{host: host, l: l, targets: targets}:
	default:
		n := v.Dropped.Add(1)
		if n == 1 || n%100 == 0 {
			slog.Warn("probe queue full; request dropped", "host", host, "listener", l.GetKey(), "dropped_total", n)
		}
		v.mu.Lock()
		delete(v.last, key) // let the next request for it through
		v.mu.Unlock()
		v.done(job{host: host, l: l})
	}
}

func (v *Verifier) done(j job) {
	v.mu.Lock()
	delete(v.busy, j.host+"/"+j.l.GetKey())
	v.mu.Unlock()
	v.pending.Done()
}

// pruneLocked forgets min-gap entries and per-host limiters not used for an hour, so
// memory stays bounded by recent activity.
func (v *Verifier) pruneLocked(now time.Time) {
	if now.Sub(v.lastPrune) < time.Minute {
		return
	}
	v.lastPrune = now
	horizon := max(time.Hour, v.Limits.MinGap)
	hosts := map[string]bool{}
	for k, at := range v.last {
		if now.Sub(at) > horizon && !v.busy[k] {
			delete(v.last, k)
			continue
		}
		hosts[k[:strings.IndexByte(k, '/')]] = true
	}
	for h := range v.perHost {
		if !hosts[h] {
			delete(v.perHost, h)
		}
	}
}

func (v *Verifier) hostLimiter(host string) *rate.Limiter {
	v.mu.Lock()
	defer v.mu.Unlock()
	lim, ok := v.perHost[host]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(v.Limits.PerHostPerMinute/60), max(1, int(v.Limits.PerHostPerMinute)))
		v.perHost[host] = lim
	}
	return lim
}

// probeListener probes every target of one listener and publishes one result: the first
// confirmed target, else a no_response one, else the first unreachable one.
func (v *Verifier) probeListener(ctx context.Context, j job) {
	lim := v.hostLimiter(j.host)
	var results []Result
	for _, t := range j.targets {
		if err := v.global.Wait(ctx); err != nil {
			return
		}
		if err := lim.Wait(ctx); err != nil {
			return
		}
		results = append(results, v.Prober(ctx, t))
	}
	best := results[0]
	rank := map[string]int{ResultConfirmed: 0, ResultNoResponse: 1, ResultUnreachable: 2}
	for _, r := range results[1:] {
		if rank[r.Result] < rank[best.Result] {
			best = r
		}
	}
	detail := best.Detail
	if len(results) > 1 {
		var others []string
		for _, r := range results {
			if r.Target != best.Target {
				others = append(others, r.Target.String()+" "+r.Result)
			}
		}
		if detail != "" {
			detail += "; "
		}
		detail += "also " + strings.Join(others, ", ")
	}
	id := bus.NewEventID()
	ev := &asmv1.ExposureConfirmation{
		EventId: id, HostId: j.host, RunId: v.RunID, ObservedAt: timestamppb.New(v.now()), Listener: j.l,
		Result: best.Result, Target: best.Target.String(), Probe: best.Probe, Banner: best.Banner, Detail: detail,
		RttMs: uint32(best.RTT.Milliseconds()), Checker: v.Checker, Origin: bus.OriginVerifier,
	}
	if best.Result == ResultConfirmed {
		evd := "probe: " + best.Probe + " " + best.Target.String() + " connected"
		if best.Banner != "" {
			evd += " (banner " + best.Banner + ")"
		}
		ev.Exposure = &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_CONFIRMED, Evidence: []string{evd}}
	}
	slog.Info("probed", "host", j.host, "listener", j.l.GetKey(), "target", ev.GetTarget(), "result", ev.GetResult(),
		"probe", ev.GetProbe(), "detail", ev.GetDetail())
	if err := v.Publish(ctx, bus.VerifierSubject(j.host), id, ev); err != nil {
		slog.Warn("publish probe result failed", "host", j.host, "listener", j.l.GetKey(), "err", err)
		v.mu.Lock()
		delete(v.last, j.host+"/"+j.l.GetKey()) // let the next request retry it
		v.mu.Unlock()
	}
}
