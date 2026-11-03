package verifier

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
)

// PublishFunc sends one backend event.
type PublishFunc func(ctx context.Context, subject, id string, msg proto.Message) error

// Limits bound the checker's traffic.
type Limits struct {
	// GlobalPerSecond probes per second in total (burst the same).
	GlobalPerSecond float64
	// PerHostPerMinute probes per minute per host (burst the same).
	PerHostPerMinute float64
	// Concurrency is the number of listeners probed at once.
	Concurrency int
	// Reprobe: a listener seen again (in a snapshot) is re-probed only after this long.
	Reprobe time.Duration
	// MinGap: an exposure change re-probes a listener at most this often.
	MinGap time.Duration
}

// Verifier schedules probes for listeners from exposure events and snapshots.
type Verifier struct {
	Scope   Scope
	Prober  Probe
	Publish PublishFunc
	RunID   string
	Checker string
	Limits  Limits
	Now     func() time.Time

	global  *rate.Limiter
	sem     chan struct{}
	mu      sync.Mutex
	perHost map[string]*rate.Limiter
	last    map[string]time.Time // host/key -> last probe start
	busy    map[string]bool
	wg      sync.WaitGroup
}

// Probe runs one probe (Prober.Probe; a stub in tests).
type Probe func(ctx context.Context, t Target) Result

// New returns a verifier with limits defaulted (5/s global, 30/min per host, 16 at once,
// reprobe 24 h, min gap 30 s).
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
	if l.Reprobe <= 0 {
		l.Reprobe = 24 * time.Hour
	}
	if l.MinGap <= 0 {
		l.MinGap = 30 * time.Second
	}
	return &Verifier{Scope: scope, Prober: probe, Publish: publish, RunID: runID, Checker: checker, Limits: l,
		global:  rate.NewLimiter(rate.Limit(l.GlobalPerSecond), max(1, int(l.GlobalPerSecond))),
		sem:     make(chan struct{}, l.Concurrency),
		perHost: map[string]*rate.Limiter{}, last: map[string]time.Time{}, busy: map[string]bool{}}
}

// Exposure schedules a probe for an exposure.changed event (agent or cloud).
func (v *Verifier) Exposure(ctx context.Context, host string, ev *asmv1.ExposureEvent) {
	v.schedule(ctx, host, ev.GetListener(), int(ev.GetExposure().GetLevel()), ev.GetExposure().GetEvidence(), ev.GetHost(), v.Limits.MinGap)
}

// Snapshot schedules probes for a snapshot's listeners not probed within Reprobe.
func (v *Verifier) Snapshot(ctx context.Context, host string, s *asmv1.Snapshot) {
	for _, l := range s.GetListeners() {
		v.schedule(ctx, host, l.GetListener(), int(l.GetExposure().GetLevel()), l.GetExposure().GetEvidence(), s.GetHost(), v.Limits.Reprobe)
	}
}

// Wait waits for the probes in flight (tests, shutdown).
func (v *Verifier) Wait() { v.wg.Wait() }

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) schedule(ctx context.Context, host string, l *asmv1.Listener, lvl int, evidence []string, h *asmv1.HostInfo, gap time.Duration) {
	targets, why := v.Scope.Targets(host, l, lvl, evidence, h)
	key := host + "/" + l.GetKey()
	if len(targets) == 0 {
		slog.Debug("not probing", "host", host, "listener", l.GetKey(), "why", why)
		return
	}
	v.mu.Lock()
	if v.busy[key] || (!v.last[key].IsZero() && v.now().Sub(v.last[key]) < gap) {
		v.mu.Unlock()
		return
	}
	v.busy[key], v.last[key] = true, v.now()
	lim, ok := v.perHost[host]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(v.Limits.PerHostPerMinute/60), max(1, int(v.Limits.PerHostPerMinute)))
		v.perHost[host] = lim
	}
	v.mu.Unlock()
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		defer func() {
			v.mu.Lock()
			delete(v.busy, key)
			v.mu.Unlock()
		}()
		select {
		case v.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-v.sem }()
		v.probeListener(ctx, host, l, targets, lim)
	}()
}

// probeListener probes every target of one listener and publishes one result: the first
// confirmed target, else a no_response one, else the first unreachable one.
func (v *Verifier) probeListener(ctx context.Context, host string, l *asmv1.Listener, targets []Target, lim *rate.Limiter) {
	var results []Result
	for _, t := range targets {
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
		EventId: id, HostId: host, RunId: v.RunID, ObservedAt: timestamppb.New(v.now()), Listener: l,
		Result: best.Result, Target: best.Target.String(), Probe: best.Probe, Banner: best.Banner, Detail: detail,
		RttMs: uint32(best.RTT.Milliseconds()), Checker: v.Checker, Origin: "verifier",
	}
	if best.Result == ResultConfirmed {
		evd := "probe: " + best.Probe + " " + best.Target.String() + " connected"
		if best.Banner != "" {
			evd += " (banner " + best.Banner + ")"
		}
		ev.Exposure = &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_CONFIRMED, Evidence: []string{evd}}
	}
	slog.Info("probed", "host", host, "listener", l.GetKey(), "target", ev.GetTarget(), "result", ev.GetResult(),
		"probe", ev.GetProbe(), "detail", ev.GetDetail())
	if err := v.Publish(ctx, bus.Subject(host, bus.KindExposureConfirmed), id, ev); err != nil {
		slog.Warn("publish probe result failed", "host", host, "listener", l.GetKey(), "err", err)
		v.mu.Lock()
		delete(v.last, host+"/"+l.GetKey()) // let the next event retry it
		v.mu.Unlock()
	}
}

// Forget drops a closed listener's probe history.
func (v *Verifier) Forget(host, key string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.last, host+"/"+key)
}
