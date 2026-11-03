package agent

import (
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

// fakeJudge rates a listener by its port: levels[port], default bound.
type fakeJudge struct {
	trigger string
	mu      sync.Mutex
	levels  map[uint16]model.ExposureLevel
	calls   int
}

func newJudge(trigger string, levels map[uint16]model.ExposureLevel) *fakeJudge {
	return &fakeJudge{trigger: trigger, levels: levels}
}

func (j *fakeJudge) Trigger() string { return j.trigger }

func (j *fakeJudge) Judge(ls []state.Listener) map[model.ListenerKey]model.Exposure {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls++
	out := make(map[model.ListenerKey]model.Exposure, len(ls))
	for _, l := range ls {
		lvl, ok := j.levels[l.Key.Port]
		if !ok {
			lvl = model.ExposureBound
		}
		out[l.Key] = model.Exposure{Level: lvl, Evidence: []string{"port:" + strconv.Itoa(int(l.Key.Port)) + " " + j.trigger}}
	}
	return out
}

func (h *harness) exposures() []state.ExposureChange {
	h.t.Helper()
	select {
	case c := <-h.rec.exposures:
		return c
	case <-time.After(5 * time.Second):
		h.t.Fatal("no exposure changes published")
		return nil
	}
}

func (h *harness) noExposures(d time.Duration) {
	h.t.Helper()
	select {
	case c := <-h.rec.exposures:
		h.t.Fatalf("unexpected exposure changes: %+v", c)
	case <-time.After(d):
	}
}

func TestBaselineSnapshotCarriesExposureWithoutEvents(t *testing.T) {
	j := newJudge("start", map[uint16]model.ExposureLevel{22: model.ExposureHostFirewallOpen})
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 22, 10, model.SourceBaseline), obs(model.Opened, 2, 80, 11, model.SourceBaseline)}, nil, Options{Judge: j})
	close(h.release)
	snap := h.snapshot()
	if len(snap) != 2 || snap[0].Exposure.Level != model.ExposureHostFirewallOpen || snap[1].Exposure.Level != model.ExposureBound {
		t.Fatalf("snapshot = %+v", snap)
	}
	h.noExposures(50 * time.Millisecond)
	h.stop()
}

func TestOpenedThenExposureChanged(t *testing.T) {
	j := newJudge("start", map[uint16]model.ExposureLevel{8080: model.ExposureHostFirewallOpen})
	h := startWith(t, nil, nil, Options{Judge: j})
	close(h.release)
	h.snapshot()

	h.send(obs(model.Opened, 5, 8080, 42, model.SourceEBPF))
	ch := h.change()
	if len(ch) != 1 || ch[0].Kind != model.Opened || ch[0].Exposure.Level != model.ExposureHostFirewallOpen {
		t.Fatalf("opened = %+v", ch)
	}
	ex := h.exposures()
	if len(ex) != 1 || ex[0].Key != key(8080) || ex[0].Trigger != "opened" || ex[0].Previous.Level != model.ExposureUnknown ||
		ex[0].Exposure.Level != model.ExposureHostFirewallOpen || !ex[0].At.Equal(t0) || len(ex[0].Procs) != 1 {
		t.Fatalf("exposure = %+v", ex)
	}
	// The Opened is handed to the sink before its exposure change.
	calls := h.rec.calls()
	if i := slices.Index(calls, "changes"); i < 0 || calls[i+1] != "exposures" {
		t.Fatalf("call order %v", calls)
	}

	h.send(obs(model.Closed, 5, 8080, 0, model.SourceEBPF))
	cl := h.change()
	if len(cl) != 1 || cl[0].Kind != model.Closed || cl[0].Exposure.Level != model.ExposureHostFirewallOpen {
		t.Fatalf("closed = %+v", cl)
	}
	h.noExposures(50 * time.Millisecond)
	h.stop()
}

func TestNewJudgeRejudgesOnlyChangedLevels(t *testing.T) {
	judges := make(chan Judge)
	j := newJudge("start", nil)
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 22, 10, model.SourceBaseline), obs(model.Opened, 2, 80, 11, model.SourceBaseline)}, nil,
		Options{Judge: j, Judges: judges})
	close(h.release)
	h.snapshot()

	judges <- newJudge("firewall", map[uint16]model.ExposureLevel{22: model.ExposureHostFirewallOpen})
	ex := h.exposures()
	if len(ex) != 1 || ex[0].Key != key(22) || ex[0].Trigger != "firewall" ||
		ex[0].Previous.Level != model.ExposureBound || ex[0].Exposure.Level != model.ExposureHostFirewallOpen {
		t.Fatalf("exposure = %+v", ex)
	}
	// Same levels, new evidence: no event; the next change carries the new evidence.
	judges <- newJudge("recheck", map[uint16]model.ExposureLevel{22: model.ExposureHostFirewallOpen})
	h.noExposures(50 * time.Millisecond)
	h.send(obs(model.Opened, 3, 80, 12, model.SourceEBPF)) // second socket on :80: owner change
	ch := h.change()
	if len(ch) != 1 || ch[0].Kind != model.OwnerChanged || ch[0].Exposure.Evidence[0] != "port:80 recheck" {
		t.Fatalf("owner change = %+v", ch)
	}
	h.noExposures(50 * time.Millisecond)
	h.stop()
}

func TestRestartInsideGraceKeepsLevelSilently(t *testing.T) {
	j := newJudge("start", nil)
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 9000, 10, model.SourceBaseline)}, nil, Options{Judge: j, CloseGrace: time.Hour})
	close(h.release)
	h.snapshot()
	// Observation times are the table's clock for the grace deadline.
	closeObs, reopen := obs(model.Closed, 1, 9000, 0, model.SourceEBPF), obs(model.Opened, 2, 9000, 20, model.SourceEBPF)
	closeObs.At, reopen.At = time.Now(), time.Now()
	h.send(closeObs)
	h.send(reopen)
	ch := h.change()
	if len(ch) != 1 || ch[0].Kind != model.OwnerChanged || ch[0].Exposure.Level != model.ExposureBound {
		t.Fatalf("restart = %+v", ch)
	}
	h.noExposures(50 * time.Millisecond)
	h.stop()
}

func TestOtherListenerChangeCanMoveALevel(t *testing.T) {
	// A judge where :80 is open only while :18080 (its port mapping's proxy) is open.
	j := &mappingJudge{}
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 80, 10, model.SourceBaseline)}, nil, Options{Judge: j})
	close(h.release)
	h.snapshot()
	h.send(obs(model.Opened, 2, 18080, 20, model.SourceEBPF))
	h.change()
	ex := h.exposures()
	byKey := map[model.ListenerKey]state.ExposureChange{}
	for _, e := range ex {
		byKey[e.Key] = e
	}
	if len(ex) != 2 || byKey[key(18080)].Trigger != "opened" || byKey[key(80)].Trigger != "listener" ||
		byKey[key(80)].Exposure.Level != model.ExposureHostFirewallOpen {
		t.Fatalf("exposures = %+v", ex)
	}
	h.stop()
}

type mappingJudge struct{}

func (mappingJudge) Trigger() string { return "start" }

func (mappingJudge) Judge(ls []state.Listener) map[model.ListenerKey]model.Exposure {
	proxied := slices.ContainsFunc(ls, func(l state.Listener) bool { return l.Key.Port == 18080 })
	out := map[model.ListenerKey]model.Exposure{}
	for _, l := range ls {
		lvl := model.ExposureBound
		if l.Key.Port == 80 && !proxied {
			lvl = model.ExposureLocal
		}
		if proxied {
			lvl = model.ExposureHostFirewallOpen
		}
		out[l.Key] = model.Exposure{Level: lvl}
	}
	return out
}

func TestReconcileSnapshotCarriesExposure(t *testing.T) {
	j := newJudge("start", map[uint16]model.ExposureLevel{443: model.ExposureLocal})
	h := startWith(t, []model.Observation{obs(model.Opened, 1, 443, 10, model.SourceBaseline)}, nil, Options{Judge: j, Recheck: 10 * time.Millisecond})
	close(h.release)
	h.snapshot()
	h.recheck()
	h.reply([]model.Observation{obs(model.Opened, 1, 443, 10, model.SourceReconcile)}, nil)
	snap := h.snapshot()
	if len(snap) != 1 || snap[0].Exposure.Level != model.ExposureLocal {
		t.Fatalf("recheck snapshot = %+v", snap)
	}
	h.stop()
}
