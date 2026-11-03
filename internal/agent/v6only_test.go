package agent

import (
	"net/netip"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

// v6Judge rates a [::] listener open when it takes IPv4 (not v6-only), bound otherwise:
// a host whose only external address is IPv4.
type v6Judge struct{}

func (v6Judge) Trigger() string { return "start" }

func (v6Judge) Judge(ls []state.Listener) map[model.ListenerKey]model.Exposure {
	out := make(map[model.ListenerKey]model.Exposure, len(ls))
	for _, l := range ls {
		if l.V6Only == model.V6OnlyOn {
			out[l.Key] = model.Exposure{Level: model.ExposureBound, Evidence: []string{"bind:any (IPv6 only)"}}
		} else {
			out[l.Key] = model.Exposure{Level: model.ExposureHostFirewallOpen, Evidence: []string{"bind:any"}}
		}
	}
	return out
}

var v6Key = model.NewKey(4026531840, "tcp", netip.IPv6Unspecified(), 9443)

func v6Obs(kind model.Kind, cookie uint64, pid uint32, v model.V6Only, src model.Source) model.Observation {
	o := model.Observation{Kind: kind, Cookie: cookie, Key: v6Key, At: time.Now(), Source: src, V6Only: v}
	if pid != 0 {
		o.Proc = model.Process{PID: pid, Comm: "svc"}
	}
	return o
}

func wantExposure(t *testing.T, ex []state.ExposureChange, from, to model.ExposureLevel) {
	t.Helper()
	if len(ex) != 1 || ex[0].Key != v6Key || ex[0].Trigger != "listener" ||
		ex[0].Previous.Level != from || ex[0].Exposure.Level != to {
		t.Fatalf("exposure = %+v, want %v -> %v", ex, from, to)
	}
}

// The same process adds a dual-stack SO_REUSEPORT socket to a v6-only [::] key: the
// holder set is unchanged (no Change), but the key now takes IPv4. Closing it again
// lowers the key once every socket left is v6-only.
func TestDualStackReuseportSocketRejudges(t *testing.T) {
	h := startWith(t, []model.Observation{v6Obs(model.Opened, 1, 10, model.V6OnlyOn, model.SourceBaseline)}, nil, Options{Judge: v6Judge{}})
	close(h.release)
	if snap := h.snapshot(); len(snap) != 1 || snap[0].Exposure.Level != model.ExposureBound {
		t.Fatalf("baseline = %+v", snap)
	}
	h.send(v6Obs(model.Opened, 2, 10, model.V6OnlyOff, model.SourceEBPF))
	wantExposure(t, h.exposures(), model.ExposureBound, model.ExposureHostFirewallOpen)

	// Another v6-only worker: the dual-stack socket still takes IPv4, nothing moves.
	h.send(v6Obs(model.Opened, 3, 10, model.V6OnlyOn, model.SourceEBPF))
	h.noExposures(50 * time.Millisecond)

	h.send(v6Obs(model.Closed, 2, 0, model.V6OnlyUnknown, model.SourceEBPF))
	wantExposure(t, h.exposures(), model.ExposureHostFirewallOpen, model.ExposureBound)
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("no listener-level change expected: %+v", rest)
	}
}

// The socket closes and reopens dual-stack inside the close grace, by the same process:
// a silent restart for the table, a new IPv4 exposure for the judge. And back.
func TestReopenWithOtherV6OnlyInsideGraceRejudges(t *testing.T) {
	h := startWith(t, []model.Observation{v6Obs(model.Opened, 1, 10, model.V6OnlyOn, model.SourceBaseline)}, nil,
		Options{Judge: v6Judge{}, CloseGrace: time.Hour})
	close(h.release)
	h.snapshot()
	h.send(v6Obs(model.Closed, 1, 0, model.V6OnlyUnknown, model.SourceEBPF))
	h.send(v6Obs(model.Opened, 2, 10, model.V6OnlyOff, model.SourceEBPF))
	wantExposure(t, h.exposures(), model.ExposureBound, model.ExposureHostFirewallOpen)

	h.send(v6Obs(model.Closed, 2, 0, model.V6OnlyUnknown, model.SourceEBPF))
	h.send(v6Obs(model.Opened, 3, 10, model.V6OnlyOn, model.SourceEBPF))
	wantExposure(t, h.exposures(), model.ExposureHostFirewallOpen, model.ExposureBound)

	// The same flag again: nothing.
	h.send(v6Obs(model.Closed, 3, 0, model.V6OnlyUnknown, model.SourceEBPF))
	h.send(v6Obs(model.Opened, 4, 10, model.V6OnlyOn, model.SourceEBPF))
	h.noExposures(50 * time.Millisecond)
	if rest := h.stop(); len(rest) != 0 {
		t.Fatalf("no listener-level change expected: %+v", rest)
	}
}
