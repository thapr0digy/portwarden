package main

import (
	"net/netip"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
)

const testHostNS = 4026531840

type fakeResolver struct{ calls int }

func (f *fakeResolver) Enrich(p model.Process) model.Process {
	f.calls++
	if p.Exe == "" {
		p.Exe = "/resolved"
	}
	if p.Unit == "" {
		p.Unit = "from-cgroup.service"
	}
	return p
}

type fakeMatcher struct{ socketUnit, service string }

func (f fakeMatcher) Match(model.ListenerKey) (string, string, bool) {
	return f.socketUnit, f.service, f.socketUnit != ""
}

func obs(netns, pid uint32) model.Observation {
	return model.Observation{
		Kind: model.Opened,
		Key:  model.NewKey(netns, model.ProtoTCP, netip.MustParseAddr("0.0.0.0"), 22),
		Proc: model.Process{PID: pid, Comm: "x"},
	}
}

func TestEnricherSetsSocketUnitForHostPID1(t *testing.T) {
	r := &fakeResolver{}
	enrich := newEnricher(r, fakeMatcher{"ssh.socket", "ssh.service"}, testHostNS)

	got := enrich(obs(testHostNS, 1)).Proc
	if got.Exe != "/resolved" || got.SocketUnit != "ssh.socket" || got.Unit != "ssh.service" {
		t.Fatalf("pid 1 in host netns = %+v, want exe resolved, ssh.socket / ssh.service", got)
	}
}

func TestEnricherLeavesOtherHoldersToTheResolver(t *testing.T) {
	r := &fakeResolver{}
	enrich := newEnricher(r, fakeMatcher{"ssh.socket", "ssh.service"}, testHostNS)

	for name, o := range map[string]model.Observation{
		"other pid in host netns": obs(testHostNS, 42),
		"pid 1 in another netns":  obs(testHostNS+1, 1),
	} {
		got := enrich(o).Proc
		if got.SocketUnit != "" || got.Unit != "from-cgroup.service" || got.Exe != "/resolved" {
			t.Errorf("%s: %+v, want only resolver fields", name, got)
		}
	}
}

func TestEnricherNoSocketUnitMatchKeepsResolverUnit(t *testing.T) {
	enrich := newEnricher(&fakeResolver{}, fakeMatcher{}, testHostNS)
	got := enrich(obs(testHostNS, 1)).Proc
	if got.SocketUnit != "" || got.Unit != "from-cgroup.service" {
		t.Fatalf("unmatched pid 1 = %+v", got)
	}
}

func TestEnricherKeepsOwnerlessObservationEmpty(t *testing.T) {
	r := &fakeResolver{}
	enrich := newEnricher(r, fakeMatcher{"ssh.socket", "ssh.service"}, testHostNS)
	o := obs(testHostNS, 0)
	o.Proc = model.Process{}
	if got := enrich(o).Proc; !got.IsZero() || r.calls != 0 {
		t.Fatalf("ownerless = %+v (resolver calls %d), want untouched", got, r.calls)
	}
}
