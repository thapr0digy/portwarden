package main

import (
	"slices"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/state"
)

type fakeView struct{}

func (fakeView) Judge([]state.Listener) map[model.ListenerKey]model.Exposure { return nil }
func (fakeView) Trigger() string                                             { return "firewall" }
func (fakeView) FirewallDigest() string                                      { return "d1" }
func (fakeView) Conditions() []string                                        { return []string{"fw:unreadable x"} }
func (fakeView) Interfaces() ([]netif.Interface, error) {
	return []netif.Interface{{Name: "eth0"}}, nil
}

type callLog struct{ calls []string }

func (c *callLog) SetFirewall(d string) { c.calls = append(c.calls, "firewall:"+d) }
func (c *callLog) SetInterfaces(ifs []netif.Interface) {
	c.calls = append(c.calls, "interfaces:"+ifs[0].Name)
}
func (c *callLog) SetConditions(cs []string) { c.calls = append(c.calls, "conditions:"+cs[0]) }

// The fingerprint goes first: a host.changed raised by the conditions or interfaces of
// the same view must already carry it.
func TestOnJudgeSetsTheFingerprintFirst(t *testing.T) {
	var log callLog
	onJudge(&log, &log)(fakeView{})
	want := []string{"firewall:d1", "interfaces:eth0", "conditions:fw:unreadable x"}
	if !slices.Equal(log.calls, want) {
		t.Fatalf("calls %v, want %v", log.calls, want)
	}
}
