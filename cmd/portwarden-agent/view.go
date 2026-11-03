package main

import (
	"github.com/thapr0digy/portwarden/internal/agent"
	"github.com/thapr0digy/portwarden/internal/netif"
)

// viewInfo is what the agent publishes about an exposure view (exposure.View).
type viewInfo interface {
	FirewallDigest() string
	Conditions() []string
	Interfaces() ([]netif.Interface, error)
}

// firewallSink takes the firewall fingerprint (publish.Publisher).
type firewallSink interface{ SetFirewall(digest string) }

// hostSink takes the host block's inputs (publicip.Collector, which publishes host.changed).
type hostSink interface {
	SetInterfaces([]netif.Interface)
	SetConditions([]string)
}

// onJudge returns the agent loop's OnJudge hook: as a new view replaces the judge, its
// firewall fingerprint is set first, so the host.changed its conditions or interfaces
// cause, and the exposure events it causes, all carry the new fingerprint.
func onJudge(fw firewallSink, host hostSink) func(agent.Judge) {
	return func(j agent.Judge) {
		v, ok := j.(viewInfo)
		if !ok {
			return
		}
		fw.SetFirewall(v.FirewallDigest())
		if ifs, err := v.Interfaces(); err == nil {
			host.SetInterfaces(ifs)
		}
		host.SetConditions(v.Conditions())
	}
}
