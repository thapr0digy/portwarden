package main

import "github.com/thapr0digy/portwarden/internal/model"

// processResolver fills process details from /proc (procinfo.Resolver).
type processResolver interface {
	Enrich(model.Process) model.Process
}

// socketUnitMatcher finds the systemd socket unit that owns a listener (sdsocket.Matcher).
type socketUnitMatcher interface {
	Match(model.ListenerKey) (socketUnit, service string, ok bool)
}

// newEnricher returns the agent's Enrich option. It resolves every holder's process
// details; a host-netns listener held by PID 1 (systemd, for socket activation) also
// gets the owning socket unit as SocketUnit and its service as Unit. An ownerless
// observation (kernel socket) is left empty.
func newEnricher(r processResolver, m socketUnitMatcher, hostNetNS uint32) func(model.Observation) model.Observation {
	return func(o model.Observation) model.Observation {
		if o.Proc.IsZero() {
			return o
		}
		o.Proc = r.Enrich(o.Proc)
		if o.Key.NetNS == hostNetNS && o.Proc.PID == 1 {
			if socketUnit, service, ok := m.Match(o.Key); ok {
				o.Proc.SocketUnit, o.Proc.Unit = socketUnit, service
			}
		}
		return o
	}
}
