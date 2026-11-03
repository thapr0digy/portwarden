package model

import (
	"net/netip"
	"testing"
	"time"
)

func TestProxyRoutesSameStructureIgnoresCounters(t *testing.T) {
	k := NewKey(1, ProtoTCP, netip.MustParseAddr("127.0.0.1"), 8000)
	a := ProxyRoutes{
		Proxy:   ProxyInstance{ID: "nginx/1//etc/nginx/nginx.conf", Kind: "nginx", Procs: []Process{{PID: 10, Comm: "nginx"}}},
		Routes:  []ProxyRoute{{Path: "/", Backends: []ProxyBackend{{Address: "127.0.0.1:8000", Listener: &k, Config: true, Connections: 1}}}},
		Trigger: ProxyTriggerStarted,
	}
	b := a.Clone()
	b.Routes[0].Backends[0].Connections = 99
	b.Routes[0].Backends[0].LastSeen = time.Now()
	b.Trigger = ProxyTriggerTraffic
	b.Proxy.Procs[0].Comm = "renamed" // not part of a process's identity
	if !a.SameStructure(b) {
		t.Fatal("counters, times, trigger and comm must not count as a change")
	}
	c := a.Clone()
	c.Routes[0].Backends[0].Seen = true
	if a.SameStructure(c) {
		t.Fatal("a backend becoming seen is a change")
	}
	d := a.Clone()
	other := NewKey(1, ProtoTCP, netip.MustParseAddr("0.0.0.0"), 8000)
	d.Routes[0].Backends[0].Listener = &other
	if a.SameStructure(d) {
		t.Fatal("a different backend listener is a change")
	}
	d.Routes[0].Backends[0].Listener = nil
	if a.SameStructure(d) {
		t.Fatal("losing the backend listener is a change")
	}
	if a.Routes[0].Backends[0].Listener != &k {
		t.Fatal("Clone must not alias the original")
	}
}
