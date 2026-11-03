package model

import (
	"net/netip"
	"slices"
	"time"
)

// Proxy route kinds.
const (
	RouteProxy     = "proxy"
	RouteFastCGI   = "fastcgi"
	RouteUWSGI     = "uwsgi"
	RouteSCGI      = "scgi"
	RouteGRPC      = "grpc"
	RouteMemcached = "memcached"
	RouteStatic    = "static"
	RouteReturn    = "return"
)

// Proxy routes triggers: why a proxy's route set was published.
const (
	ProxyTriggerStarted  = "started"
	ProxyTriggerConfig   = "config"
	ProxyTriggerListener = "listener"
	ProxyTriggerTraffic  = "traffic"
	ProxyTriggerRecheck  = "recheck"
	ProxyTriggerStopped  = "stopped"
)

// ProxyInstance is one reverse proxy: its process tree, its listeners and its config.
type ProxyInstance struct {
	// ID is stable across reloads and restarts: <kind>/<netns>/<config path or exe>.
	ID   string
	Kind string
	// NetNS is the network namespace of the proxy's listeners.
	NetNS uint32
	// Procs lists the master first, then the other holders of its listeners.
	Procs      []Process
	Listeners  []ListenerKey
	ConfigPath string
	Files      []string
	Notes      []string
}

// Master is the root of the proxy's process tree (zero when unknown).
func (p ProxyInstance) Master() Process {
	if len(p.Procs) == 0 {
		return Process{}
	}
	return p.Procs[0]
}

// ProxyBackend is one place a route sends traffic to, joined to the listener it ends at.
type ProxyBackend struct {
	// Address is as written in the config, or the observed destination of an inferred
	// backend.
	Address string
	// Addr is the resolved destination; invalid when unresolved or a Unix socket.
	Addr netip.AddrPort
	Unix string
	// Listener is the listener the backend ends at (nil when none matches) and Procs
	// its holders.
	Listener *ListenerKey
	Procs    []Process
	// Config: named in the configuration. Seen: the proxy connected to it.
	Config, Seen bool
	Connections  uint64
	LastSeen     time.Time
	Note         string
}

// ProxyRoute is one routing rule from a frontend (listen, names, path) to backends.
type ProxyRoute struct {
	Listen      []string
	Frontends   []ListenerKey
	ServerNames []string
	Path        string
	Kind        string
	Target      string
	Upstream    string
	Root        string
	Source      string
	// Inferred: the route comes from observed connections only.
	Inferred bool
	Notes    []string
	Backends []ProxyBackend
}

// ProxyRoutes is a proxy's full route set, as published on proxy.routes.
type ProxyRoutes struct {
	Proxy   ProxyInstance
	Routes  []ProxyRoute
	Removed bool
	Trigger string
	At      time.Time
}

// ProxyRef names a proxy route that ends at a listener.
type ProxyRef struct {
	ProxyID     string
	Kind        string
	Proxy       Process
	Frontends   []ListenerKey
	ServerNames []string
	Path        string
	Config      bool
	Seen        bool
}

// SameStructure reports whether two route sets publish the same thing, ignoring the
// connection counters, last-seen times, trigger and time, which change with traffic.
func (r ProxyRoutes) SameStructure(o ProxyRoutes) bool {
	if r.Removed != o.Removed || !r.Proxy.equal(o.Proxy) || len(r.Routes) != len(o.Routes) {
		return false
	}
	for i := range r.Routes {
		if !r.Routes[i].sameStructure(o.Routes[i]) {
			return false
		}
	}
	return true
}

func (p ProxyInstance) equal(o ProxyInstance) bool {
	return p.ID == o.ID && p.Kind == o.Kind && p.NetNS == o.NetNS &&
		slices.EqualFunc(p.Procs, o.Procs, Process.SameIdentity) &&
		slices.Equal(p.Listeners, o.Listeners) && p.ConfigPath == o.ConfigPath &&
		slices.Equal(p.Files, o.Files) && slices.Equal(p.Notes, o.Notes)
}

func (r ProxyRoute) sameStructure(o ProxyRoute) bool {
	if !slices.Equal(r.Listen, o.Listen) || !slices.Equal(r.Frontends, o.Frontends) ||
		!slices.Equal(r.ServerNames, o.ServerNames) || r.Path != o.Path || r.Kind != o.Kind ||
		r.Target != o.Target || r.Upstream != o.Upstream || r.Root != o.Root ||
		r.Source != o.Source || r.Inferred != o.Inferred || !slices.Equal(r.Notes, o.Notes) ||
		len(r.Backends) != len(o.Backends) {
		return false
	}
	for i := range r.Backends {
		if !r.Backends[i].sameStructure(o.Backends[i]) {
			return false
		}
	}
	return true
}

func (b ProxyBackend) sameStructure(o ProxyBackend) bool {
	sameListener := (b.Listener == nil) == (o.Listener == nil) &&
		(b.Listener == nil || *b.Listener == *o.Listener)
	return b.Address == o.Address && b.Addr == o.Addr && b.Unix == o.Unix && sameListener &&
		slices.EqualFunc(b.Procs, o.Procs, Process.SameIdentity) &&
		b.Config == o.Config && b.Seen == o.Seen && b.Note == o.Note
}

// Clone returns a deep copy.
func (r ProxyRoutes) Clone() ProxyRoutes {
	r.Proxy.Procs = slices.Clone(r.Proxy.Procs)
	r.Proxy.Listeners = slices.Clone(r.Proxy.Listeners)
	r.Proxy.Files = slices.Clone(r.Proxy.Files)
	r.Proxy.Notes = slices.Clone(r.Proxy.Notes)
	routes := make([]ProxyRoute, len(r.Routes))
	for i, rt := range r.Routes {
		rt.Listen = slices.Clone(rt.Listen)
		rt.Frontends = slices.Clone(rt.Frontends)
		rt.ServerNames = slices.Clone(rt.ServerNames)
		rt.Notes = slices.Clone(rt.Notes)
		backends := make([]ProxyBackend, len(rt.Backends))
		for j, b := range rt.Backends {
			if b.Listener != nil {
				k := *b.Listener
				b.Listener = &k
			}
			b.Procs = slices.Clone(b.Procs)
			backends[j] = b
		}
		rt.Backends = backends
		routes[i] = rt
	}
	r.Routes = routes
	return r
}
