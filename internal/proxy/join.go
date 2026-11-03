// Package proxy joins what the proxy mapper reads (each proxy's configured routes and the
// connections it was seen making) to the agent's listener table, so every route ends at a
// real program, and indexes the result by backend listener (behind_proxy).
package proxy

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/state"
)

// Observed is one destination a proxy connected to, aggregated in the kernel.
type Observed struct {
	Addr  netip.AddrPort
	Count uint64
	Last  time.Time
}

// State is what the mapper knows about one proxy: its instance (with the config files
// and read notes), its configured routes (nil for an observed-only kind) and its
// observed connections.
type State struct {
	Instance model.ProxyInstance
	Routes   []conf.Route
	Observed []Observed
	// Trigger says why this state was produced (started, config, traffic, recheck).
	Trigger string
	At      time.Time
}

// Update is the mapper's full view: every current proxy and the local addresses of each
// network namespace that holds a listener (for joining non-loopback backends).
type Update struct {
	States     []State
	NetnsAddrs map[uint32][]netip.Addr
}

// index finds listeners by protocol and port.
type index struct {
	byPort map[protoPort][]state.Listener
	addrs  map[uint32][]netip.Addr
}

type protoPort struct {
	proto string
	port  uint16
}

func newIndex(listeners []state.Listener, addrs map[uint32][]netip.Addr) *index {
	ix := &index{byPort: make(map[protoPort][]state.Listener), addrs: addrs}
	for _, l := range listeners {
		k := protoPort{l.Key.Proto, l.Key.Port}
		ix.byPort[k] = append(ix.byPort[k], l)
	}
	return ix
}

func (ix *index) has(netns uint32, a netip.Addr) bool {
	return slices.Contains(ix.addrs[netns], a)
}

// find returns the listener a connection from a process in netns to dst reaches: in
// the proxy's own netns an exact bind first, then a wildcard (loopback, or one of the
// netns's own addresses); in another netns a listener whose netns owns dst.
func (ix *index) find(netns uint32, proto string, dst netip.AddrPort) (state.Listener, bool) {
	a := dst.Addr().Unmap()
	cands := ix.byPort[protoPort{proto, dst.Port()}]
	rank := func(l state.Listener) int {
		la := l.Key.Addr
		wild := la.IsUnspecified() && (la.Is6() || a.Is4())
		switch {
		case l.Key.NetNS == netns && la == a:
			return 1
		case l.Key.NetNS == netns && wild && (a.IsLoopback() || ix.has(netns, a)):
			return 2
		case l.Key.NetNS != netns && !a.IsLoopback() && la == a && ix.has(l.Key.NetNS, a):
			return 3
		case l.Key.NetNS != netns && !a.IsLoopback() && wild && ix.has(l.Key.NetNS, a):
			return 4
		}
		return 0
	}
	best, bestRank := state.Listener{}, 0
	for _, l := range cands {
		if r := rank(l); r > 0 && (bestRank == 0 || r < bestRank) {
			best, bestRank = l, r
		}
	}
	return best, bestRank > 0
}

// Join resolves a proxy's routes against the listeners: frontends among the proxy's own
// listeners, backends to the listeners they reach, and observed connections marking
// backends seen; observed destinations no route names become inferred routes.
func Join(s State, listeners []state.Listener, addrs map[uint32][]netip.Addr) model.ProxyRoutes {
	ix := newIndex(listeners, addrs)
	inst := s.Instance
	observed := make(map[netip.AddrPort]Observed, len(s.Observed))
	for _, o := range s.Observed {
		k := netip.AddrPortFrom(o.Addr.Addr().Unmap(), o.Addr.Port())
		prev := observed[k]
		prev.Addr, prev.Count = k, prev.Count+o.Count
		if o.Last.After(prev.Last) {
			prev.Last = o.Last
		}
		observed[k] = prev
	}
	used := make(map[netip.AddrPort]bool)
	out := model.ProxyRoutes{Proxy: inst, Trigger: s.Trigger, At: s.At}
	for _, r := range s.Routes {
		rt := model.ProxyRoute{
			Listen: r.Listen, ServerNames: r.ServerNames, Path: r.Path, Kind: r.Kind,
			Target: r.Target, Upstream: r.Upstream, Root: r.Root, Source: r.Source, Notes: r.Notes,
			Frontends: frontends(inst.Listeners, r.Listen),
		}
		proto := model.ProtoTCP
		if len(r.Listen) > 0 && allUDP(r.Listen) {
			proto = model.ProtoUDP
		}
		for _, b := range r.Backends {
			rt.Backends = append(rt.Backends, joinBackend(b, inst.NetNS, proto, ix, observed, used))
		}
		out.Routes = append(out.Routes, rt)
	}
	var extra []netip.AddrPort
	for k := range observed {
		if !used[k] {
			extra = append(extra, k)
		}
	}
	slices.SortFunc(extra, func(a, b netip.AddrPort) int { return a.Compare(b) })
	for _, k := range extra {
		o := observed[k]
		b := model.ProxyBackend{Address: k.String(), Addr: k, Seen: true, Connections: o.Count, LastSeen: o.Last}
		if l, ok := ix.find(inst.NetNS, model.ProtoTCP, k); ok {
			lk := l.Key
			b.Listener, b.Procs = &lk, slices.Clone(l.Procs)
		} else {
			b.Note = "no listener"
		}
		out.Routes = append(out.Routes, model.ProxyRoute{
			Frontends: slices.Clone(inst.Listeners), Kind: model.RouteProxy, Target: k.String(),
			Inferred: true, Backends: []model.ProxyBackend{b},
		})
	}
	return out
}

func joinBackend(b conf.Backend, netns uint32, proto string, ix *index, observed map[netip.AddrPort]Observed, used map[netip.AddrPort]bool) model.ProxyBackend {
	pb := model.ProxyBackend{Address: b.Address, Unix: b.Unix, Config: true, Note: b.Note}
	if b.Unix != "" || len(b.Addrs) == 0 {
		return pb
	}
	pb.Addr = b.Addrs[0]
	joined := false
	for _, a := range b.Addrs {
		a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
		if o, ok := observed[a]; ok {
			used[a] = true
			pb.Seen = true
			pb.Connections += o.Count
			if o.Last.After(pb.LastSeen) {
				pb.LastSeen = o.Last
			}
		}
		if joined {
			continue
		}
		if l, ok := ix.find(netns, proto, a); ok {
			lk := l.Key
			pb.Addr, pb.Listener, pb.Procs = a, &lk, slices.Clone(l.Procs)
			joined = true
		}
	}
	if !joined && pb.Note == "" {
		pb.Note = "no listener"
	}
	return pb
}

func allUDP(listen []string) bool {
	for _, l := range listen {
		if !strings.HasSuffix(l, "/udp") {
			return false
		}
	}
	return true
}

// frontends picks the proxy's listeners a route's listen addresses are served on: same
// port (any port for "*"), same protocol, and the same address or a wildcard listener
// (a specific listen address may be served by a wildcard socket).
func frontends(own []model.ListenerKey, listen []string) []model.ListenerKey {
	var out []model.ListenerKey
	for _, k := range own {
		for _, l := range listen {
			if listenMatches(k, l) {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

func listenMatches(k model.ListenerKey, listen string) bool {
	proto := model.ProtoTCP
	if s, ok := strings.CutSuffix(listen, "/udp"); ok {
		listen, proto = s, model.ProtoUDP
	}
	i := strings.LastIndex(listen, ":")
	if k.Proto != proto || strings.HasPrefix(listen, "unix:") || i < 0 {
		return false
	}
	host := strings.TrimSuffix(strings.TrimPrefix(listen[:i], "["), "]")
	if port := listen[i+1:]; port != "*" {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || uint16(p) != k.Port {
			return false
		}
	}
	if host == "*" || host == "" || k.Addr.IsUnspecified() {
		return true
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return true // a name: the port decides
	}
	return a.Unmap() == k.Addr
}

// BehindProxy indexes the routes by the backend listener they end at.
func BehindProxy(sets []model.ProxyRoutes) map[model.ListenerKey][]model.ProxyRef {
	out := make(map[model.ListenerKey][]model.ProxyRef)
	for _, s := range sets {
		if s.Removed {
			continue
		}
		for _, r := range s.Routes {
			for _, b := range r.Backends {
				if b.Listener == nil {
					continue
				}
				ref := model.ProxyRef{
					ProxyID: s.Proxy.ID, Kind: s.Proxy.Kind, Proxy: s.Proxy.Master(),
					Frontends: r.Frontends, ServerNames: r.ServerNames, Path: r.Path,
					Config: b.Config, Seen: b.Seen,
				}
				if !slices.ContainsFunc(out[*b.Listener], func(o model.ProxyRef) bool { return sameRef(o, ref) }) {
					out[*b.Listener] = append(out[*b.Listener], ref)
				}
			}
		}
	}
	return out
}

func sameRef(a, b model.ProxyRef) bool {
	return a.ProxyID == b.ProxyID && a.Path == b.Path && slices.Equal(a.ServerNames, b.ServerNames) &&
		slices.Equal(a.Frontends, b.Frontends) && a.Config == b.Config && a.Seen == b.Seen
}
