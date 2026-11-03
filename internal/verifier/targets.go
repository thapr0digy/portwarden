// Package verifier is the outside checker (design §4 level 4, §9). It probes only what
// the inventory asks for (pwb.probe.<host>.request, built from the inventory's stored
// state, never from a host's event) and only addresses that pass its own checks: inside
// allow_cidrs, and, for a non-public address, listed for that host in host_addresses.
// At most 4 addresses and 4 ports per listener. TCP probes connect and read what the
// service sends first; UDP probes send one fixed, well-formed request per protocol.
package verifier

import (
	"fmt"
	"net/netip"
	"slices"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
)

// Caps on one listener's probes.
const (
	MaxAddresses = 4
	MaxPorts     = 4
)

// Scope decides which addresses may be probed.
type Scope struct {
	// Allow is the allowlist: nothing outside it is ever probed. Empty allows nothing.
	Allow []netip.Prefix
	// HostAddresses are operator-declared addresses per host id. A non-public address is
	// probed only when listed here for that host.
	HostAddresses map[string][]netip.Addr
}

// Target is one address and port to probe for a listener.
type Target struct {
	Proto string
	Addr  netip.Addr
	Port  uint16
}

func (t Target) String() string { return netip.AddrPortFrom(t.Addr, t.Port).String() }

// Targets lists what to probe for a request, or why nothing.
func (s Scope) Targets(host string, r *asmv1.ProbeRequest) ([]Target, string) {
	if int(r.GetLevel()) < int(model.ExposureBound) {
		return nil, "level below bound"
	}
	listed := s.HostAddresses[host]
	var cands []netip.Addr
	for _, a := range r.GetAddresses() {
		if ip, err := netip.ParseAddr(a); err == nil {
			cands = append(cands, ip.Unmap())
		}
	}
	bind, err := netip.ParseAddr(r.GetListener().GetAddr())
	if err != nil {
		return nil, "unparsable bind address"
	}
	bind = bind.Unmap()
	if bind.IsUnspecified() {
		for _, a := range listed {
			if bind.Is4() && !a.Is4() {
				continue
			}
			cands = append(cands, a)
		}
	}
	var addrs []netip.Addr
	for _, a := range cands {
		switch {
		case slices.Contains(addrs, a), !s.allowed(a):
		case !netif.IsPublic(a) && !slices.Contains(listed, a):
			// A private address only when the operator listed it for this host.
		default:
			addrs = append(addrs, a)
		}
	}
	addrs = addrs[:min(len(addrs), MaxAddresses)]
	ports := r.GetPorts()
	if len(ports) == 0 {
		ports = []uint32{r.GetListener().GetPort()}
	}
	proto := r.GetProto()
	if proto == "" {
		proto = r.GetListener().GetProto()
	}
	var out []Target
	for _, a := range addrs {
		for _, p := range ports[:min(len(ports), MaxPorts)] {
			if p == 0 || p > 65535 {
				continue
			}
			out = append(out, Target{Proto: proto, Addr: a, Port: uint16(p)})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Sprintf("no candidate address passes the allowlist (candidates %v)", cands)
	}
	return out, ""
}

func (s Scope) allowed(a netip.Addr) bool {
	for _, p := range s.Allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
