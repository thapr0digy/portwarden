// Package verifier is the outside checker (design §4 level 4, §9): from outside the
// servers it probes listeners at level bound or above, only on addresses in the
// inventory (a host's inbound public-IP candidates, a listener's own bind address, and
// addresses the operator lists per host) and only inside the configured allowlist, and
// publishes exposure.confirmed with what it saw. TCP probes connect and read what the
// service sends first; UDP probes send one fixed, well-formed request per protocol.
package verifier

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
)

// Scope decides which addresses may be probed.
type Scope struct {
	// Allow is the allowlist: nothing outside it is ever probed. Empty allows nothing.
	Allow []netip.Prefix
	// HostAddresses are extra inventory addresses per host id (operator-declared).
	HostAddresses map[string][]netip.Addr
}

// Target is one address and port to probe for a listener.
type Target struct {
	Proto string
	Addr  netip.Addr
	Port  uint16
}

func (t Target) String() string { return netip.AddrPortFrom(t.Addr, t.Port).String() }

// dnatRe matches the agent's port-mapping evidence "nat: dnat tcp/18080 -> 172.17.0.2:80".
var dnatRe = regexp.MustCompile(`^nat: dnat (tcp|udp)/(\d+) -> `)

// Targets lists what to probe for a listener at level lvl, or why nothing.
func (s Scope) Targets(host string, l *asmv1.Listener, lvl int, evidence []string, h *asmv1.HostInfo) ([]Target, string) {
	if lvl < int(model.ExposureBound) {
		return nil, "level below bound"
	}
	type pp struct {
		proto string
		port  uint16
	}
	var ports []pp
	for _, e := range evidence {
		if m := dnatRe.FindStringSubmatch(e); m != nil {
			if n, err := strconv.ParseUint(m[2], 10, 16); err == nil && n > 0 {
				ports = append(ports, pp{m[1], uint16(n)})
			}
		}
	}
	if len(ports) == 0 {
		ports = []pp{{l.GetProto(), uint16(l.GetPort())}}
	}
	bind, err := netip.ParseAddr(l.GetAddr())
	if err != nil {
		return nil, "unparsable bind address " + l.GetAddr()
	}
	bind = bind.Unmap()
	var addrs []netip.Addr
	switch {
	case bind.IsUnspecified():
		var cands []netip.Addr
		for _, ip := range h.GetPublicIps() {
			if ip.GetDir() != model.DirIn {
				continue
			}
			if a, err := netip.ParseAddr(ip.GetIp()); err == nil {
				cands = append(cands, a.Unmap())
			}
		}
		cands = append(cands, s.HostAddresses[host]...)
		for _, a := range cands {
			// 0.0.0.0 serves IPv4 only; :: serves both (unless v6only, which the stream
			// does not carry: over-report).
			if bind.Is4() && !a.Is4() {
				continue
			}
			addrs = append(addrs, a)
		}
	case bind.IsLoopback():
		return nil, "loopback"
	default:
		addrs = []netip.Addr{bind}
	}
	var out []Target
	for _, a := range addrs {
		if !s.allowed(a) {
			continue
		}
		for _, p := range ports {
			t := Target{Proto: p.proto, Addr: a, Port: p.port}
			if !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Sprintf("no inventory address inside the allowlist (candidates %v)", addrs)
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
