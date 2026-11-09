package admin

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/model"
)

// Target is where the reader connects for an endpoint.
type Target struct {
	// Network is "unix" (Path inside the proxy's root) or "tcp" (Addr).
	Network string
	Path    string
	Addr    netip.AddrPort
	// Host is the HTTP Host header: the endpoint as configured when it names a host,
	// else localhost:<port> (what Caddy's origin check allows on a wildcard listener).
	Host string
}

// Plan picks the connection for an endpoint, or says why there is none. A TCP endpoint
// must be one of the proxy's own listeners; the address dialled is loopback in the
// agent's namespace, or in a container's namespace one of its own addresses that the host
// reaches over a container network. It never resolves a name and never picks an address
// outside the proxy's namespace.
func Plan(ep Endpoint, p Proxy) (Target, error) {
	switch ep.Network {
	case "unix":
		if !strings.HasPrefix(ep.Addr, "/") {
			return Target{}, undetermined("endpoint unix:%s is not an absolute path", ep.Addr)
		}
		return Target{Network: "unix", Path: ep.Addr, Host: "localhost"}, nil
	case "tcp":
	default:
		return Target{}, undetermined("endpoint %s: unknown network %q", ep, ep.Network)
	}
	host, port, err := splitEndpoint(ep.Addr)
	if err != nil {
		return Target{}, undetermined("endpoint %s: %v", ep, err)
	}
	var want netip.Addr // invalid: any address (wildcard or localhost)
	localhost := strings.EqualFold(host, "localhost")
	wildcard := host == "" || host == "*"
	if !localhost && !wildcard {
		a, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			return Target{}, undetermined("endpoint %s: host %s is not an address (no DNS lookups)", ep, host)
		}
		want = a.Unmap()
	}
	hdr := ep.Addr
	if wildcard || (want.IsValid() && want.IsUnspecified()) {
		hdr = "localhost:" + strconv.Itoa(int(port))
	}
	var held []model.ListenerKey
	for _, l := range p.Listeners {
		if l.Proto != "tcp" || l.Port != port || l.NetNS != p.NetNS {
			continue
		}
		la := l.Addr.Unmap()
		switch {
		case wildcard, want.IsValid() && want.IsUnspecified():
		case localhost:
			if !la.IsLoopback() && !la.IsUnspecified() {
				continue
			}
		case la != want && !la.IsUnspecified():
			continue
		}
		held = append(held, l)
	}
	if len(held) == 0 {
		return Target{}, undetermined("endpoint %s is not a listener the proxy holds", ep)
	}
	var lastErr error
	for _, l := range held {
		a, err := dialAddr(l.Addr.Unmap(), want, localhost, p)
		if err == nil {
			return Target{Network: "tcp", Addr: netip.AddrPortFrom(a, port), Host: hdr}, nil
		}
		lastErr = err
	}
	return Target{}, lastErr
}

// dialAddr is the address to dial for the proxy's listener la (want: the endpoint's
// own address, when it names one).
func dialAddr(la, want netip.Addr, localhost bool, p Proxy) (netip.Addr, error) {
	if p.SameNetNS {
		switch {
		case !la.IsUnspecified():
			return la, nil
		case want.IsValid() && !want.IsUnspecified() && (want.IsLoopback() || containsAddr(p.LocalAddrs, want)):
			return want, nil
		case la.Is4():
			return netip.MustParseAddr("127.0.0.1"), nil
		default:
			return netip.IPv6Loopback(), nil
		}
	}
	// Another network namespace: its loopback cannot be reached without entering it.
	if la.IsLoopback() || localhost || (want.IsValid() && want.IsLoopback()) {
		return netip.Addr{}, undetermined("endpoint is on a container's loopback, unreachable without entering its network namespace")
	}
	var cands []netip.Addr
	switch {
	case !la.IsUnspecified():
		cands = []netip.Addr{la}
	case want.IsValid() && !want.IsUnspecified():
		cands = []netip.Addr{want}
	default:
		for _, a := range p.LocalAddrs {
			if !a.IsLoopback() && !a.IsLinkLocalUnicast() && (la.Is6() || a.Is4()) {
				cands = append(cands, a)
			}
		}
	}
	for _, a := range cands {
		if containsAddr(p.LocalAddrs, a) && p.HostContainerNet != nil && p.HostContainerNet(a) {
			return a, nil
		}
	}
	return netip.Addr{}, undetermined("no address of the proxy's network namespace is on a host container network")
}

func containsAddr(as []netip.Addr, a netip.Addr) bool {
	for _, x := range as {
		if x.Unmap() == a {
			return true
		}
	}
	return false
}

// splitEndpoint splits "host:port", "[v6]:port", ":port".
func splitEndpoint(s string) (string, uint16, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, errText("no port")
	}
	host, ps := s[:i], s[i+1:]
	if strings.HasPrefix(host, "[") != strings.HasSuffix(host, "]") {
		return "", 0, errText("bad brackets")
	}
	if strings.Contains(strings.Trim(host, "[]"), ":") && !strings.HasPrefix(host, "[") {
		return "", 0, errText("an IPv6 host needs brackets")
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil || p == 0 {
		return "", 0, errText("bad port " + ps)
	}
	return host, uint16(p), nil
}

type errText string

func (e errText) Error() string { return string(e) }
