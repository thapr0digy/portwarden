package conf

import (
	"net/netip"
	"strconv"
	"strings"
)

// Names resolves host names without DNS: IP literals, "localhost", and the names in the
// proxy root's /etc/hosts. Anything else stays unresolved.
type Names struct {
	hosts map[string][]netip.Addr
}

// LoadNames reads /etc/hosts from fsys (missing or unreadable is fine).
func LoadNames(fsys FS) *Names {
	n := &Names{hosts: make(map[string][]netip.Addr)}
	if fsys == nil {
		return n
	}
	b, err := fsys.ReadFile("/etc/hosts")
	if err != nil {
		return n
	}
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		for _, name := range f[1:] {
			name = strings.ToLower(name)
			n.hosts[name] = append(n.hosts[name], a.Unmap())
		}
	}
	return n
}

// Lookup returns the addresses of host (an IP literal, bracketed or not, or a name).
func (n *Names) Lookup(host string) ([]netip.Addr, bool) {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		return []netip.Addr{a.Unmap()}, true
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if as, ok := n.hosts[h]; ok {
		return as, true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}, true
	}
	return nil, false
}

// SplitHostPort splits "host:port", "[v6]:port", "host" (port def) and "*:port".
// ok is false for a malformed port.
func SplitHostPort(s string, def uint16) (host string, port uint16, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, false
		}
		host, rest := s[1:end], s[end+1:]
		if rest == "" {
			return host, def, true
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, false
		}
		p, err := strconv.ParseUint(rest[1:], 10, 16)
		return host, uint16(p), err == nil
	}
	if strings.Count(s, ":") > 1 { // a bare IPv6 address
		return s, def, true
	}
	h, ps, found := strings.Cut(s, ":")
	if !found {
		return s, def, true
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	return h, uint16(p), err == nil
}

// Endpoint builds a Backend for "host[:port]" with default port def. note is kept
// (e.g. "backup") and joined with the reason when the name does not resolve.
func (n *Names) Endpoint(address, hostPort string, def uint16, note string) Backend {
	b := Backend{Address: address, Note: note}
	host, port, ok := SplitHostPort(hostPort, def)
	if !ok || host == "" {
		b.Note = joinNote(note, "unresolved: bad address "+hostPort)
		return b
	}
	addrs, ok := n.Lookup(host)
	if !ok {
		b.Note = joinNote(note, "unresolved: hostname "+host+" (no DNS lookups)")
		return b
	}
	for _, a := range addrs {
		b.Addrs = append(b.Addrs, netip.AddrPortFrom(a, port))
	}
	return b
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
