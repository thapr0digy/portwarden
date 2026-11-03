// Package netif lists the host's network interfaces and their addresses, and tells
// which of them face the outside.
package netif

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Interface is one network interface of the host netns.
type Interface struct {
	Name     string
	Up       bool
	Loopback bool
	// Prefixes are the interface's addresses with their connected prefix lengths.
	Prefixes []netip.Prefix
}

// containerPrefixes name interfaces that container runtimes, CNI plugins and VM
// managers create: bridges, veth pairs, overlay tunnels. Traffic on them comes from
// containers or VMs on this host, not from the outside.
var containerPrefixes = []string{
	"docker", "br-", "veth", "cni", "flannel", "cali", "cilium", "lxc", "lxdbr",
	"kube-", "weave", "virbr", "vnet", "podman", "tunl", "vxlan", "genev", "nodelocaldns",
}

// ContainerNet reports whether the interface belongs to a container or VM network, by
// its name.
func (i Interface) ContainerNet() bool {
	for _, p := range containerPrefixes {
		if strings.HasPrefix(i.Name, p) {
			return true
		}
	}
	return false
}

// External reports whether packets from the outside can arrive on the interface: up,
// not loopback, not a container network.
func (i Interface) External() bool { return i.Up && !i.Loopback && !i.ContainerNet() }

// Snapshot lists the interfaces, sorted by name.
func Snapshot() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("netif: %w", err)
	}
	out := make([]Interface, 0, len(ifs))
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, fmt.Errorf("netif: %s: %w", ifc.Name, err)
		}
		i := Interface{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0, Loopback: ifc.Flags&net.FlagLoopback != 0}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			bits, _ := ipn.Mask.Size()
			addr = addr.Unmap()
			if addr.Is4() && bits > 32 {
				bits -= 96
			}
			i.Prefixes = append(i.Prefixes, netip.PrefixFrom(addr, bits))
		}
		out = append(out, i)
	}
	slices.SortFunc(out, func(a, b Interface) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Owner returns the interface that has addr.
func Owner(ifs []Interface, addr netip.Addr) (Interface, bool) {
	for _, i := range ifs {
		for _, p := range i.Prefixes {
			if p.Addr() == addr {
				return i, true
			}
		}
	}
	return Interface{}, false
}

// Route returns the interface whose connected prefix most specifically covers addr.
func Route(ifs []Interface, addr netip.Addr) (string, bool) {
	best, bestBits := "", -1
	for _, i := range ifs {
		if !i.Up {
			continue
		}
		for _, p := range i.Prefixes {
			if p.Masked().Contains(addr) && p.Bits() > bestBits {
				best, bestBits = i.Name, p.Bits()
			}
		}
	}
	return best, bestBits >= 0
}

// Fingerprint is a stable text form of the interface list, for change detection.
func Fingerprint(ifs []Interface) string {
	var b strings.Builder
	for _, i := range ifs {
		fmt.Fprintf(&b, "%s up=%v lo=%v %v\n", i.Name, i.Up, i.Loopback, i.Prefixes)
	}
	return b.String()
}

// IsPublic reports whether addr is routable on the internet: global unicast, outside
// RFC 1918 / ULA, CGNAT (100.64/10), documentation, benchmarking and other reserved
// ranges.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(addr) {
			return false
		}
	}
	if addr.Is6() {
		return netip.MustParsePrefix("2000::/3").Contains(addr)
	}
	return true
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b::/96"),
}
