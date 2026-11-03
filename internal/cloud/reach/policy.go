package reach

import (
	"fmt"
	"net/netip"
	"strings"
)

// Family is an address family: 4 or 6.
type Family int

// The two families.
const (
	V4 Family = 4
	V6 Family = 6
)

// All returns every address of the family (0.0.0.0/0 or ::/0, as the clouds spell it).
func All(f Family) Set {
	if f == V6 {
		return MustParse("::/0")
	}
	return MustParse("0.0.0.0/0")
}

// Anywhere is how the clouds write "every address" of the family.
func Anywhere(f Family) string {
	if f == V6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

// notGlobal is every range that is never reached from the internet: the IANA
// special-purpose registries' ranges that are not globally reachable (RFC 6890 and its
// updates). IPv6 outside 2000::/3 (global unicast) is not public.
var notGlobal = MustParse(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
).Union(MustParse(
	"::/3", "4000::/2", "8000::/1", // everything but 2000::/3 (ULA, link-local, multicast, loopback …)
	"2001:db8::/32", "2001:2::/48", "2001:10::/28",
))

// Policy is the reach rule with the operator's VPN ranges. The zero Policy has none.
type Policy struct{ vpn Set }

// NewPolicy returns the rule with vpn as the operator's VPN or office ranges, which
// never count as the internet.
func NewPolicy(vpn []netip.Prefix) Policy { return Policy{vpn: Prefixes(vpn...)} }

func (p Policy) trusted() Set { return p.vpn.Union(notGlobal) }

// ParseVPN parses the config's vpn_cidrs.
func ParseVPN(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("vpn_cidrs: %q: %w", c, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Internet returns the family's addresses that count as the internet.
func (p Policy) Internet(f Family) Set {
	return All(f).Subtract(p.trusted())
}

// Exposed returns the part of allowed that is the internet (both families).
func (p Policy) Exposed(allowed Set) Set {
	return allowed.Subtract(p.trusted())
}

// Describe names a set of internet addresses for evidence: "0.0.0.0/0" or "::/0" when it
// is all of the family's internet, otherwise its prefixes, at most max of them
// ("+N more" after).
func (p Policy) Describe(s Set, max int) string {
	for _, f := range []Family{V4, V6} {
		if in := p.Internet(f); !in.IsEmpty() && s.Equal(in) {
			return Anywhere(f)
		}
	}
	cidrs := s.CIDRs()
	parts := make([]string, 0, min(len(cidrs), max)+1)
	for i, c := range cidrs {
		if i == max {
			parts = append(parts, fmt.Sprintf("+%d more", len(cidrs)-max))
			break
		}
		parts = append(parts, c.String())
	}
	if len(parts) == 0 {
		return "nowhere"
	}
	return strings.Join(parts, ", ")
}
