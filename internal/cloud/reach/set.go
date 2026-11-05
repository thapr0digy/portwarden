// Package reach is the cloud look-up's shared reach rule (M10): every cloud's judge works
// out the set of source addresses its rules let through to a port, and this package says
// whether that set reaches the internet.
//
// The rule is the user's (M10 design review): a port is open to the internet unless every
// source address that gets through is private or inside the operator's VPN ranges.
// Private means not globally reachable (RFC 1918, CGNAT 100.64.0.0/10, ULA fc00::/7,
// loopback, link-local, documentation, multicast and the other special-purpose ranges);
// the VPN ranges (config cloud.vpn_cidrs) add the operator's own VPN egress or office
// addresses. So an SSH rule that allows only an office's public IP counts as open unless
// that IP is listed.
//
// A Set holds IPv4 and IPv6 addresses together: IPv4 lives in the IPv4-mapped block
// ::ffff:0:0/96 of one 128-bit space, so the two families never overlap.
package reach

import (
	"math/bits"
	"net/netip"
	"slices"
)

// u128 is a 128-bit address.
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }

func (a u128) addOne() (u128, bool) {
	lo, c := bits.Add64(a.lo, 1, 0)
	hi, c := bits.Add64(a.hi, 0, c)
	return u128{hi, lo}, c != 0
}

func (a u128) subOne() (u128, bool) {
	lo, b := bits.Sub64(a.lo, 1, 0)
	hi, b := bits.Sub64(a.hi, 0, b)
	return u128{hi, lo}, b != 0
}

// mask returns the host bits of a /n prefix.
func hostMask(n int) u128 {
	switch {
	case n <= 0:
		return u128{^uint64(0), ^uint64(0)}
	case n < 64:
		return u128{^uint64(0) >> n, ^uint64(0)}
	case n < 128:
		return u128{0, ^uint64(0) >> (n - 64)}
	}
	return u128{}
}

func fromAddr(a netip.Addr) u128 {
	b := a.As16() // IPv4 comes back IPv4-mapped
	var hi, lo uint64
	for i := range 8 {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	return u128{hi, lo}
}

func (a u128) addr() netip.Addr {
	var b [16]byte
	for i := range 8 {
		b[7-i] = byte(a.hi >> (8 * i))
		b[15-i] = byte(a.lo >> (8 * i))
	}
	return netip.AddrFrom16(b).Unmap()
}

// span is an inclusive address range.
type span struct{ lo, hi u128 }

// Set is a set of addresses: sorted, disjoint, non-adjacent spans. The zero Set is empty.
type Set struct{ s []span }

// Prefix returns the set of a prefix's addresses (an IPv4 prefix in the mapped block). An
// IPv6 prefix never holds the mapped block: a cloud's IPv6 rule (::/0) never matches IPv4.
func Prefix(p netip.Prefix) Set {
	s := prefix(p)
	if p.IsValid() && !p.Addr().Is4() && !p.Addr().Is4In6() {
		s = s.Subtract(prefix(mappedBlock))
	}
	return s
}

var mappedBlock = netip.MustParsePrefix("::ffff:0:0/96")

func prefix(p netip.Prefix) Set {
	if !p.IsValid() {
		return Set{}
	}
	p = p.Masked()
	bitsN := p.Bits()
	if p.Addr().Is4() {
		bitsN += 96
	}
	lo := fromAddr(p.Addr())
	m := hostMask(bitsN)
	return Set{[]span{{lo, u128{lo.hi | m.hi, lo.lo | m.lo}}}}
}

// Prefixes returns the union of prefixes.
func Prefixes(ps ...netip.Prefix) Set {
	var out Set
	for _, p := range ps {
		out = out.Union(Prefix(p))
	}
	return out
}

// MustParse is Prefixes over CIDR strings; it panics on a bad one (fixed tables only).
func MustParse(cidrs ...string) Set {
	var out Set
	for _, c := range cidrs {
		out = out.Union(Prefix(netip.MustParsePrefix(c)))
	}
	return out
}

// IsEmpty reports whether the set holds no address.
func (a Set) IsEmpty() bool { return len(a.s) == 0 }

// Equal reports whether two sets hold the same addresses.
func (a Set) Equal(b Set) bool { return slices.Equal(a.s, b.s) }

// Union returns a ∪ b.
func (a Set) Union(b Set) Set {
	all := append(slices.Clone(a.s), b.s...)
	slices.SortFunc(all, func(x, y span) int {
		if x.lo.less(y.lo) {
			return -1
		}
		if y.lo.less(x.lo) {
			return 1
		}
		return 0
	})
	var out []span
	for _, sp := range all {
		if n := len(out); n > 0 {
			last := &out[n-1]
			next, overflow := last.hi.addOne()
			if overflow || !next.less(sp.lo) { // overlapping or adjacent
				if last.hi.less(sp.hi) {
					last.hi = sp.hi
				}
				continue
			}
		}
		out = append(out, sp)
	}
	return Set{out}
}

// Intersect returns a ∩ b.
func (a Set) Intersect(b Set) Set {
	var out []span
	i, j := 0, 0
	for i < len(a.s) && j < len(b.s) {
		x, y := a.s[i], b.s[j]
		lo, hi := x.lo, x.hi
		if lo.less(y.lo) {
			lo = y.lo
		}
		if y.hi.less(hi) {
			hi = y.hi
		}
		if !hi.less(lo) {
			out = append(out, span{lo, hi})
		}
		if x.hi.less(y.hi) {
			i++
		} else {
			j++
		}
	}
	return Set{out}
}

// Subtract returns a \ b.
func (a Set) Subtract(b Set) Set {
	return a.Intersect(b.complement())
}

func (a Set) complement() Set {
	var out []span
	next, done := u128{}, false
	for _, sp := range a.s {
		if next.less(sp.lo) {
			end, _ := sp.lo.subOne()
			out = append(out, span{next, end})
		}
		var overflow bool
		next, overflow = sp.hi.addOne()
		if overflow {
			done = true
			break
		}
	}
	if !done {
		out = append(out, span{next, u128{^uint64(0), ^uint64(0)}})
	}
	return Set{out}
}

// CIDRs returns the set as the fewest prefixes that cover it exactly, in address order.
func (a Set) CIDRs() []netip.Prefix {
	var out []netip.Prefix
	for _, sp := range a.s {
		lo := sp.lo
		for {
			// The largest block that starts at lo and ends at or before sp.hi.
			n := 128
			for n > 0 {
				m := hostMask(n - 1)
				if lo.hi&m.hi != 0 || lo.lo&m.lo != 0 {
					break // lo not aligned to a /n-1
				}
				end := u128{lo.hi | m.hi, lo.lo | m.lo}
				if sp.hi.less(end) {
					break
				}
				n--
			}
			out = append(out, toPrefix(lo, n))
			m := hostMask(n)
			end := u128{lo.hi | m.hi, lo.lo | m.lo}
			if !end.less(sp.hi) {
				break
			}
			lo, _ = end.addOne()
		}
	}
	return out
}

func toPrefix(lo u128, n int) netip.Prefix {
	a := lo.addr()
	if a.Is4() {
		return netip.PrefixFrom(a, n-96)
	}
	return netip.PrefixFrom(a, n)
}
