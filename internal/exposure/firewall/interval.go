package firewall

import (
	"math"
	"net/netip"
	"slices"
)

// Intervals. A path's destination can be an address interval (after a DNAT to an
// address range) and a port interval (a ranged packet, or a DNAT to a port range). The
// evaluator never walks such an interval value by value: before a match that looks at
// the destination, a path is cut where the match's own set starts or ends, so each
// piece is wholly in or wholly out of the set and is decided by its first value. The
// number of pieces is bounded by the boundaries the rules name, and by maxStates.

// splitFor cuts every ranged path in states where m tells destinations apart.
func (e *evaluator) splitFor(m Match, states []state) []state {
	ranged := slices.ContainsFunc(states, func(s state) bool {
		return s.pkt.daddrHi != s.pkt.daddr || s.pkt.dportHi != s.pkt.dport
	})
	if !ranged {
		return states
	}
	switch m.Field {
	case FieldDPort:
		cuts := portCuts(m.Ports)
		var out []state
		for _, s := range states {
			out = append(out, splitPorts(s, cuts)...)
		}
		return out
	case FieldDAddr:
		return e.splitAddrs(states, addrCuts(m))
	case FieldDAddrType:
		return e.splitAddrs(states, e.env.AddrCuts)
	}
	return states
}

// portCuts lists the ports where a set of ranges starts or ends (the port after its
// last), sorted.
func portCuts(ranges []PortRange) []uint16 {
	var cuts []uint16
	for _, r := range ranges {
		if r.Lo > r.Hi {
			continue
		}
		cuts = append(cuts, r.Lo)
		if r.Hi < math.MaxUint16 {
			cuts = append(cuts, r.Hi+1)
		}
	}
	slices.Sort(cuts)
	return slices.Compact(cuts)
}

// splitPorts cuts a path's destination port interval at cuts (each the first port of
// a new piece). While the port is still the packet's own, the packet's ports are cut
// alike.
func splitPorts(s state, cuts []uint16) []state {
	lo, hi := s.pkt.dport, s.pkt.dportHi
	if lo == hi {
		return []state{s}
	}
	var out []state
	start := lo
	emit := func(a, b uint16) {
		p := s
		p.pkt.dport, p.pkt.dportHi = a, b
		if s.pkt.portKept {
			p.pkt.odport, p.pkt.odportHi = a, b
		}
		out = append(out, p)
	}
	for _, c := range cuts {
		if c > start && c <= hi {
			emit(start, c-1)
			start = c
		}
	}
	emit(start, hi)
	return out
}

// addrCuts lists where a match's prefixes and ranges start and end (the address after
// their last), sorted.
func addrCuts(m Match) []netip.Addr {
	var cuts []netip.Addr
	add := func(lo, hi netip.Addr) {
		cuts = append(cuts, lo)
		if n := hi.Next(); n.IsValid() {
			cuts = append(cuts, n)
		}
	}
	for _, p := range m.Pfx {
		p = p.Masked()
		add(p.Addr(), LastAddr(p))
	}
	for _, r := range m.Ranges {
		add(r.Lo, r.Hi)
	}
	slices.SortFunc(cuts, netip.Addr.Compare)
	return slices.Compact(cuts)
}

// splitAddrs cuts every path's destination address interval at cuts.
func (e *evaluator) splitAddrs(states []state, cuts []netip.Addr) []state {
	var out []state
	for _, s := range states {
		lo, hi := s.pkt.daddr, s.pkt.daddrHi
		if lo == hi || len(cuts) == 0 {
			out = append(out, s)
			continue
		}
		start := lo
		for _, c := range cuts {
			if c.BitLen() != lo.BitLen() || c.Compare(start) <= 0 || c.Compare(hi) > 0 {
				continue
			}
			p := s
			p.pkt.daddr, p.pkt.daddrHi = start, c.Prev()
			out = append(out, p)
			start = c
		}
		p := s
		p.pkt.daddr, p.pkt.daddrHi = start, hi
		out = append(out, p)
	}
	return e.dedupe(out)
}

// LastAddr is the last address of a prefix.
func LastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
