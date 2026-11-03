package firewall

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
)

// Packet is the first packet of a new connection from the outside: an arbitrary source
// address and port ("0/0"), arriving on IIf for DAddr:DPort.
type Packet struct {
	Family Family // FamilyIP or FamilyIP6
	Proto  string // tcp or udp
	DAddr  netip.Addr
	DPort  uint16
	IIf    string
}

// Env answers the routing questions the rules depend on.
type Env struct {
	// IsLocal reports whether an address belongs to the host (fib daddr type local,
	// addrtype LOCAL, and whether a DNAT'ed packet is delivered or forwarded).
	IsLocal func(netip.Addr) bool
	// Route returns the output interface for a forwarded destination; false when no
	// connected interface covers it.
	Route func(netip.Addr) (string, bool)
}

// Outcome is one way the packet's evaluation can end.
type Outcome struct {
	Accept bool
	// Forwarded: a DNAT sent the packet through the forward hook rather than input.
	Forwarded bool
	// DAddr and DPort are where the packet ends up (after any DNAT or redirect).
	DAddr netip.Addr
	DPort uint16
	// Origin and Where locate the decision: for a drop the dropping chain (a policy reads
	// "policy ip filter INPUT"); for an accept the last filter chain that accepted it, or
	// "" when no filter chain saw the packet.
	Origin, Where string
	// Maybe lists what the path depended on that the model could not decide.
	Maybe []string
	// Notes lists decided facts on the path: "rate-limited" (a limit the first packet
	// passes) and "source-restricted:<chain>" (an accept skipped only because the
	// source is not listed).
	Notes []string
	// Undecidable is set for a verdict that leaves the packet's fate open (queue), or a
	// destination the model lost track of (a NAT target it cannot read).
	Undecidable bool
}

// Decision summarises a set of outcomes.
type Decision int

const (
	Undetermined Decision = iota // outcomes disagree, or one is undecidable
	Open                         // every outcome accepts
	Closed                       // every outcome drops
)

// Result is every outcome of one packet.
type Result struct {
	Outcomes []Outcome
	// Truncated is set when forks exceeded the evaluator's bound; the result is then
	// Undetermined.
	Truncated bool
}

// Decision is Open when every outcome accepts, Closed when every one drops.
func (r Result) Decision() Decision {
	if r.Truncated || len(r.Outcomes) == 0 {
		return Undetermined
	}
	accepts, drops := 0, 0
	for _, o := range r.Outcomes {
		switch {
		case o.Undecidable:
			return Undetermined
		case o.Accept:
			accepts++
		default:
			drops++
		}
	}
	switch {
	case drops == 0:
		return Open
	case accepts == 0:
		return Closed
	}
	return Undetermined
}

// Notes is every distinct note of the outcomes, sorted.
func (r Result) Notes() []string {
	var out []string
	for _, o := range r.Outcomes {
		out = append(out, o.Notes...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// MaybeReasons is every distinct reason the outcomes depended on, sorted.
func (r Result) MaybeReasons() []string {
	var out []string
	for _, o := range r.Outcomes {
		out = append(out, o.Maybe...)
	}
	if r.Truncated {
		out = append(out, "too many paths")
	}
	slices.Sort(out)
	return slices.Compact(out)
}

const (
	maxStates = 256 // live paths per chain; beyond it the result is Truncated
	maxDepth  = 64  // nested jumps
)

// Evaluate pushes p through the prerouting hook (filter chains, then NAT), then through
// input when it is for the host, or forward when a DNAT sent it elsewhere.
func (rs *Ruleset) Evaluate(p Packet, env Env) Result {
	e := &evaluator{rs: rs, env: env, index: make(map[chainKey]*Chain, len(rs.Chains))}
	for _, c := range rs.Chains {
		e.index[chainKey{c.Origin, c.Family, c.Table, c.Name}] = c
	}
	start := state{pkt: pktState{
		family: p.Family, proto: p.Proto, daddr: p.DAddr, dport: p.DPort,
		iif: p.IIf, oifKnown: true, markKnown: true,
	}}
	var out []Outcome
	passed, final := e.hook(HookPrerouting, []state{start})
	out = append(out, final...)
	var local, fwd []state
	for _, s := range passed {
		switch {
		case s.lost:
			out = append(out, s.outcome(false, true))
		case !s.pkt.dnat || env.IsLocal(s.pkt.daddr):
			local = append(local, s)
		default:
			s.pkt.oif, s.pkt.oifKnown = env.Route(s.pkt.daddr)
			s.pkt.forwarded = true
			fwd = append(fwd, s)
		}
	}
	for _, h := range []struct {
		hook Hook
		in   []state
	}{{HookInput, local}, {HookForward, fwd}} {
		if len(h.in) == 0 {
			continue
		}
		passed, final := e.hook(h.hook, h.in)
		out = append(out, final...)
		for _, s := range passed {
			out = append(out, s.outcome(true, false))
		}
	}
	return Result{Outcomes: dedupeOutcomes(out), Truncated: e.truncated}
}

// pktState is the packet as the rules see it; comparable, so paths can be deduplicated.
type pktState struct {
	family          Family
	proto           string
	daddr           netip.Addr
	dport           uint16
	iif, oif        string
	oifKnown        bool
	mark            uint32
	markKnown       bool
	dnat, forwarded bool
}

// state is one path through the rules.
type state struct {
	pkt pktState
	// origin and where: the last filter chain that accepted the packet, on hook
	// whereHook.
	origin, where string
	whereHook     Hook
	// maybe is a sorted, comma-joined list of undecidable expressions on this path.
	maybe string
	// notes is a sorted, comma-joined list of decided facts worth telling (a rate limit
	// the first packet passes, an accept only for listed sources).
	notes string
	// lost: a NAT target the model cannot read rewrote the destination.
	lost bool
}

func (s state) withMaybe(reason string) state {
	s.maybe = addToList(s.maybe, reason)
	return s
}

func (s state) withNote(note string) state {
	s.notes = addToList(s.notes, note)
	return s
}

// addToList adds item to a sorted, comma-joined list.
func addToList(list, item string) string {
	if item == "" {
		return list
	}
	parts := strings.Split(list, ",")
	if list == "" {
		parts = nil
	}
	if !slices.Contains(parts, item) {
		parts = append(parts, item)
		slices.Sort(parts)
	}
	return strings.Join(parts, ",")
}

func (s state) outcome(accept, undecidable bool) Outcome {
	o := Outcome{
		Accept: accept, Forwarded: s.pkt.forwarded, DAddr: s.pkt.daddr, DPort: s.pkt.dport,
		Origin: s.origin, Where: s.where, Undecidable: undecidable,
	}
	if s.maybe != "" {
		o.Maybe = strings.Split(s.maybe, ",")
	}
	if s.notes != "" {
		o.Notes = strings.Split(s.notes, ",")
	}
	return o
}

type evaluator struct {
	rs        *Ruleset
	env       Env
	index     map[chainKey]*Chain
	truncated bool
	// base is the base chain being evaluated: regular chains it jumps to take its type
	// (a dnat in a chain reached from a NAT base chain ends that evaluation).
	base *Chain
}

// acceptedBy reports whether a policy accept in c should become the path's accept
// location: when none is recorded, the recorded one is from an earlier hook, or it was
// itself a policy. An explicit accept rule on the same hook is kept.
func (s state) acceptedBy(c *Chain) state {
	if s.where == "" || s.whereHook != c.Hook || strings.HasPrefix(s.where, "policy ") {
		s.origin, s.where, s.whereHook = c.Origin, "policy "+c.Where(), c.Hook
	}
	return s
}

// terminal is a path that ended in a chain with a verdict.
type terminal struct {
	s    state
	kind VerdictKind // Accept, Drop or Queue
	c    *Chain
}

// hook runs every base chain on h, by priority. A packet must be accepted by each one
// it meets; it returns the paths every chain accepted and the outcomes of those dropped.
func (e *evaluator) hook(h Hook, in []state) (passed []state, final []Outcome) {
	var chains []*Chain
	for _, c := range e.rs.Chains {
		if c.Hook == h {
			chains = append(chains, c)
		}
	}
	slices.SortStableFunc(chains, func(a, b *Chain) int {
		return cmp.Or(cmp.Compare(a.Prio, b.Prio), cmp.Compare(a.Origin, b.Origin), cmp.Compare(a.Table, b.Table))
	})
	live := in
	for _, c := range chains {
		var seen, skip []state
		for _, s := range live {
			if c.Family.covers(s.pkt.family) {
				seen = append(seen, s)
			} else {
				skip = append(skip, s)
			}
		}
		if len(seen) == 0 {
			continue
		}
		e.base = c
		terms, through := e.chain(c, seen, 0)
		next := skip
		for _, t := range terms {
			switch t.kind {
			case VerdictAccept:
				next = append(next, t.s)
			case VerdictQueue:
				final = append(final, t.s.outcome(false, true))
			default:
				final = append(final, t.s.outcome(false, false))
			}
		}
		for _, s := range through {
			if c.Policy == VerdictDrop {
				s.origin, s.where = c.Origin, "policy "+c.Where()
				final = append(final, s.outcome(false, false))
				continue
			}
			if c.Type != TypeNAT {
				s = s.acceptedBy(c)
			}
			next = append(next, s)
		}
		live = e.dedupe(next)
	}
	return live, final
}

// chain runs the rules of c over every path in, returning the paths that ended with a
// verdict and those that fell off the end or returned.
func (e *evaluator) chain(c *Chain, in []state, depth int) (terms []terminal, through []state) {
	if depth > maxDepth {
		e.truncated = true
		return nil, nil
	}
	live := in
	var returned []state
	for i := range c.Rules {
		var next []state
		for _, s := range live {
			t, n, r := e.rule(c, &c.Rules[i], s, depth)
			terms = append(terms, t...)
			next = append(next, n...)
			returned = append(returned, r...)
		}
		live = e.dedupe(next)
		if len(live) == 0 {
			break
		}
	}
	return terms, e.dedupe(append(live, returned...))
}

// rule evaluates one rule for one path. It returns the paths that ended with a verdict,
// those that go on to the next rule, and those that returned from the chain.
func (e *evaluator) rule(c *Chain, r *Rule, s state, depth int) (terms []terminal, next, returned []state) {
	cur := []state{s}
	for i, x := range r.Exprs {
		if len(cur) == 0 {
			return terms, next, returned
		}
		switch x := x.(type) {
		case Match:
			var keep []state
			for _, st := range cur {
				switch m, why := x.eval(st.pkt, e.env); m {
				case yes:
					keep = append(keep, st.withNote(x.Note))
				case no:
					if x.Field == FieldSAddr && x.Op == OpEq && e.wouldAccept(r.Exprs[i+1:], st.pkt) {
						st = st.withNote("source-restricted:" + c.Where())
					}
					next = append(next, st)
				default:
					keep = append(keep, st.withMaybe(why).withNote(x.Note))
					next = append(next, st.withMaybe(why))
				}
			}
			cur = keep
		case Mark:
			for i := range cur {
				if x.Unknown {
					cur[i].pkt.markKnown = false
				} else {
					cur[i].pkt.mark = (cur[i].pkt.mark &^ x.Clear) ^ x.Xor
				}
			}
		case NAT:
			if x.Kind == NATOther {
				continue
			}
			for i := range cur {
				applyNAT(&cur[i], x, e.env)
			}
			if e.base.Type == TypeNAT {
				for _, st := range cur {
					terms = append(terms, terminal{st, VerdictAccept, c})
				}
				return terms, next, returned
			}
		case VMap:
			if x.Unknown != "" {
				// A verdict map the model cannot read: it may decide the packet's fate
				// (undecidable) or match nothing and fall through.
				for i := range cur {
					cur[i] = cur[i].withMaybe(x.Unknown)
					st := cur[i]
					st.origin, st.where = c.Origin, c.Where()
					terms = append(terms, terminal{st, VerdictQueue, c})
				}
				continue
			}
			var rest []state
			for _, st := range cur {
				pending := []state{st}
				for _, el := range x.Elems {
					var unmatched []state
					for _, ps := range pending {
						switch m, why := el.Match.eval(ps.pkt, e.env); m {
						case yes:
							t, n, rt := e.verdict(c, el.Verdict, ps, depth)
							terms, next, returned = append(terms, t...), append(next, n...), append(returned, rt...)
						case no:
							unmatched = append(unmatched, ps)
						default:
							t, n, rt := e.verdict(c, el.Verdict, ps.withMaybe(why), depth)
							terms, next, returned = append(terms, t...), append(next, n...), append(returned, rt...)
							unmatched = append(unmatched, ps.withMaybe(why))
						}
					}
					pending = unmatched
				}
				rest = append(rest, pending...)
			}
			cur = rest
		case Verdict:
			for _, st := range cur {
				t, n, rt := e.verdict(c, x, st, depth)
				terms, next, returned = append(terms, t...), append(next, n...), append(returned, rt...)
			}
			return terms, next, returned
		}
	}
	return terms, append(next, cur...), returned
}

// wouldAccept reports whether the rest of a rule, whose source match just failed, would
// otherwise accept the packet: no remaining match says no and it ends in accept.
func (e *evaluator) wouldAccept(rest []Expr, p pktState) bool {
	for _, x := range rest {
		switch x := x.(type) {
		case Match:
			if m, _ := x.eval(p, e.env); m == no {
				return false
			}
		case Verdict:
			return x.Kind == VerdictAccept
		}
	}
	return false
}

func (e *evaluator) verdict(c *Chain, v Verdict, s state, depth int) (terms []terminal, next, returned []state) {
	switch v.Kind {
	case VerdictContinue:
		return nil, []state{s}, nil
	case VerdictAccept:
		if e.base.Type != TypeNAT {
			s.origin, s.where, s.whereHook = c.Origin, c.Where(), e.base.Hook
		}
		return []terminal{{s, VerdictAccept, c}}, nil, nil
	case VerdictDrop:
		s.origin, s.where = c.Origin, c.Where()
		return []terminal{{s, VerdictDrop, c}}, nil, nil
	case VerdictQueue:
		s.origin, s.where = c.Origin, c.Where()
		return []terminal{{s.withMaybe("queue"), VerdictQueue, c}}, nil, nil
	case VerdictReturn:
		return nil, nil, []state{s}
	case VerdictJump, VerdictGoto:
		target := e.index[chainKey{c.Origin, c.Family, c.Table, v.Target}]
		if target == nil {
			// A jump to a chain the dump does not have: nothing to follow.
			s = s.withMaybe("missing chain " + v.Target)
			return []terminal{{s, VerdictQueue, c}}, nil, nil
		}
		terms, through := e.chain(target, []state{s}, depth+1)
		if v.Kind == VerdictJump {
			return terms, through, nil
		}
		return terms, nil, through
	}
	return nil, []state{s}, nil
}

func applyNAT(s *state, n NAT, env Env) {
	if n.Unknown != "" {
		*s = s.withMaybe(n.Unknown)
		s.lost = true
		return
	}
	if n.Kind == NATDnat && n.Addr.IsValid() {
		s.pkt.daddr = n.Addr.Unmap()
	}
	if n.Port != 0 {
		s.pkt.dport = n.Port
	}
	s.pkt.dnat = true
	if n.Kind == NATRedirect {
		// Redirect delivers to the host itself: keep a local destination.
		if !env.IsLocal(s.pkt.daddr) {
			s.lost = true
			*s = s.withMaybe("redirect")
		}
	}
}

// dedupe drops identical paths, keeping order, and flags truncation past the bound.
func (e *evaluator) dedupe(in []state) []state {
	if len(in) < 2 {
		return in
	}
	seen := make(map[state]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) > maxStates {
		e.truncated = true
		out = out[:maxStates]
	}
	return out
}

func dedupeOutcomes(in []Outcome) []Outcome {
	var out []Outcome
	for _, o := range in {
		if !slices.ContainsFunc(out, func(p Outcome) bool { return outcomeEqual(o, p) }) {
			out = append(out, o)
		}
	}
	return out
}

func outcomeEqual(a, b Outcome) bool {
	return a.Accept == b.Accept && a.Forwarded == b.Forwarded && a.DAddr == b.DAddr && a.DPort == b.DPort &&
		a.Origin == b.Origin && a.Where == b.Where && a.Undecidable == b.Undecidable &&
		slices.Equal(a.Maybe, b.Maybe) && slices.Equal(a.Notes, b.Notes)
}

// tri is a three-valued match result.
type tri int

const (
	no tri = iota
	yes
	maybe
)

func boolTri(b bool) tri {
	if b {
		return yes
	}
	return no
}

// eval decides the match for a packet; on maybe it also says why.
func (m Match) eval(p pktState, env Env) (tri, string) {
	in, why := m.contains(p, env)
	if in == maybe || m.Op == OpEq {
		return in, why
	}
	// OpNe: a field the packet does not have (a tcp port on a udp packet, an ip6 address
	// on an ipv4 packet) fails either way, as nftables' implicit protocol dependency does.
	if !m.applies(p) {
		return no, ""
	}
	if in == yes {
		return no, ""
	}
	return yes, ""
}

// applies reports whether the packet has the field at all.
func (m Match) applies(p pktState) bool {
	switch m.Field {
	case FieldDPort, FieldSPort:
		return m.Proto == "" || m.Proto == p.proto
	case FieldSAddr, FieldDAddr, FieldL4Proto:
		return m.Family == 0 || m.Family == p.family
	case FieldTCPFlags:
		return p.proto == "tcp"
	}
	return true
}

// contains decides whether the packet's field is in the match's set.
func (m Match) contains(p pktState, env Env) (tri, string) {
	if !m.applies(p) {
		return no, ""
	}
	switch m.Field {
	case FieldL4Proto:
		return boolTri(slices.Contains(m.Names, p.proto)), ""
	case FieldDPort:
		return boolTri(portIn(m.Ports, p.dport)), ""
	case FieldSPort:
		return maybe, "source port"
	case FieldSAddr:
		// Anyone: an outside address in no listed prefix, unless one covers everything.
		for _, pfx := range m.Pfx {
			if pfx.Bits() == 0 {
				return yes, ""
			}
		}
		for _, r := range m.Ranges {
			if r.Lo.IsUnspecified() && (r.Hi == netip.MustParseAddr("255.255.255.255") || r.Hi == maxIPv6) {
				return yes, ""
			}
		}
		return no, ""
	case FieldDAddr:
		for _, pfx := range m.Pfx {
			if pfx.Contains(p.daddr) {
				return yes, ""
			}
		}
		for _, r := range m.Ranges {
			if r.Lo.Compare(p.daddr) <= 0 && p.daddr.Compare(r.Hi) <= 0 {
				return yes, ""
			}
		}
		return no, ""
	case FieldIIf:
		return boolTri(slices.ContainsFunc(m.Names, func(g string) bool { return globMatch(g, p.iif) })), ""
	case FieldOIf:
		if !p.oifKnown {
			return maybe, "output interface"
		}
		return boolTri(slices.ContainsFunc(m.Names, func(g string) bool { return globMatch(g, p.oif) })), ""
	case FieldCtState:
		states := []string{"new"}
		if p.dnat {
			states = append(states, "dnat")
		}
		return boolTri(slices.ContainsFunc(m.Names, func(n string) bool { return slices.Contains(states, n) })), ""
	case FieldNFProto:
		name := "ipv4"
		if p.family == FamilyIP6 {
			name = "ipv6"
		}
		return boolTri(slices.Contains(m.Names, name)), ""
	case FieldDAddrType:
		return addrTypeIn(m.Names, p.daddr, env)
	case FieldTCPFlags:
		// The first packet of a new TCP connection carries SYN alone.
		const flags = tcpSYN
		if m.Any {
			return boolTri(flags&m.Mark != 0), ""
		}
		return boolTri(flags&m.Mask == m.Mark&m.Mask), ""
	case FieldAlways:
		return yes, ""
	case FieldMark:
		if !p.markKnown {
			return maybe, "mark"
		}
		return boolTri(p.mark&m.Mask == m.Mark&m.Mask), ""
	}
	return maybe, m.Unknown
}

var maxIPv6 = netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

func portIn(ranges []PortRange, port uint16) bool {
	for _, r := range ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// addrTypeIn decides fib daddr type / addrtype --dst-type for a unicast destination.
func addrTypeIn(types []string, addr netip.Addr, env Env) (tri, string) {
	result := no
	for _, t := range types {
		switch strings.ToLower(t) {
		case "local":
			if env.IsLocal(addr) {
				return yes, ""
			}
		case "unicast":
			return yes, ""
		case "multicast", "broadcast", "anycast", "blackhole", "unreachable", "prohibit", "nat", "xresolve", "throw":
		default:
			result = maybe
		}
	}
	if result == maybe {
		return maybe, "address type"
	}
	return no, ""
}
