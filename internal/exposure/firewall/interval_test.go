package firewall

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

// outcomeText renders an outcome for golden comparisons:
// "accept fwd 172.17.0.2-172.17.0.4:80 orig=30000-30999 kept" .
func outcomeText(o Outcome) string {
	verdict := "drop"
	if o.Accept {
		verdict = "accept"
	}
	if o.Undecidable {
		verdict = "undecidable"
	}
	where := "local"
	if o.Forwarded {
		where = "fwd"
	}
	a := o.DAddr.String()
	if o.DAddrHi.IsValid() {
		a += "-" + o.DAddrHi.String()
	}
	p := fmt.Sprint(o.DPort)
	if o.DPortHi != 0 {
		p += fmt.Sprintf("-%d", o.DPortHi)
	}
	s := fmt.Sprintf("%s %s %s:%s", verdict, where, a, p)
	if o.Ranged {
		s += fmt.Sprintf(" orig=%d-%d", o.OrigPort, o.OrigPortHi)
		if o.PortKept {
			s += " kept"
		}
	}
	return s
}

func outcomeTexts(r Result) []string {
	var out []string
	for _, o := range r.Outcomes {
		out = append(out, outcomeText(o))
	}
	slices.Sort(out)
	return out
}

// natRanges is a NAT prerouting chain with one rule per case and a forward chain that
// drops by default and accepts only 172.17.0.2-172.17.0.3 and port 80 or 8000-8049.
func natRanges(rules ...Rule) *Ruleset {
	pre := &Chain{Origin: "nft", Family: FamilyIP, Table: "nat", Name: "pre", Hook: HookPrerouting, Type: TypeNAT, Prio: -100, Policy: VerdictAccept, Rules: rules}
	fwd := &Chain{Origin: "nft", Family: FamilyIP, Table: "filter", Name: "fwd", Hook: HookForward, Policy: VerdictDrop, Rules: []Rule{
		rule(Match{Field: FieldDAddr, Family: FamilyIP, Ranges: []AddrRange{{netip.MustParseAddr("172.17.0.2"), netip.MustParseAddr("172.17.0.3")}}},
			Match{Field: FieldDPort, Ports: []PortRange{{80, 80}, {8000, 8049}}}, accept()),
	}}
	in := &Chain{Origin: "nft", Family: FamilyIP, Table: "filter", Name: "in", Hook: HookInput, Policy: VerdictDrop, Rules: []Rule{
		rule(Match{Field: FieldDPort, Ports: []PortRange{{9000, 9049}}}, accept()),
	}}
	return &Ruleset{Chains: []*Chain{pre, fwd, in}}
}

func rangedPkt(lo, hi uint16) Packet {
	p := pkt("tcp", lo)
	p.DPortHi = hi
	return p
}

func TestEvaluateDNATToAddressRange(t *testing.T) {
	rs := natRanges(rule(dport("tcp", 18080), NAT{Kind: NATDnat, Addr: netip.MustParseAddr("172.17.0.1"), AddrHi: netip.MustParseAddr("172.17.0.4"), Port: 80}))
	r := decide(t, rs, pkt("tcp", 18080))
	// The range is cut where the forward rule's address range starts and ends.
	want := []string{"accept fwd 172.17.0.2-172.17.0.3:80", "drop fwd 172.17.0.1:80", "drop fwd 172.17.0.4:80"}
	if got := outcomeTexts(r); !slices.Equal(got, want) {
		t.Fatalf("outcomes\n got  %q\n want %q", got, want)
	}
	if r.Decision() != Undetermined {
		t.Fatalf("some backends accept, some drop: %v", r.Decision())
	}
}

func TestEvaluateDNATToPortRange(t *testing.T) {
	ctr := netip.MustParseAddr("172.17.0.2")
	keep := NAT{Kind: NATDnat, Addr: ctr, Port: 8000, PortHi: 8099}
	cases := []struct {
		name string
		nat  NAT
		p    Packet
		want []string
	}{
		// A port inside the range is kept: 8010 stays 8010, inside the accepted 8000-8049.
		{"kept inside", keep, pkt("tcp", 8010), []string{"accept fwd 172.17.0.2:8010"}},
		// A port outside it may become any port of the range: 8000-8049 accepted, the rest not.
		{"outside", keep, pkt("tcp", 7000), []string{"accept fwd 172.17.0.2:8000-8049", "drop fwd 172.17.0.2:8050-8099"}},
		// random: any port of the range, even for a port inside it.
		{"random", NAT{Kind: NATDnat, Addr: ctr, Port: 8000, PortHi: 8099, Random: true}, pkt("tcp", 8010),
			[]string{"accept fwd 172.17.0.2:8000-8049", "drop fwd 172.17.0.2:8050-8099"}},
		// A ranged packet: 7990-8099 port-preserving into 8000-8099; 7990-7999 lie outside.
		{"ranged", keep, rangedPkt(7990, 8099), []string{
			"accept fwd 172.17.0.2:8000-8049 orig=7990-7999",
			"accept fwd 172.17.0.2:8000-8049 orig=8000-8049 kept",
			"drop fwd 172.17.0.2:8050-8099 orig=7990-7999",
			"drop fwd 172.17.0.2:8050-8099 orig=8050-8099 kept",
		}},
		// Redirect to a port range on the host: kept inside 9000-9099, accepted 9000-9049.
		{"redirect", NAT{Kind: NATRedirect, Port: 9000, PortHi: 9099}, rangedPkt(9040, 9059), []string{
			"accept local 192.0.2.10:9040-9049 orig=9040-9049 kept",
			"drop local 192.0.2.10:9050-9059 orig=9050-9059 kept",
		}},
	}
	for _, c := range cases {
		rs := natRanges(rule(Match{Field: FieldDPort, Proto: "tcp", Ports: []PortRange{{1, 65535}}}, c.nat))
		if got := outcomeTexts(decide(t, rs, c.p)); !slices.Equal(got, c.want) {
			t.Errorf("%s: outcomes\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

// A packet standing for a whole 30000-39999 range is split only where rules tell its
// ports apart, never port by port.
func TestEvaluateRangedPacketSplitsAtRuleBoundaries(t *testing.T) {
	ctr := netip.MustParseAddr("172.17.0.2")
	rs := natRanges(
		rule(Match{Field: FieldDPort, Proto: "tcp", Ports: []PortRange{{30000, 30999}}}, NAT{Kind: NATDnat, Addr: ctr, Port: 80}),
		rule(Match{Field: FieldDPort, Proto: "tcp", Ports: []PortRange{{31000, 39999}}}, NAT{Kind: NATDnat, Addr: ctr}),
	)
	r := decide(t, rs, rangedPkt(30000, 39999))
	want := []string{
		"accept fwd 172.17.0.2:80 orig=30000-30999",
		"drop fwd 172.17.0.2:31000-39999 orig=31000-39999 kept",
	}
	if got := outcomeTexts(r); !slices.Equal(got, want) {
		t.Fatalf("outcomes\n got  %q\n want %q", got, want)
	}
	if r.Truncated {
		t.Fatal("truncated")
	}
	// The whole port space at once, against the forward chain's few boundaries.
	r = decide(t, rs, rangedPkt(1, 65535))
	if r.Truncated || len(r.Outcomes) > 8 {
		t.Fatalf("%d outcomes, truncated %v: %q", len(r.Outcomes), r.Truncated, outcomeTexts(r))
	}
}

// A ranged destination is cut at the host's address boundaries before the routing
// questions are asked: part of a DNAT range that is the host itself is delivered
// locally, the rest is forwarded.
func TestEvaluateAddressRangeAcrossHostAddress(t *testing.T) {
	env := testEnv()
	env.AddrCuts = []netip.Addr{hostAddr, hostAddr.Next()}
	rs := natRanges(rule(dport("tcp", 9010), NAT{Kind: NATDnat, Addr: netip.MustParseAddr("192.0.2.9"), AddrHi: netip.MustParseAddr("192.0.2.11")}))
	got := outcomeTexts(rs.Evaluate(pkt("tcp", 9010), env))
	want := []string{"accept local 192.0.2.10:9010", "drop fwd 192.0.2.11:9010", "drop fwd 192.0.2.9:9010"}
	if !slices.Equal(got, want) {
		t.Fatalf("outcomes\n got  %q\n want %q", got, want)
	}
}

func TestEvaluateNumgenPick(t *testing.T) {
	ep := func(name, addr string) *Chain {
		return &Chain{Origin: "nft", Family: FamilyIP, Table: "kube-proxy", Name: name, Rules: []Rule{
			rule(Match{Field: FieldL4Proto, Names: []string{"tcp"}}, NAT{Kind: NATDnat, Addr: netip.MustParseAddr(addr), Port: 80}),
		}}
	}
	vm := VMap{Key: Match{Field: FieldAlways}, Pick: true, PickAll: true, Elems: []VMapElem{
		{Match: Match{Field: FieldAlways}, Verdict: Verdict{Kind: VerdictGoto, Target: "ep-a"}},
		{Match: Match{Field: FieldAlways}, Verdict: Verdict{Kind: VerdictGoto, Target: "ep-b"}},
	}}
	pre := &Chain{Origin: "nft", Family: FamilyIP, Table: "kube-proxy", Name: "pre", Hook: HookPrerouting, Type: TypeNAT, Policy: VerdictAccept,
		Rules: []Rule{rule(dport("tcp", 30080), vm)}}
	in := &Chain{Origin: "nft", Family: FamilyIP, Table: "f", Name: "in", Hook: HookInput, Policy: VerdictAccept}
	rs := &Ruleset{Chains: []*Chain{pre, ep("ep-a", "172.17.0.2"), ep("ep-b", "172.17.0.3"), in}}
	want := []string{"accept fwd 172.17.0.2:80", "accept fwd 172.17.0.3:80"}
	if got := outcomeTexts(decide(t, rs, pkt("tcp", 30080))); !slices.Equal(got, want) {
		t.Fatalf("every element and no fall-through\n got  %q\n want %q", got, want)
	}
	vm.PickAll = false
	pre.Rules[0] = rule(dport("tcp", 30080), vm)
	want = append(want, "accept local 192.0.2.10:30080")
	if got := outcomeTexts(decide(t, rs, pkt("tcp", 30080))); !slices.Equal(got, want) {
		t.Fatalf("a value no element covers falls through\n got  %q\n want %q", got, want)
	}
}

func TestSplitHelpers(t *testing.T) {
	if got := portCuts([]PortRange{{80, 80}, {8000, 8049}, {1, 0}, {65000, 65535}}); !slices.Equal(got, []uint16{80, 81, 8000, 8050, 65000}) {
		t.Errorf("portCuts: %v", got)
	}
	m := Match{Field: FieldDAddr, Pfx: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/30")}, Ranges: []AddrRange{{netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.9")}}}
	var got []string
	for _, a := range addrCuts(m) {
		got = append(got, a.String())
	}
	if !slices.Equal(got, []string{"10.0.0.0", "10.0.0.4", "10.0.0.9", "10.0.0.10"}) {
		t.Errorf("addrCuts: %v", got)
	}
	for p, want := range map[string]string{"10.0.0.0/30": "10.0.0.3", "10.1.2.3/16": "10.1.255.255", "fd00::/120": "fd00::ff", "0.0.0.0/0": "255.255.255.255"} {
		if got := LastAddr(netip.MustParsePrefix(p)).String(); got != want {
			t.Errorf("LastAddr(%s) = %s, want %s", p, got, want)
		}
	}
}
