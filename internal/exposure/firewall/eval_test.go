package firewall

import (
	"net/netip"
	"slices"
	"testing"
)

var (
	hostAddr = netip.MustParseAddr("192.0.2.10")
	ctrAddr  = netip.MustParseAddr("172.17.0.2")
)

func testEnv() Env {
	return Env{
		IsLocal: func(a netip.Addr) bool { return a == hostAddr || a.IsLoopback() },
		Route: func(a netip.Addr) (string, bool) {
			if netip.MustParsePrefix("172.17.0.0/16").Contains(a) {
				return "docker0", true
			}
			return "", false
		},
	}
}

func pkt(proto string, port uint16) Packet {
	return Packet{Family: FamilyIP, Proto: proto, DAddr: hostAddr, DPort: port, IIf: "eth0"}
}

func dport(proto string, ports ...uint16) Match {
	m := Match{Field: FieldDPort, Proto: proto}
	for _, p := range ports {
		m.Ports = append(m.Ports, PortRange{p, p})
	}
	return m
}

func accept() Verdict { return Verdict{Kind: VerdictAccept} }
func drop() Verdict   { return Verdict{Kind: VerdictDrop} }

func rule(exprs ...Expr) Rule { return Rule{Exprs: exprs} }

func base(name string, hook Hook, prio int, policy VerdictKind, rules ...Rule) *Chain {
	return &Chain{Origin: "nft", Family: FamilyInet, Table: "filter", Name: name, Hook: hook, Prio: prio, Policy: policy, Rules: rules}
}

func regular(name string, rules ...Rule) *Chain {
	return &Chain{Origin: "nft", Family: FamilyInet, Table: "filter", Name: name, Rules: rules}
}

func decide(t *testing.T, rs *Ruleset, p Packet) Result {
	t.Helper()
	return rs.Evaluate(p, testEnv())
}

func TestEvaluateDecisions(t *testing.T) {
	ctNew := Match{Field: FieldCtState, Names: []string{"established", "related"}}
	input := base("input", HookInput, 0, VerdictDrop,
		rule(ctNew, accept()),
		rule(Match{Field: FieldIIf, Names: []string{"lo"}}, accept()),
		rule(dport("tcp", 22, 443), accept()),
		rule(Match{Field: FieldDPort, Proto: "tcp", Ports: []PortRange{{9000, 9100}}}, accept()),
		rule(Match{Field: FieldSAddr, Family: FamilyIP, Pfx: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, dport("tcp", 5432), accept()),
		rule(Match{Field: FieldSAddr, Op: OpNe, Family: FamilyIP, Pfx: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, dport("tcp", 3306), drop()),
		rule(dport("tcp", 3306), accept()),
		rule(Match{Field: FieldIIf, Names: []string{"eth*"}}, dport("tcp", 8000), accept()),
		rule(dport("tcp", 7000), Match{Field: FieldUnknown, Unknown: "limit"}, accept()),
		rule(dport("", 7100), accept()),
		rule(dport("udp", 51820), accept()),
		rule(Match{Field: FieldSAddr, Family: FamilyIP6, Pfx: []netip.Prefix{netip.MustParsePrefix("fe80::/10")}}, dport("udp", 546), accept()),
		rule(Verdict{Kind: VerdictJump, Target: "extra"}),
		rule(dport("tcp", 8100), drop()),
	)
	extra := regular("extra",
		rule(dport("tcp", 8200), accept()),
		rule(dport("tcp", 8300), Verdict{Kind: VerdictReturn}),
		rule(dport("udp", 8400), Verdict{Kind: VerdictGoto, Target: "extra_udp"}),
	)
	extraUDP := regular("extra_udp", rule(accept()))
	rs := &Ruleset{Chains: []*Chain{input, extra, extraUDP}}

	cases := []struct {
		proto string
		port  uint16
		want  Decision
	}{
		{"tcp", 22, Open},
		{"tcp", 443, Open},
		{"tcp", 80, Closed},
		{"tcp", 9050, Open},
		{"tcp", 5432, Closed},       // only from 10/8
		{"tcp", 3306, Closed},       // != 10/8 drop catches anyone
		{"tcp", 8000, Open},         // eth* glob
		{"tcp", 7000, Undetermined}, // rate limited
		{"tcp", 7100, Open},         // th dport
		{"udp", 7100, Open},
		{"udp", 51820, Open},
		{"tcp", 51820, Closed},
		{"udp", 546, Closed}, // ip6 saddr rule never matches an ipv4 packet, and not anyone
		{"tcp", 8200, Open},  // via jump
		{"tcp", 8300, Closed},
		{"udp", 8400, Open}, // goto
		{"tcp", 8100, Closed},
	}
	for _, c := range cases {
		r := decide(t, rs, pkt(c.proto, c.port))
		if got := r.Decision(); got != c.want {
			t.Errorf("%s/%d: got %v, want %v (%+v)", c.proto, c.port, got, c.want, r.Outcomes)
		}
	}

	r := decide(t, rs, pkt("tcp", 7000))
	if got := r.MaybeReasons(); !slices.Equal(got, []string{"limit"}) {
		t.Errorf("maybe reasons: %v", got)
	}
	r = decide(t, rs, pkt("tcp", 22))
	if o := r.Outcomes[0]; o.Where != "inet filter input" || o.Origin != "nft" {
		t.Errorf("accept location: %+v", o)
	}
	r = decide(t, rs, pkt("tcp", 80))
	if o := r.Outcomes[0]; o.Where != "policy inet filter input" {
		t.Errorf("drop location: %+v", o)
	}
}

func TestEvaluateNoFilterIsOpen(t *testing.T) {
	r := decide(t, &Ruleset{}, pkt("tcp", 80))
	if r.Decision() != Open || r.Outcomes[0].Where != "" {
		t.Fatalf("empty ruleset: %+v", r)
	}
	rs := &Ruleset{Chains: []*Chain{base("input", HookInput, 0, VerdictAccept)}}
	r = decide(t, rs, pkt("tcp", 80))
	if r.Decision() != Open || r.Outcomes[0].Where != "policy inet filter input" {
		t.Fatalf("accept policy: %+v", r)
	}
}

func TestEvaluateEveryBaseChainMustAccept(t *testing.T) {
	first := base("a", HookInput, -10, VerdictAccept, rule(dport("tcp", 80), accept()))
	second := base("b", HookInput, 0, VerdictAccept, rule(dport("tcp", 80), drop()))
	second.Table = "other"
	rs := &Ruleset{Chains: []*Chain{second, first}}
	if got := decide(t, rs, pkt("tcp", 80)).Decision(); got != Closed {
		t.Fatalf("accept in one base chain must not override a drop in another: %v", got)
	}
	if got := decide(t, rs, pkt("tcp", 81)).Decision(); got != Open {
		t.Fatalf("81: %v", got)
	}
}

func TestEvaluateFamilies(t *testing.T) {
	v4only := base("input", HookInput, 0, VerdictDrop)
	v4only.Family = FamilyIP
	rs := &Ruleset{Chains: []*Chain{v4only}}
	if got := decide(t, rs, pkt("tcp", 80)).Decision(); got != Closed {
		t.Fatalf("v4: %v", got)
	}
	p6 := Packet{Family: FamilyIP6, Proto: "tcp", DAddr: netip.MustParseAddr("2001:db8::1"), DPort: 80, IIf: "eth0"}
	if got := decide(t, rs, p6).Decision(); got != Open {
		t.Fatalf("an ip table must not judge ipv6: %v", got)
	}
}

// dockerLike is Docker's iptables layout: DNAT in nat PREROUTING, accept in filter
// FORWARD's DOCKER chain, and a host INPUT that drops everything (ufw default deny).
func dockerLike() *Ruleset {
	nat := &Chain{Origin: "iptables", Family: FamilyIP, Table: "nat", Name: "PREROUTING", Hook: HookPrerouting, Type: TypeNAT, Prio: -100, Policy: VerdictAccept,
		Rules: []Rule{rule(Match{Field: FieldDAddrType, Names: []string{"LOCAL"}}, Verdict{Kind: VerdictJump, Target: "DOCKER"})}}
	natDocker := &Chain{Origin: "iptables", Family: FamilyIP, Table: "nat", Name: "DOCKER", Rules: []Rule{
		rule(Match{Field: FieldIIf, Op: OpNe, Names: []string{"docker0"}}, dport("tcp", 18080), NAT{Kind: NATDnat, Addr: ctrAddr, Port: 80}),
	}}
	input := &Chain{Origin: "iptables", Family: FamilyIP, Table: "filter", Name: "INPUT", Hook: HookInput, Policy: VerdictDrop}
	fwd := &Chain{Origin: "iptables", Family: FamilyIP, Table: "filter", Name: "FORWARD", Hook: HookForward, Policy: VerdictDrop,
		Rules: []Rule{rule(Match{Field: FieldOIf, Names: []string{"docker0"}}, Verdict{Kind: VerdictJump, Target: "DOCKER"})}}
	fwdDocker := &Chain{Origin: "iptables", Family: FamilyIP, Table: "filter", Name: "DOCKER", Rules: []Rule{
		rule(Match{Field: FieldDAddr, Family: FamilyIP, Pfx: []netip.Prefix{netip.PrefixFrom(ctrAddr, 32)}}, Match{Field: FieldIIf, Op: OpNe, Names: []string{"docker0"}},
			Match{Field: FieldOIf, Names: []string{"docker0"}}, dport("tcp", 80), accept()),
		rule(Match{Field: FieldIIf, Op: OpNe, Names: []string{"docker0"}}, Match{Field: FieldOIf, Names: []string{"docker0"}}, drop()),
	}}
	return &Ruleset{Chains: []*Chain{nat, natDocker, input, fwd, fwdDocker}}
}

func TestEvaluateDNATGoesThroughForward(t *testing.T) {
	r := decide(t, dockerLike(), pkt("tcp", 18080))
	if r.Decision() != Open {
		t.Fatalf("published port: %+v", r)
	}
	o := r.Outcomes[0]
	if !o.Forwarded || o.DAddr != ctrAddr || o.DPort != 80 || o.Where != "ip filter DOCKER" || o.Origin != "iptables" {
		t.Fatalf("outcome: %+v", o)
	}
	if got := decide(t, dockerLike(), pkt("tcp", 18081)).Decision(); got != Closed {
		t.Fatalf("unpublished port reaches INPUT's drop policy: %v", got)
	}
}

func TestEvaluateStatisticForksToEveryEndpoint(t *testing.T) {
	sep := func(name string, addr string) *Chain {
		return &Chain{Origin: "iptables", Family: FamilyIP, Table: "nat", Name: name, Rules: []Rule{
			rule(Verdict{Kind: VerdictJump, Target: "MARK-MASQ"}),
			rule(dport("tcp"), NAT{Kind: NATDnat, Addr: netip.MustParseAddr(addr), Port: 8080}),
		}}
	}
	// dport("tcp") with no ports never matches: replace with a protocol match.
	a, b := sep("SEP-A", "172.17.0.9"), sep("SEP-B", "172.17.0.10")
	for _, c := range []*Chain{a, b} {
		c.Rules[1].Exprs[0] = Match{Field: FieldL4Proto, Names: []string{"tcp"}}
	}
	pre := &Chain{Origin: "iptables", Family: FamilyIP, Table: "nat", Name: "PREROUTING", Hook: HookPrerouting, Type: TypeNAT, Prio: -100, Policy: VerdictAccept,
		Rules: []Rule{
			rule(dport("tcp", 30080), Match{Field: FieldUnknown, Unknown: "statistic"}, Verdict{Kind: VerdictJump, Target: "SEP-B"}),
			rule(dport("tcp", 30080), Verdict{Kind: VerdictJump, Target: "SEP-A"}),
		}}
	masq := &Chain{Origin: "iptables", Family: FamilyIP, Table: "nat", Name: "MARK-MASQ", Rules: []Rule{rule(Mark{Clear: 0x4000, Xor: 0x4000})}}
	fwd := &Chain{Origin: "iptables", Family: FamilyIP, Table: "filter", Name: "FORWARD", Hook: HookForward, Policy: VerdictDrop,
		Rules: []Rule{rule(Match{Field: FieldMark, Mark: 0x4000, Mask: 0x4000}, accept())}}
	rs := &Ruleset{Chains: []*Chain{pre, a, b, masq, fwd}}
	r := decide(t, rs, pkt("tcp", 30080))
	if r.Decision() != Open {
		t.Fatalf("both endpoints are forwarded on the mark: %+v", r)
	}
	var dests []string
	for _, o := range r.Outcomes {
		dests = append(dests, o.DAddr.String())
	}
	slices.Sort(dests)
	if !slices.Equal(slices.Compact(dests), []string{"172.17.0.10", "172.17.0.9"}) {
		t.Fatalf("destinations: %v", dests)
	}
}

func TestEvaluateUnknownOutputInterfaceIsMaybe(t *testing.T) {
	rs := dockerLike()
	rs.Chains[1].Rules[0].Exprs[2] = NAT{Kind: NATDnat, Addr: netip.MustParseAddr("10.9.9.9"), Port: 80}
	// Every path still drops: only 172.17.0.2:80 is accepted.
	if got := decide(t, rs, pkt("tcp", 18080)).Decision(); got != Closed {
		t.Fatalf("unrouted DNAT target in docker's layout: %v", got)
	}
	rs.Chains[4].Rules[0] = rule(Match{Field: FieldOIf, Names: []string{"docker0"}}, accept())
	r := decide(t, rs, pkt("tcp", 18080))
	if r.Decision() != Undetermined || !slices.Contains(r.MaybeReasons(), "output interface") {
		t.Fatalf("an accept on an unknown output interface: %+v", r)
	}
}

func TestEvaluateVMapAndMissingChain(t *testing.T) {
	inJump := regular("in_docker0", rule(dport("tcp", 80), accept()), rule(drop()))
	fwd := base("forward", HookForward, 0, VerdictAccept, rule(VMap{
		Key:   Match{Field: FieldOIf},
		Elems: []VMapElem{{Match: Match{Field: FieldOIf, Names: []string{"docker0"}}, Verdict: Verdict{Kind: VerdictJump, Target: "in_docker0"}}},
	}))
	pre := &Chain{Origin: "nft", Family: FamilyIP, Table: "nat", Name: "prerouting", Hook: HookPrerouting, Type: TypeNAT, Prio: -100, Policy: VerdictAccept,
		Rules: []Rule{
			rule(dport("tcp", 18080), NAT{Kind: NATDnat, Addr: ctrAddr, Port: 80}),
			rule(dport("tcp", 18081), NAT{Kind: NATDnat, Addr: ctrAddr, Port: 81}),
		}}
	rs := &Ruleset{Chains: []*Chain{pre, fwd, inJump}}
	if got := decide(t, rs, pkt("tcp", 18080)).Decision(); got != Open {
		t.Fatalf("vmap jump accept: %v", got)
	}
	if got := decide(t, rs, pkt("tcp", 18081)).Decision(); got != Closed {
		t.Fatalf("vmap jump drop: %v", got)
	}

	broken := base("input", HookInput, 0, VerdictAccept, rule(Verdict{Kind: VerdictJump, Target: "nowhere"}))
	r := decide(t, &Ruleset{Chains: []*Chain{broken}}, pkt("tcp", 1))
	if r.Decision() != Undetermined {
		t.Fatalf("jump to a missing chain: %+v", r)
	}
}

func TestEvaluateMarkAndNe(t *testing.T) {
	in := base("input", HookInput, 0, VerdictDrop,
		rule(Mark{Xor: 0x1}),
		rule(Match{Field: FieldMark, Mark: 0x1, Mask: 0xffffffff}, dport("tcp", 1), accept()),
		rule(Match{Field: FieldDPort, Op: OpNe, Proto: "tcp", Ports: []PortRange{{2, 2}}}, accept()),
	)
	rs := &Ruleset{Chains: []*Chain{in}}
	for port, want := range map[uint16]Decision{1: Open, 2: Closed, 3: Open} {
		if got := decide(t, rs, pkt("tcp", port)).Decision(); got != want {
			t.Errorf("tcp/%d: %v, want %v", port, got, want)
		}
	}
	// A tcp port match never matches udp, negated or not.
	if got := decide(t, rs, pkt("udp", 3)).Decision(); got != Closed {
		t.Errorf("udp/3: %v", got)
	}
}

func TestEvaluateForkBound(t *testing.T) {
	var rules []Rule
	for i := 0; i < 12; i++ {
		rules = append(rules, rule(Match{Field: FieldUnknown, Unknown: "x"}, Mark{Xor: 1 << i}))
	}
	rs := &Ruleset{Chains: []*Chain{base("input", HookInput, 0, VerdictAccept, rules...)}}
	r := decide(t, rs, pkt("tcp", 1))
	if !r.Truncated || r.Decision() != Undetermined {
		t.Fatalf("2^12 marked paths must hit the bound: truncated=%v", r.Truncated)
	}
}
