package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

// Every expression type is written field by field: no pointers, no Go syntax.
func TestCanonicalEveryExpr(t *testing.T) {
	build := func() *Ruleset {
		m := Match{Field: FieldSAddr, Op: OpNe, Family: FamilyIP, Proto: "tcp",
			Ports:  []PortRange{{80, 80}, {9000, 9100}},
			Pfx:    []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fe80::/10")},
			Ranges: []AddrRange{{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.9")}},
			Names:  []string{"eth*", `we"ird`}, Mark: 1, Mask: 3, Unknown: "limit", Any: true, Note: "rate-limited"}
		return &Ruleset{Chains: []*Chain{{Origin: "nft", Family: FamilyInet, Table: "filter", Name: "input", Hook: HookInput,
			Type: TypeFilter, Prio: 10, Policy: VerdictDrop, Rules: []Rule{{Exprs: []Expr{
				m,
				VMap{Key: Match{Field: FieldDPort}, Elems: []VMapElem{{Match: m, And: []Match{m}, Verdict: Verdict{Kind: VerdictJump, Target: "x"}}}},
				Mark{Clear: 1, Xor: 2},
				NAT{Kind: NATDnat, Addr: netip.MustParseAddr("172.17.0.2"), Port: 80},
				NAT{Kind: NATRedirect},
				Verdict{Kind: VerdictAccept},
			}}}}}}
	}
	a, b := build().Canonical(), build().Canonical()
	if a != b {
		t.Fatal("separately built equal rulesets differ")
	}
	for _, bad := range []string{"0x", "expr type=", "invalid IP", "netip", "firewall."} {
		if strings.Contains(a, bad) {
			t.Errorf("canonical text contains %q:\n%s", bad, a)
		}
	}
	for _, want := range []string{"10.0.0.0/8", "fe80::/10", "192.0.2.1-192.0.2.9", "addr=172.17.0.2 port=80", "addr=- port=0", `"we\"ird"`, "9000-9100", `target="x"`} {
		if !strings.Contains(a, want) {
			t.Errorf("canonical text lacks %q:\n%s", want, a)
		}
	}
}
