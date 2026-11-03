package nft

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/thapr0digy/portwarden/internal/exposure/firewall"
)

func TestNATStatementRanges(t *testing.T) {
	ip := netip.MustParseAddr
	for _, c := range []struct {
		kind, body string
		want       firewall.NAT
	}{
		{"dnat", `{"addr":"10.0.0.5","port":80}`, firewall.NAT{Kind: firewall.NATDnat, Addr: ip("10.0.0.5"), Port: 80}},
		{"dnat", `{"addr":{"range":["10.0.0.1","10.0.0.3"]},"port":{"range":[8000,8100]}}`,
			firewall.NAT{Kind: firewall.NATDnat, Addr: ip("10.0.0.1"), AddrHi: ip("10.0.0.3"), Port: 8000, PortHi: 8100}},
		{"dnat", `{"family":"ip","addr":"10.0.0.5","port":{"range":[30000,30999]},"flags":"fully-random"}`,
			firewall.NAT{Kind: firewall.NATDnat, Addr: ip("10.0.0.5"), Port: 30000, PortHi: 30999, Random: true}},
		{"dnat", `{"addr":"10.0.0.5","port":{"range":[30000,30999]},"flags":["persistent","random"]}`,
			firewall.NAT{Kind: firewall.NATDnat, Addr: ip("10.0.0.5"), Port: 30000, PortHi: 30999, Random: true}},
		{"dnat", `{"addr":{"range":["10.0.0.1","10.0.0.1"]},"port":{"range":[80,80]},"flags":"random"}`,
			firewall.NAT{Kind: firewall.NATDnat, Addr: ip("10.0.0.1"), Port: 80}},
		{"dnat", `{"addr":{"range":["fd00::2","fd00::9"]},"port":443}`,
			firewall.NAT{Kind: firewall.NATDnat, Addr: ip("fd00::2"), AddrHi: ip("fd00::9"), Port: 443}},
		{"redirect", `{"port":{"range":[9000,9100]}}`, firewall.NAT{Kind: firewall.NATRedirect, Port: 9000, PortHi: 9100}},
		{"dnat", `{"addr":{"range":["10.0.0.3","10.0.0.1"]}}`, firewall.NAT{Kind: firewall.NATDnat, Unknown: "dnat target"}},
		{"dnat", `{"addr":{"range":["10.0.0.1","fd00::1"]}}`, firewall.NAT{Kind: firewall.NATDnat, Unknown: "dnat target"}},
		{"dnat", `{"addr":"10.0.0.1","port":{"range":[90,80]}}`, firewall.NAT{Kind: firewall.NATDnat, Addr: ip("10.0.0.1"), Unknown: "dnat port"}},
		{"dnat", `{"addr":{"map":{"key":{"meta":{"key":"l4proto"}},"data":"@m"}}}`, firewall.NAT{Kind: firewall.NATDnat, Unknown: "dnat target"}},
	} {
		got := natStmt(c.kind, json.RawMessage(c.body))
		if got != firewall.Expr(c.want) {
			t.Errorf("%s %s:\n got  %+v\n want %+v", c.kind, c.body, got, c.want)
		}
	}
}

func TestNumgenVerdictMap(t *testing.T) {
	doc := func(mod int, elems string) string {
		return `{"nftables":[{"table":{"family":"ip","name":"kube-proxy"}},
		 {"chain":{"family":"ip","table":"kube-proxy","name":"svc"}},
		 {"chain":{"family":"ip","table":"kube-proxy","name":"a"}},
		 {"chain":{"family":"ip","table":"kube-proxy","name":"b"}},
		 {"rule":{"family":"ip","table":"kube-proxy","chain":"svc","expr":[{"vmap":{"key":{"numgen":{"mode":"random","mod":` +
			itoa(mod) + `,"offset":0}},"data":{"set":[` + elems + `]}}}]}}]}`
	}
	two := `[0,{"goto":{"target":"a"}}],[1,{"goto":{"target":"b"}}]`
	for _, c := range []struct {
		name    string
		data    string
		elems   int
		pickAll bool
		unknown string
	}{
		{"covered", doc(2, two), 2, true, ""},
		{"gap", doc(3, two), 2, false, ""},
		{"out of range values ignored", doc(1, two), 1, true, ""},
		{"bad mod", doc(0, two), 0, false, "vmap on numgen mod 0"},
		{"bad element", doc(2, `["x",{"goto":{"target":"a"}}]`), 0, false, "vmap numgen element"},
	} {
		rs, err := Parse([]byte(c.data))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var vm firewall.VMap
		for _, ch := range rs.Chains {
			if ch.Name == "svc" {
				vm = ch.Rules[0].Exprs[0].(firewall.VMap)
			}
		}
		if len(vm.Elems) != c.elems || vm.PickAll != c.pickAll || vm.Unknown != c.unknown || vm.Pick != (c.unknown == "") {
			t.Errorf("%s: %+v", c.name, vm)
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
