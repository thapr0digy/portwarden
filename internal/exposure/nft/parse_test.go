package nft

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/thapr0digy/portwarden/internal/exposure/firewall"
)

var (
	vmAddr     = netip.MustParseAddr("192.168.5.15")
	dockerAddr = netip.MustParseAddr("172.17.0.1")
	dockerNet  = netip.MustParsePrefix("172.17.0.0/16")
)

func vmEnv() firewall.Env {
	return firewall.Env{
		IsLocal: func(a netip.Addr) bool { return a == vmAddr || a == dockerAddr || a.IsLoopback() },
		Route: func(a netip.Addr) (string, bool) {
			if dockerNet.Contains(a) {
				return "docker0", true
			}
			return "eth0", true
		},
	}
}

func load(t *testing.T, path string) *Ruleset {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func eval(rs *Ruleset, proto string, port uint16) firewall.Result {
	fw := &firewall.Ruleset{Chains: rs.Chains}
	return fw.Evaluate(firewall.Packet{Family: firewall.FamilyIP, Proto: proto, DAddr: vmAddr, DPort: port, IIf: "eth0"}, vmEnv())
}

// host-firewall.json: testdata/host-firewall.nft loaded with `nft -f` on Ubuntu 24.04
// (nftables 1.0.9) and dumped with `nft -j list table inet pwfx_filter`.
func TestHostFirewallFixture(t *testing.T) {
	rs := load(t, "testdata/host-firewall.json")
	if len(rs.Tables) != 1 || rs.Tables[0].Name != "pwfx_filter" || rs.Tables[0].Family != firewall.FamilyInet || rs.Tables[0].HasXT {
		t.Fatalf("tables: %+v", rs.Tables)
	}
	var input *firewall.Chain
	for _, c := range rs.Chains {
		if c.Name == "input" {
			input = c
		}
	}
	if input == nil || input.Hook != firewall.HookInput || input.Policy != firewall.VerdictDrop || input.Prio != 0 || len(input.Rules) != 18 {
		t.Fatalf("input chain: %+v", input)
	}
	cases := []struct {
		proto string
		port  uint16
		want  firewall.Decision
	}{
		{"tcp", 22, firewall.Open},   // @allowed_tcp
		{"tcp", 443, firewall.Open},  // @allowed_tcp
		{"tcp", 80, firewall.Open},   // anonymous set
		{"tcp", 8443, firewall.Open}, // anonymous set
		{"tcp", 9050, firewall.Open}, // range
		{"tcp", 9101, firewall.Closed},
		{"tcp", 5432, firewall.Closed}, // only @admin_nets
		{"tcp", 6379, firewall.Closed}, // only 10/8
		{"tcp", 3306, firewall.Closed}, // saddr != 10/8 drop
		{"udp", 51820, firewall.Open},
		{"udp", 546, firewall.Closed},        // ip6 fe80::/10 only
		{"tcp", 8000, firewall.Open},         // iifname "eth*"
		{"tcp", 7000, firewall.Undetermined}, // limit
		{"tcp", 7100, firewall.Open},         // th dport
		{"udp", 7100, firewall.Open},         // th dport
		{"udp", 7200, firewall.Open},         // l4proto udp + udp dport
		{"tcp", 8200, firewall.Open},         // jump extra
		{"tcp", 8300, firewall.Closed},       // return, then policy
		{"udp", 8400, firewall.Open},         // goto extra_udp
		{"tcp", 8100, firewall.Closed},       // reject
		{"tcp", 12345, firewall.Closed},      // policy drop
	}
	for _, c := range cases {
		if got := eval(rs, c.proto, c.port).Decision(); got != c.want {
			t.Errorf("%s/%d: got %v, want %v", c.proto, c.port, got, c.want)
		}
	}
	r := eval(rs, "tcp", 22)
	if o := r.Outcomes[0]; o.Origin != "nft" || o.Where != "inet pwfx_filter input" {
		t.Errorf("22 accepted at %+v", o)
	}
}

// docker-iptables-nft.json: Docker 29.1.3 (iptables backend, iptables-nft 1.8.10) with
// `-p 18080:80 -p 127.0.0.1:18081:81 -p 18053:53/udp`, dumped with `nft -j list ruleset`.
// The DNAT targets and addrtype/conntrack matches are xt blobs here.
func TestDockerIptablesNftFixtureFlagsXT(t *testing.T) {
	rs := load(t, "../testdata/docker-iptables-nft.json")
	xt := map[string]bool{}
	for _, tb := range rs.Tables {
		xt[tb.Family.String()+" "+tb.Name] = tb.HasXT
	}
	for _, want := range []string{"ip nat", "ip filter", "ip6 nat"} {
		if !xt[want] {
			t.Errorf("%s: want HasXT (tables %v)", want, xt)
		}
	}
	if xt["ip raw"] {
		t.Error("ip raw has no xt expression")
	}
	// From the JSON alone the published port cannot be decided: the DNAT target is hidden.
	if got := eval(rs, "tcp", 18080).Decision(); got != firewall.Undetermined {
		t.Errorf("18080 from xt-blind JSON: %v", got)
	}
}

// docker-nftables.json: Docker 29.1.3 with "firewall-backend": "nftables" and the same
// three published ports, on a host whose ufw was disabled (leftover empty ufw chains).
func TestDockerNftablesFixture(t *testing.T) {
	rs := load(t, "../testdata/docker-nftables.json")
	var docker *Table
	for i := range rs.Tables {
		if rs.Tables[i].Name == "docker-bridges" {
			docker = &rs.Tables[i]
		}
	}
	if docker == nil || docker.HasXT {
		t.Fatalf("docker-bridges table: %+v", docker)
	}
	r := eval(rs, "tcp", 18080)
	if r.Decision() != firewall.Open {
		t.Fatalf("18080: %+v", r)
	}
	o := r.Outcomes[0]
	if !o.Forwarded || o.DAddr != netip.MustParseAddr("172.17.0.2") || o.DPort != 80 || o.Where != "ip docker-bridges filter-forward-in__docker0" {
		t.Errorf("18080 outcome: %+v", o)
	}
	if r := eval(rs, "udp", 18053); r.Decision() != firewall.Open || r.Outcomes[0].DPort != 53 {
		t.Errorf("18053/udp: %+v", r)
	}
	// 18081 is published on 127.0.0.1 only: from outside it is not DNAT'ed and reaches
	// the host's INPUT, whose policy (ufw disabled) accepts it.
	if r := eval(rs, "tcp", 18081); r.Decision() != firewall.Open || r.Outcomes[0].Forwarded {
		t.Errorf("18081: %+v", r)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil {
		t.Fatal("want an error")
	}
	if _, err := Parse([]byte(`{"nftables":[{"rule":{"family":"ip","table":"t","chain":"c","expr":[]}}]}`)); err == nil {
		t.Fatal("rule for an unknown chain must fail")
	}
}

func TestParseSkipsOtherFamiliesAndDormantTables(t *testing.T) {
	doc := `{"nftables":[
	 {"table":{"family":"bridge","name":"b"}},
	 {"chain":{"family":"bridge","table":"b","name":"in","type":"filter","hook":"input","prio":0,"policy":"drop"}},
	 {"rule":{"family":"bridge","table":"b","chain":"in","expr":[{"drop":null}]}},
	 {"table":{"family":"inet","name":"off","flags":["dormant"]}},
	 {"chain":{"family":"inet","table":"off","name":"in","type":"filter","hook":"input","prio":0,"policy":"drop"}}
	]}`
	rs, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Tables) != 0 || len(rs.Chains) != 0 {
		t.Fatalf("got %+v", rs)
	}
}

func TestParseExpressions(t *testing.T) {
	doc := `{"nftables":[
	 {"table":{"family":"inet","name":"t"}},
	 {"chain":{"family":"inet","table":"t","name":"in","type":"filter","hook":"input","prio":"filter","policy":"drop"}},
	 {"rule":{"family":"inet","table":"t","chain":"in","expr":[
	   {"mangle":{"key":{"meta":{"key":"mark"}},"value":{"|":[{"meta":{"key":"mark"}},16]}}}]}},
	 {"rule":{"family":"inet","table":"t","chain":"in","expr":[
	   {"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16]},"right":16}},
	   {"match":{"op":"<","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":1024}},
	   {"accept":null}]}},
	 {"rule":{"family":"inet","table":"t","chain":"in","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"range":["192.168.5.1","192.168.5.20"]}}},
	   {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":17}},
	   {"accept":null}]}},
	 {"rule":{"family":"inet","table":"t","chain":"in","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"flags"}},"right":"syn"}},
	   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5000}},
	   {"accept":null}]}}
	]}`
	rs, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Chains[0].Prio != 0 {
		t.Errorf("named priority: %d", rs.Chains[0].Prio)
	}
	for port, want := range map[uint16]firewall.Decision{1023: firewall.Open, 1024: firewall.Closed, 5000: firewall.Undetermined} {
		if got := eval(rs, "tcp", port).Decision(); got != want {
			t.Errorf("tcp/%d: %v, want %v", port, got, want)
		}
	}
	if got := eval(rs, "udp", 9999).Decision(); got != firewall.Open {
		t.Errorf("udp to an address in the range: %v", got)
	}
}

func TestFixturesExist(t *testing.T) {
	for _, f := range []string{"testdata/host-firewall.nft", "testdata/host-firewall.json"} {
		if _, err := os.Stat(filepath.Clean(f)); err != nil {
			t.Error(err)
		}
	}
}
