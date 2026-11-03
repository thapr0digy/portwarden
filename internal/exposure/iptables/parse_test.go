package iptables

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/thapr0digy/portwarden/internal/exposure/firewall"
)

var (
	vmAddr = netip.MustParseAddr("192.168.5.15")
	nets   = map[string]netip.Prefix{
		"docker0": netip.MustParsePrefix("172.17.0.0/16"),
		"cni0":    netip.MustParsePrefix("10.42.0.0/24"),
	}
)

func vmEnv() firewall.Env {
	return firewall.Env{
		IsLocal: func(a netip.Addr) bool {
			return a == vmAddr || a == netip.MustParseAddr("172.17.0.1") || a == netip.MustParseAddr("10.42.0.1") || a.IsLoopback()
		},
		Route: func(a netip.Addr) (string, bool) {
			for name, pfx := range nets {
				if pfx.Contains(a) {
					return name, true
				}
			}
			return "eth0", true
		},
	}
}

func load(t *testing.T, path string, fam firewall.Family) *Ruleset {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Parse(data, fam)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func eval(rs *Ruleset, proto string, port uint16) firewall.Result {
	fw := &firewall.Ruleset{Chains: rs.Chains}
	return fw.Evaluate(firewall.Packet{Family: firewall.FamilyIP, Proto: proto, DAddr: vmAddr, DPort: port, IIf: "eth0"}, vmEnv())
}

type portCase struct {
	proto     string
	port      uint16
	want      firewall.Decision
	forwarded []string // DNAT destinations, when forwarded
}

func check(t *testing.T, rs *Ruleset, cases []portCase) {
	t.Helper()
	for _, c := range cases {
		r := eval(rs, c.proto, c.port)
		if got := r.Decision(); got != c.want {
			t.Errorf("%s/%d: got %v, want %v (%+v)", c.proto, c.port, got, c.want, r.Outcomes)
			continue
		}
		var dests []string
		for _, o := range r.Outcomes {
			if o.Forwarded {
				dests = append(dests, netip.AddrPortFrom(o.DAddr, o.DPort).String())
			}
		}
		slices.Sort(dests)
		dests = slices.Compact(dests)
		if !slices.Equal(dests, c.forwarded) {
			t.Errorf("%s/%d: forwarded to %v, want %v", c.proto, c.port, dests, c.forwarded)
		}
	}
}

// docker-iptables-nft.v4.txt: Docker 29.1.3 (iptables backend) on Ubuntu 24.04 with
// `-p 18080:80 -p 127.0.0.1:18081:81 -p 18053:53/udp`, recorded with iptables-save.
func TestDockerFixture(t *testing.T) {
	rs := load(t, "../testdata/docker-iptables-nft.v4.txt", firewall.FamilyIP)
	if rs.Backend != "nf_tables" || rs.LegacyPresent {
		t.Fatalf("backend %q legacy %v", rs.Backend, rs.LegacyPresent)
	}
	if !slices.Equal(rs.Tables, []string{"raw", "filter", "nat"}) {
		t.Fatalf("tables %v", rs.Tables)
	}
	check(t, rs, []portCase{
		{"tcp", 18080, firewall.Open, []string{"172.17.0.2:80"}},
		{"udp", 18053, firewall.Open, []string{"172.17.0.2:53"}},
		// Published on 127.0.0.1 only: from outside it is not DNAT'ed; INPUT accepts.
		{"tcp", 18081, firewall.Open, nil},
		{"tcp", 22, firewall.Open, nil},
	})
}

// ufw-docker.v4.txt: the same Docker host with ufw enabled (deny incoming; allow 22/tcp,
// 8443/tcp, 51820/udp, and 5432/tcp from 10.0.0.0/8 only).
func TestUfwDockerFixture(t *testing.T) {
	rs := load(t, "../testdata/ufw-docker.v4.txt", firewall.FamilyIP)
	check(t, rs, []portCase{
		{"tcp", 22, firewall.Open, nil},
		{"tcp", 8443, firewall.Open, nil},
		{"udp", 51820, firewall.Open, nil},
		{"tcp", 5432, firewall.Closed, nil},
		{"tcp", 80, firewall.Closed, nil},
		{"udp", 53, firewall.Closed, nil},
		// The classic: Docker's DNAT sends 18080 through FORWARD, past ufw's INPUT.
		{"tcp", 18080, firewall.Open, []string{"172.17.0.2:80"}},
		// 18081 is not DNAT'ed from outside and ufw drops it on INPUT.
		{"tcp", 18081, firewall.Closed, nil},
	})
	r := eval(rs, "tcp", 8443)
	if o := r.Outcomes[0]; o.Origin != "iptables" || o.Where != "ip filter ufw-user-input" {
		t.Errorf("8443 accepted at %+v", o)
	}
	r = eval(rs, "tcp", 80)
	if o := r.Outcomes[0]; o.Where != "policy ip filter INPUT" {
		t.Errorf("80 dropped at %+v", o)
	}
	rs6 := load(t, "../testdata/ufw-docker.v6.txt", firewall.FamilyIP6)
	fw := &firewall.Ruleset{Chains: rs6.Chains}
	v6 := func(port uint16) firewall.Decision {
		return fw.Evaluate(firewall.Packet{Family: firewall.FamilyIP6, Proto: "tcp", DAddr: netip.MustParseAddr("2001:db8::15"), DPort: port, IIf: "eth0"},
			firewall.Env{IsLocal: func(a netip.Addr) bool { return a == netip.MustParseAddr("2001:db8::15") }, Route: func(netip.Addr) (string, bool) { return "eth0", true }}).Decision()
	}
	if v6(8443) != firewall.Open || v6(80) != firewall.Closed {
		t.Errorf("ipv6 ufw: 8443 %v, 80 %v", v6(8443), v6(80))
	}
}

// kube-proxy.v4.txt: kube-proxy's iptables-mode layout for a NodePort service (30080,
// two endpoints chosen by -m statistic) and a CNI portmap hostPort (8088), with
// flannel's forward accepts; loaded with iptables-restore into a scratch netns on
// Ubuntu 24.04 and recorded with iptables-save (testdata/kube-proxy.restore).
func TestKubeProxyFixture(t *testing.T) {
	rs := load(t, "../testdata/kube-proxy.v4.txt", firewall.FamilyIP)
	check(t, rs, []portCase{
		{"tcp", 30080, firewall.Open, []string{"10.42.0.10:8080", "10.42.0.9:8080"}},
		{"tcp", 8088, firewall.Open, []string{"10.42.0.12:80"}},
		{"tcp", 30081, firewall.Open, nil},
	})
	r := eval(rs, "tcp", 30080)
	if got := r.MaybeReasons(); !slices.Equal(got, []string{"-m statistic"}) {
		t.Errorf("30080 depends on %v", got)
	}
}

func TestParseRuleOptions(t *testing.T) {
	dump := `# Generated by iptables-save v1.8.7 (legacy) on Mon Nov  2 20:00:00 2026
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:svc - [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -i eth+ -p tcp -m multiport --dports 80,443,8000:8010 -j ACCEPT
-A INPUT -p tcp -m tcp ! --dport 1:1023 -m conntrack --ctstate NEW -j svc
-A INPUT -p udp -m udp --sport 53 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 25 -m recent --name smtp --rcheck -j ACCEPT
-A INPUT -p tcp -m tcp --dport 26 -m mark --mark 0x1/0xff -j ACCEPT
-A INPUT -p tcp -m iprange --dst-range 192.168.5.10-192.168.5.20 -m tcp --dport 27 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 28 -m pkttype --pkt-type broadcast -j ACCEPT
-A INPUT -s 0.0.0.0/0.0.0.0 -p tcp -m tcp --dport 29 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 30 -m comment --comment "a \"quoted\" note" -j LOG --log-prefix "[x] "
-A INPUT -p tcp -m tcp --dport 30 -j ACCEPT
-A svc -p tcp -m tcp --dport 2000 -j REJECT --reject-with tcp-reset
-A svc -j ACCEPT
COMMIT
`
	rs, err := Parse([]byte(dump), firewall.FamilyIP)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Backend != "legacy" {
		t.Errorf("backend %q", rs.Backend)
	}
	check(t, rs, []portCase{
		{"tcp", 80, firewall.Open, nil},
		{"tcp", 8005, firewall.Open, nil},
		{"tcp", 22, firewall.Closed, nil},
		{"tcp", 1500, firewall.Open, nil},       // via svc
		{"tcp", 2000, firewall.Closed, nil},     // svc rejects
		{"udp", 53, firewall.Undetermined, nil}, // source port 53: the client picks it
		{"tcp", 25, firewall.Closed, nil},       // -m recent --rcheck: a fresh source has no entry
		{"tcp", 26, firewall.Closed, nil},       // mark is 0
		{"tcp", 27, firewall.Open, nil},         // in the destination range
		{"tcp", 28, firewall.Closed, nil},       // broadcast only
		{"tcp", 29, firewall.Open, nil},         // from 0/0
		{"tcp", 30, firewall.Open, nil},         // LOG does not end the chain
	})
}

func TestParseErrors(t *testing.T) {
	for name, dump := range map[string]string{
		"rule outside table": "-A INPUT -j ACCEPT\n",
		"undeclared chain":   "*filter\n:INPUT ACCEPT [0:0]\n-A NOPE -j ACCEPT\nCOMMIT\n",
		"truncated":          "*filter\n:INPUT ACCEPT [0:0]\n",
		"bad quote":          "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment \"x -j ACCEPT\nCOMMIT\n",
		"bad port":           "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport http -j ACCEPT\nCOMMIT\n",
		"garbage":            "hello\n",
	} {
		if _, err := Parse([]byte(dump), firewall.FamilyIP); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestLegacyWarning(t *testing.T) {
	dump := "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n"
	rs, err := Parse([]byte(dump), firewall.FamilyIP)
	if err != nil || !rs.LegacyPresent {
		t.Fatalf("rs %+v err %v", rs, err)
	}
}

func TestNATDestination(t *testing.T) {
	for in, want := range map[string]string{
		"172.17.0.2:80":               "172.17.0.2-172.17.0.2:80-80",
		"172.17.0.2":                  "172.17.0.2-172.17.0.2:0-0",
		"[fd00::2]:8080":              "fd00::2-fd00::2:8080-8080",
		"fd00::2":                     "fd00::2-fd00::2:0-0",
		"10.0.0.1-10.0.0.3":           "10.0.0.1-10.0.0.3:0-0",
		"10.0.0.1-10.0.0.3:8000-8100": "10.0.0.1-10.0.0.3:8000-8100",
		"10.0.0.5:30000-30999":        "10.0.0.5-10.0.0.5:30000-30999",
		"[fd00::2]-[fd00::9]:80-90":   "fd00::2-fd00::9:80-90",
		"fd00::2-fd00::9":             "fd00::2-fd00::9:0-0",
		"10.0.0.3-10.0.0.1":           "", // reversed
		"10.0.0.1-fd00::2":            "", // mixed families
		"10.0.0.1:90-80":              "",
		"10.0.0.1:0":                  "",
		":80":                         "",
		"[fd00::2]x":                  "",
	} {
		d, err := natDestination(in)
		got := ""
		if err == nil {
			got = fmt.Sprintf("%s-%s:%d-%d", d.lo, d.hi, d.port, d.portHi)
		}
		if got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func TestNATTargetRanges(t *testing.T) {
	for _, c := range []struct {
		args string
		want firewall.NAT
	}{
		{"-j DNAT --to-destination 10.0.0.1-10.0.0.3:8000-8100", firewall.NAT{Kind: firewall.NATDnat,
			Addr: netip.MustParseAddr("10.0.0.1"), AddrHi: netip.MustParseAddr("10.0.0.3"), Port: 8000, PortHi: 8100}},
		{"-j DNAT --to-destination 10.0.0.5:30000-30999 --random-fully", firewall.NAT{Kind: firewall.NATDnat,
			Addr: netip.MustParseAddr("10.0.0.5"), Port: 30000, PortHi: 30999, Random: true}},
		{"-j DNAT --to-destination 10.0.0.5:80 --random", firewall.NAT{Kind: firewall.NATDnat,
			Addr: netip.MustParseAddr("10.0.0.5"), Port: 80}},
		{"-j REDIRECT --to-ports 9000-9100", firewall.NAT{Kind: firewall.NATRedirect, Port: 9000, PortHi: 9100}},
		{"-j REDIRECT --to-ports 9000", firewall.NAT{Kind: firewall.NATRedirect, Port: 9000}},
		{"-j REDIRECT --to-ports 9100-9000", firewall.NAT{Kind: firewall.NATRedirect, Unknown: "REDIRECT --to-ports 9100-9000"}},
	} {
		dump := "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp " + c.args + "\nCOMMIT\n"
		rs, err := Parse([]byte(dump), firewall.FamilyIP)
		if err != nil {
			t.Fatalf("%s: %v", c.args, err)
		}
		var got firewall.Expr
		for _, ch := range rs.Chains {
			for _, r := range ch.Rules {
				got = r.Exprs[len(r.Exprs)-1]
			}
		}
		if got != firewall.Expr(c.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", c.args, got, c.want)
		}
	}
}

// ufw-limit.v4.txt: ufw with `ufw limit 22/tcp` and `ufw allow 8443/tcp` on Ubuntu 24.04
// (the -m recent --set / --update --hitcount pair). A fresh outside source is under the
// limit, so 22 is open.
func TestUfwLimitFixture(t *testing.T) {
	rs := load(t, "../testdata/ufw-limit.v4.txt", firewall.FamilyIP)
	check(t, rs, []portCase{
		{"tcp", 22, firewall.Open, nil},
		{"tcp", 8443, firewall.Open, nil},
		{"tcp", 80, firewall.Closed, nil},
	})
	if n := eval(rs, "tcp", 80).Notes(); len(n) != 0 {
		t.Errorf("a limit on a LOG rule is no note: %v", n)
	}
}

// fail2ban-ipset.v4.txt: fail2ban's ipset layout (a REJECT for sources in f2b-sshd
// before the allow), recorded in a scratch netns with iptables-save.
func TestFail2banIpsetFixture(t *testing.T) {
	rs := load(t, "../testdata/fail2ban-ipset.v4.txt", firewall.FamilyIP)
	check(t, rs, []portCase{
		{"tcp", 22, firewall.Open, nil},   // an outside source is not in the ban set
		{"tcp", 2222, firewall.Open, nil}, // ! --match-set src: not banned, accepted
		{"tcp", 23, firewall.Closed, nil},
	})
}

func TestRateAndConnLimits(t *testing.T) {
	dump := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m tcp --dport 1 -m limit --limit 5/sec --limit-burst 10 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2 -m hashlimit --hashlimit-above 10/sec --hashlimit-mode srcip --hashlimit-name x -j DROP
-A INPUT -p tcp -m tcp --dport 2 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3 -m connlimit --connlimit-above 5 --connlimit-mask 32 --connlimit-saddr -j REJECT
-A INPUT -p tcp -m tcp --dport 3 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 4 -m recent --rcheck --seconds 60 --name x --rdest -j DROP
-A INPUT -p tcp -m tcp --dport 4 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
-A INPUT -p tcp -m tcp --dport 6 ! --tcp-flags SYN,ACK SYN -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7 -m set --match-set allow dst -j ACCEPT
COMMIT
`
	rs, err := Parse([]byte(dump), firewall.FamilyIP)
	if err != nil {
		t.Fatal(err)
	}
	check(t, rs, []portCase{
		{"tcp", 1, firewall.Open, nil},
		{"tcp", 2, firewall.Open, nil},
		{"tcp", 3, firewall.Open, nil},
		{"tcp", 4, firewall.Undetermined, nil}, // --rdest: the list is keyed on the destination
		{"tcp", 5, firewall.Open, nil},
		{"tcp", 6, firewall.Closed, nil},
		{"tcp", 7, firewall.Undetermined, nil}, // a destination set
	})
	if n := eval(rs, "tcp", 1).Notes(); !slices.Equal(n, []string{"rate-limited"}) {
		t.Errorf("notes %v", n)
	}
}
