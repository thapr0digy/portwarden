package exposure

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

// natRangeAddrs maps the range tests' containers (by holder pid) to their addresses.
func natRangeAddrs(pid uint32) ([]netip.Addr, error) {
	a, ok := map[uint32]string{5002: "172.17.0.2", 5003: "172.17.0.3", 5005: "172.17.0.5", 5006: "172.17.0.6", 5009: "172.17.0.9"}[pid]
	if !ok {
		return nil, errors.New("no such process")
	}
	return []netip.Addr{netip.MustParseAddr(a)}, nil
}

// An iptables ruleset with NAT ranges wider than 64 ports and DNATs to ranges:
//   - tcp 30000:30999 -> 172.17.0.2:30000-30999 (port-preserving), forward accepts only 30500-30999;
//   - udp 40000:40999 -> 172.17.0.3:5000 (a range to one port);
//   - tcp 18080 -> 172.17.0.4-172.17.0.5:80 (an address range);
//   - tcp 18443 -> 172.17.0.6:8443-8444 (a port range; 18443 lies outside, so either port), forward accepts 8443 only.
const natRangeRules = `*nat
:PREROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A DOCKER -i eth0 -p tcp -m tcp --dport 30000:30999 -j DNAT --to-destination 172.17.0.2:30000-30999
-A DOCKER -i eth0 -p udp -m udp --dport 40000:40999 -j DNAT --to-destination 172.17.0.3:5000
-A DOCKER -p tcp -m tcp --dport 18080 -j DNAT --to-destination 172.17.0.4-172.17.0.5:80
-A DOCKER -p tcp -m tcp --dport 18443 -j DNAT --to-destination 172.17.0.6:8443-8444
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -d 172.17.0.2/32 -o docker0 -p tcp -m tcp --dport 30500:30999 -j ACCEPT
-A FORWARD -d 172.17.0.3/32 -o docker0 -p udp -m udp --dport 5000 -j ACCEPT
-A FORWARD -d 172.17.0.4/31 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A FORWARD -d 172.17.0.6/32 -o docker0 -p tcp -m tcp --dport 8443 -j ACCEPT
COMMIT
`

func TestJudgeNATRanges(t *testing.T) {
	fw, err := Merge(MergeInput{IPT4: []byte(natRangeRules)})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(), natRangeAddrs)
	const ns2, ns3, ns5, ns6, ns9 = 4026532702, 4026532703, 4026532705, 4026532706, 4026532709
	checkJudge(t, v, []state.Listener{
		lst(ns2, "tcp", "0.0.0.0", 30600, model.Process{PID: 5002}),
		lst(ns2, "tcp", "0.0.0.0", 30100, model.Process{PID: 5002}),
		lst(ns3, "udp", "0.0.0.0", 5000, model.Process{PID: 5003}),
		lst(ns5, "tcp", "0.0.0.0", 80, model.Process{PID: 5005}),
		lst(ns6, "tcp", "0.0.0.0", 8443, model.Process{PID: 5006}),
		lst(ns9, "tcp", "0.0.0.0", 80, model.Process{PID: 5009}),
	}, map[string]want{
		// Port-preserving: host 30600 leads to 30600, forwarded.
		"4026532702/tcp/0.0.0.0:30600": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/30500-30999 -> 172.17.0.2:30500-30999", "bind:192.168.5.15 (eth0)",
			"nat: dnat tcp/30600 -> 172.17.0.2:30600", "iptables: accept tcp/30600 from 0/0 (eth0, ip filter FORWARD)"}},
		"4026532702/tcp/0.0.0.0:30100": {model.ExposureBound, []string{
			"nat: dnat tcp/30000-30499 -> 172.17.0.2:30000-30499", "bind:192.168.5.15 (eth0)",
			"nat: dnat tcp/30100 -> 172.17.0.2:30100", "iptables: drop tcp/30100 from 0/0 (eth0, policy ip filter FORWARD)"}},
		"4026532703/udp/0.0.0.0:5000": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat udp/40000-40999 -> 172.17.0.3:5000", "bind:192.168.5.15 (eth0)",
			"nat: dnat udp/40000 -> 172.17.0.3:5000", "iptables: accept udp/40000 from 0/0 (eth0, ip filter FORWARD)"}},
		"4026532705/tcp/0.0.0.0:80": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/18080 -> 172.17.0.4-172.17.0.5:80", "bind:192.168.5.15 (eth0)",
			"iptables: accept tcp/18080 from 0/0 (eth0, ip filter FORWARD)"}},
		// Either port of 8443-8444 (the forward rule splits the range); only 8443 is
		// forwarded, so a connection may or may not get through.
		"4026532706/tcp/0.0.0.0:8443": {model.ExposureBound, []string{
			"nat: dnat tcp/18443 -> 172.17.0.6:8443", "bind:192.168.5.15 (eth0)",
			"nat: dnat tcp/18443 -> 172.17.0.6:8444",
			"fw:undetermined dnat port range (iptables: tcp/18443 from 0/0, eth0)"}},
		"4026532709/tcp/0.0.0.0:80": {model.ExposureLocal, []string{"netns: no host port mapping"}},
	})
	if n := len(v.NATMappings()); n > 16 {
		t.Fatalf("%d mappings: the ranges must not be expanded port by port", n)
	}
}

// The same 1000-port forward in nftables (`tcp dport 30000-30999 dnat to
// 172.17.0.2:30000-30999`), and a range in a verdict map's keys.
func TestJudgeNATRangesNftables(t *testing.T) {
	doc := `{"nftables":[{"table":{"family":"ip","name":"nat"}},
	 {"chain":{"family":"ip","table":"nat","name":"pre","type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
	 {"chain":{"family":"ip","table":"nat","name":"to3"}},
	 {"rule":{"family":"ip","table":"nat","chain":"pre","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"range":[30000,30999]}}},
	   {"dnat":{"addr":"172.17.0.2","port":{"range":[30000,30999]}}}]}},
	 {"rule":{"family":"ip","table":"nat","chain":"pre","expr":[{"vmap":{"key":{"concat":[{"meta":{"key":"l4proto"}},{"payload":{"protocol":"th","field":"dport"}}]},
	   "data":{"set":[[{"concat":["udp",{"range":[40000,40999]}]},{"goto":{"target":"to3"}}]]}}}]}},
	 {"rule":{"family":"ip","table":"nat","chain":"to3","expr":[{"dnat":{"addr":"172.17.0.3","port":5000}}]}}]}`
	fw, err := Merge(MergeInput{NFT: []byte(doc)})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(), natRangeAddrs)
	checkJudge(t, v, []state.Listener{
		lst(4026532702, "tcp", "0.0.0.0", 30999, model.Process{PID: 5002}),
		lst(4026532703, "udp", "0.0.0.0", 5000, model.Process{PID: 5003}),
	}, map[string]want{
		"4026532702/tcp/0.0.0.0:30999": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/30000-30999 -> 172.17.0.2:30000-30999", "bind:192.168.5.15 (eth0)",
			"nat: dnat tcp/30999 -> 172.17.0.2:30999", "firewall: accept tcp/30999 from 0/0 (eth0, no filter rules)"}},
		"4026532703/udp/0.0.0.0:5000": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat udp/40000-40999 -> 172.17.0.3:5000", "bind:192.168.5.15 (eth0)",
			"nat: dnat udp/40000 -> 172.17.0.3:5000", "firewall: accept udp/40000 from 0/0 (eth0, no filter rules)"}},
	})
}

// A ranged packet cut into more pieces than the evaluator follows: the mappings may be
// incomplete, so an unmapped container listener is not provably local.
func TestJudgeNATRangeTooManyPieces(t *testing.T) {
	var b strings.Builder
	b.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n")
	b.WriteString("-A PREROUTING -p tcp -m tcp --dport 20000:29999 -j DNAT --to-destination 172.17.0.2:20000-29999\nCOMMIT\n")
	b.WriteString("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n")
	for p := 20000; p < 20000+2*300; p += 2 {
		fmt.Fprintf(&b, "-A FORWARD -p tcp -m tcp --dport %d -j ACCEPT\n", p)
	}
	b.WriteString("COMMIT\n")
	fw, err := Merge(MergeInput{IPT4: []byte(b.String())})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(), natRangeAddrs)
	l := lst(4026532709, "tcp", "0.0.0.0", 80, model.Process{PID: 5009})
	e := v.Judge([]state.Listener{l})[l.Key]
	if e.Level != model.ExposureBound || !slices.Contains(e.Evidence, "fw:undetermined netns mapping (too many NAT paths)") {
		t.Fatalf("%v %q", e.Level, e.Evidence)
	}
}

// A container that is mapped (and closed on that mapping) in a view whose mapping
// discovery was truncated: the drop is not presented as decided.
func TestJudgeMappedContainerWithTruncation(t *testing.T) {
	var b strings.Builder
	b.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n")
	b.WriteString("-A PREROUTING -p tcp -m tcp --dport 18080 -j DNAT --to-destination 172.17.0.9:80\n")
	b.WriteString("-A PREROUTING -p tcp -m tcp --dport 20000:29999 -j DNAT --to-destination 172.17.0.2:20000-29999\nCOMMIT\n")
	b.WriteString("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n")
	for p := 20000; p < 20000+2*300; p += 2 {
		fmt.Fprintf(&b, "-A FORWARD -p tcp -m tcp --dport %d -j ACCEPT\n", p)
	}
	b.WriteString("COMMIT\n")
	fw, err := Merge(MergeInput{IPT4: []byte(b.String())})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(), natRangeAddrs)
	checkJudge(t, v, []state.Listener{lst(4026532709, "tcp", "0.0.0.0", 80, model.Process{PID: 5009})}, map[string]want{
		"4026532709/tcp/0.0.0.0:80": {model.ExposureBound, []string{
			"nat: dnat tcp/18080 -> 172.17.0.9:80", "bind:192.168.5.15 (eth0)",
			"fw:undetermined netns mapping (too many NAT paths)"}},
	})
}
