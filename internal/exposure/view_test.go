package exposure

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/state"
)

const (
	hostNS = 4026531840
	ctrNS  = 4026532426
)

func vmIfs(extra ...netif.Interface) []netif.Interface {
	ifs := []netif.Interface{
		{Name: "docker0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "eth0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.5.15/24"), netip.MustParsePrefix("fe80::5055:55ff:fe4c:1d70/64")}},
		{Name: "lo", Up: true, Loopback: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8"), netip.MustParsePrefix("::1/128")}},
	}
	return append(ifs, extra...)
}

func mergeFixtures(t *testing.T, nftFile, v4, v6 string) *Firewall {
	t.Helper()
	in := MergeInput{IPT4: readFixture(t, v4), IPT6: readFixture(t, v6)}
	if nftFile != "" {
		in.NFT = readFixture(t, nftFile)
	}
	fw, err := Merge(in)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func lst(netns uint32, proto, addr string, port uint16, procs ...model.Process) state.Listener {
	return state.Listener{Key: model.NewKey(netns, proto, netip.MustParseAddr(addr), port), Procs: procs}
}

// dockerProxies reads the docker-proxy command lines recorded with the docker fixtures.
func dockerProxies(t *testing.T) map[string]model.Process {
	t.Helper()
	out := map[string]model.Process{}
	sc := bufio.NewScanner(bytes.NewReader(readFixture(t, "docker-proxy-cmdlines.txt")))
	pid := uint32(184600)
	for sc.Scan() {
		args := strings.Fields(sc.Text())
		m, ok := ParseDockerProxy(args)
		if !ok {
			t.Fatalf("cannot parse %q", sc.Text())
		}
		pid++
		out[m.Proto+" "+m.Host.String()] = model.Process{PID: pid, Comm: "docker-proxy", Exe: "/usr/bin/docker-proxy", Cmdline: args}
	}
	return out
}

func ctrAddrs(pid uint32) ([]netip.Addr, error) {
	switch pid {
	case 4242:
		return []netip.Addr{netip.MustParseAddr("172.17.0.2")}, nil
	case 4300:
		return []netip.Addr{netip.MustParseAddr("10.42.0.9")}, nil
	case 4301:
		return []netip.Addr{netip.MustParseAddr("10.42.0.12")}, nil
	case 4400:
		return []netip.Addr{netip.MustParseAddr("34.120.1.7")}, nil
	}
	return nil, errors.New("no such process")
}

var ctrProc = model.Process{PID: 4242, Comm: "httpd"}

type want struct {
	level    model.ExposureLevel
	evidence []string
}

func checkJudge(t *testing.T, v *View, ls []state.Listener, wants map[string]want) {
	t.Helper()
	got := v.Judge(ls)
	if len(got) != len(ls) {
		t.Fatalf("judged %d of %d listeners", len(got), len(ls))
	}
	for _, l := range ls {
		w, ok := wants[l.Key.String()]
		if !ok {
			t.Fatalf("no expectation for %s", l.Key)
		}
		e := got[l.Key]
		if e.Level != w.level || !slices.Equal(e.Evidence, w.evidence) {
			t.Errorf("%s:\n got  %v %q\n want %v %q", l.Key, e.Level, e.Evidence, w.level, w.evidence)
		}
	}
}

// The ufw + Docker host (fixtures recorded together): ufw denies incoming except 22,
// 8443 and 51820/udp; Docker publishes 18080 -> :80, 127.0.0.1:18081 -> :81 and
// 18053/udp -> :53 for container 172.17.0.2.
func TestJudgeUfwDocker(t *testing.T) {
	fw := mergeFixtures(t, "ufw-docker-nft.json", "ufw-docker.v4.txt", "ufw-docker.v6.txt")
	v := NewView("start", hostNS, fw, nil, vmIfs(), ctrAddrs)
	dp := dockerProxies(t)
	ls := []state.Listener{
		lst(hostNS, "tcp", "0.0.0.0", 22),
		lst(hostNS, "tcp", "0.0.0.0", 80),
		lst(hostNS, "tcp", "127.0.0.1", 631),
		lst(hostNS, "udp", "127.0.0.53", 53),
		lst(hostNS, "tcp", "172.17.0.1", 9000),
		lst(hostNS, "tcp", "192.168.5.15", 8443),
		lst(hostNS, "tcp", "10.9.9.9", 8443),
		lst(hostNS, "tcp", "0.0.0.0", 18080, dp["tcp 0.0.0.0:18080"]),
		lst(hostNS, "tcp", "127.0.0.1", 18081, dp["tcp 127.0.0.1:18081"]),
		lst(ctrNS, "tcp", "0.0.0.0", 80, ctrProc),
		lst(ctrNS, "tcp", "0.0.0.0", 81, ctrProc),
		lst(ctrNS, "tcp", "0.0.0.0", 8080, ctrProc),
		lst(ctrNS, "udp", "0.0.0.0", 53, ctrProc),
		lst(ctrNS, "tcp", "127.0.0.1", 9090, ctrProc),
	}
	checkJudge(t, v, ls, map[string]want{
		"4026531840/tcp/0.0.0.0:22": {model.ExposureHostFirewallOpen, []string{
			"bind:any", "iptables: accept tcp/22 from 0/0 (eth0, ip filter ufw-user-input)"}},
		"4026531840/tcp/0.0.0.0:80": {model.ExposureBound, []string{
			"bind:any", "iptables: drop tcp/80 from 0/0 (eth0, policy ip filter INPUT)"}},
		"4026531840/tcp/127.0.0.1:631": {model.ExposureLocal, []string{"bind:loopback"}},
		"4026531840/udp/127.0.0.53:53": {model.ExposureLocal, []string{"bind:loopback"}},
		"4026531840/tcp/172.17.0.1:9000": {model.ExposureBound, []string{
			"bind:172.17.0.1 (docker0)", "firewall: not judged (container network interface)"}},
		"4026531840/tcp/192.168.5.15:8443": {model.ExposureHostFirewallOpen, []string{
			"bind:192.168.5.15 (eth0)", "iptables: accept tcp/8443 from 0/0 (eth0, ip filter ufw-user-input)"}},
		"4026531840/tcp/10.9.9.9:8443": {model.ExposureBound, []string{
			"bind:10.9.9.9 (no interface)", "firewall: not judged (address on no interface)"}},
		"4026531840/tcp/0.0.0.0:18080": {model.ExposureHostFirewallOpen, []string{
			"bind:any", "nat: dnat tcp/18080 -> 172.17.0.2:80", "iptables: accept tcp/18080 from 0/0 (eth0, ip filter DOCKER)"}},
		"4026531840/tcp/127.0.0.1:18081": {model.ExposureLocal, []string{"bind:loopback"}},
		"4026532426/tcp/0.0.0.0:80": {model.ExposureHostFirewallOpen, []string{
			"docker-proxy: 0.0.0.0:18080->172.17.0.2:80", "bind:any", "nat: dnat tcp/18080 -> 172.17.0.2:80",
			"iptables: accept tcp/18080 from 0/0 (eth0, ip filter DOCKER)"}},
		"4026532426/tcp/0.0.0.0:81": {model.ExposureLocal, []string{
			"docker-proxy: 127.0.0.1:18081->172.17.0.2:81", "bind:loopback"}},
		"4026532426/tcp/0.0.0.0:8080": {model.ExposureLocal, []string{"netns: no host port mapping"}},
		// No docker-proxy listener in the set: the DNAT rule alone maps it.
		"4026532426/udp/0.0.0.0:53": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat udp/18053 -> 172.17.0.2:53", "bind:192.168.5.15 (eth0)",
			"iptables: accept udp/18053 from 0/0 (eth0, ip filter DOCKER)"}},
		"4026532426/tcp/127.0.0.1:9090": {model.ExposureLocal, []string{"bind:loopback"}},
	})
	if got := v.NATMappings(); len(got) != 2 {
		t.Errorf("NAT mappings: %+v", got)
	}
}

func TestJudgeDualStackAndIPv6(t *testing.T) {
	fw := mergeFixtures(t, "ufw-docker-nft.json", "ufw-docker.v4.txt", "ufw-docker.v6.txt")
	ifs := vmIfs()
	ifs[1].Prefixes = append(ifs[1].Prefixes, netip.MustParsePrefix("2600:1f18::15/64"))
	v := NewView("start", hostNS, fw, nil, ifs, ctrAddrs)
	dual := func(l state.Listener) state.Listener { l.V6Only = model.V6OnlyOff; return l }
	checkJudge(t, v, []state.Listener{
		dual(lst(hostNS, "tcp", "::", 8443)),
		dual(lst(hostNS, "tcp", "::", 80)),
		lst(hostNS, "tcp", "2600:1f18::15", 8443),
		lst(hostNS, "tcp", "::1", 25),
	}, map[string]want{
		"4026531840/tcp/[::]:8443": {model.ExposureHostFirewallOpen, []string{
			"bind:any", "iptables: accept tcp/8443 from 0/0 (eth0, ip filter ufw-user-input)"}},
		"4026531840/tcp/[::]:80": {model.ExposureBound, []string{
			"bind:any", "iptables: drop tcp/80 from 0/0 (eth0, policy ip filter INPUT)"}},
		"4026531840/tcp/[2600:1f18::15]:8443": {model.ExposureHostFirewallOpen, []string{
			"bind:2600:1f18::15 (eth0)", "iptables: accept tcp/8443 from 0/0 (eth0, ip6 filter ufw6-user-input)"}},
		"4026531840/tcp/[::1]:25": {model.ExposureLocal, []string{"bind:loopback"}},
	})
}

func TestJudgeKubernetes(t *testing.T) {
	fw, err := Merge(MergeInput{IPT4: readFixture(t, "kube-proxy.v4.txt")})
	if err != nil {
		t.Fatal(err)
	}
	cni := netif.Interface{Name: "cni0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.42.0.1/24")}}
	v := NewView("start", hostNS, fw, nil, vmIfs(cni), ctrAddrs)
	const podNS, hostPortNS, otherNS = 4026532500, 4026532501, 4026532502
	checkJudge(t, v, []state.Listener{
		lst(podNS, "tcp", "0.0.0.0", 8080, model.Process{PID: 4300}),
		lst(hostPortNS, "tcp", "0.0.0.0", 80, model.Process{PID: 4301}),
		lst(hostPortNS, "tcp", "0.0.0.0", 9100, model.Process{PID: 4301}),
		lst(otherNS, "tcp", "0.0.0.0", 80, model.Process{PID: 4400}),
	}, map[string]want{
		"4026532500/tcp/0.0.0.0:8080": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/30080 -> 10.42.0.9:8080", "bind:192.168.5.15 (eth0)", "nat: dnat tcp/30080 -> 10.42.0.10:8080",
			"iptables: accept tcp/30080 from 0/0 (eth0, ip filter KUBE-FORWARD)"}},
		"4026532501/tcp/0.0.0.0:80": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/8088 -> 10.42.0.12:80", "bind:192.168.5.15 (eth0)",
			"iptables: accept tcp/8088 from 0/0 (eth0, ip filter FLANNEL-FWD)"}},
		// No host port maps it, but kube-proxy (iptables mode) is present: bound, as in
		// nftables mode.
		"4026532501/tcp/0.0.0.0:9100": {model.ExposureBound, []string{kubeIptPodsNote}},
		"4026532502/tcp/0.0.0.0:80": {model.ExposureBound, []string{
			"netns: public address 34.120.1.7", "firewall: not judged (other netns)"}},
	})
}

func TestJudgeWithoutFirewallOrInterfaces(t *testing.T) {
	v := NewView("start", hostNS, nil, errors.New("nft: Operation not permitted"), vmIfs(), nil)
	checkJudge(t, v, []state.Listener{lst(hostNS, "tcp", "0.0.0.0", 22), lst(ctrNS, "tcp", "0.0.0.0", 80, ctrProc)}, map[string]want{
		"4026531840/tcp/0.0.0.0:22": {model.ExposureBound, []string{"bind:any", "fw:unreadable firewall (nft: Operation not permitted)", "fw:undetermined read incomplete"}},
		"4026532426/tcp/0.0.0.0:80": {model.ExposureBound, []string{"fw:unreadable firewall (nft: Operation not permitted)", "fw:undetermined read incomplete"}},
	})
	fw := mergeFixtures(t, "", "ufw-docker.v4.txt", "ufw-docker.v6.txt")
	v = NewView("start", hostNS, fw, nil, []netif.Interface{{Name: "lo", Up: true, Loopback: true}}, nil)
	checkJudge(t, v, []state.Listener{lst(hostNS, "tcp", "0.0.0.0", 22)}, map[string]want{
		"4026531840/tcp/0.0.0.0:22": {model.ExposureBound, []string{"bind:any", "firewall: no external interface"}},
	})
}

func TestJudgeNoFilterAndUndetermined(t *testing.T) {
	native := `{"nftables":[{"table":{"family":"inet","name":"f"}},
	 {"chain":{"family":"inet","table":"f","name":"in","type":"filter","hook":"input","prio":0,"policy":"drop"}},
	 {"rule":{"family":"inet","table":"f","chain":"in","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":7000}},{"quota":{"val":10,"val_unit":"mbytes"}},{"accept":null}]}}]}`
	fw, err := Merge(MergeInput{NFT: []byte(native)})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Merge(MergeInput{NFT: []byte(`{"nftables":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	checkJudge(t, NewView("start", hostNS, fw, nil, vmIfs(), nil), []state.Listener{lst(hostNS, "tcp", "0.0.0.0", 7000)}, map[string]want{
		"4026531840/tcp/0.0.0.0:7000": {model.ExposureBound, []string{"bind:any", "fw:undetermined quota (nft: tcp/7000 from 0/0, eth0)"}},
	})
	checkJudge(t, NewView("start", hostNS, empty, nil, vmIfs(), nil), []state.Listener{lst(hostNS, "udp", "0.0.0.0", 5353)}, map[string]want{
		"4026531840/udp/0.0.0.0:5353": {model.ExposureHostFirewallOpen, []string{"bind:any", "firewall: accept udp/5353 from 0/0 (eth0, no filter rules)"}},
	})
}

func TestParseDockerProxy(t *testing.T) {
	m, ok := ParseDockerProxy(strings.Fields("/usr/bin/docker-proxy -proto udp -host-ip :: -host-port 18053 -container-ip 172.17.0.2 -container-port 53 -use-listen-fd"))
	if !ok || m.Proto != "udp" || m.Host.String() != "[::]:18053" || m.Target.String() != "172.17.0.2:53" || m.Evidence != "docker-proxy: [::]:18053->172.17.0.2:53" {
		t.Fatalf("got %+v %v", m, ok)
	}
	for _, bad := range []string{"/usr/bin/docker-proxy", "/usr/bin/docker-proxy -proto sctp -host-ip 0.0.0.0 -host-port 1 -container-ip 1.2.3.4 -container-port 2"} {
		if _, ok := ParseDockerProxy(strings.Fields(bad)); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}

func TestNetnsAddrFiles(t *testing.T) {
	got := FibTrieLocal(readFixture(t, "container-fib_trie.txt"))
	if len(got) != 1 || got[0] != netip.MustParseAddr("172.17.0.2") {
		t.Fatalf("fib_trie: %v", got)
	}
	v6, err := IfInet6(readFixture(t, "container-if_inet6.txt"))
	if err != nil || len(v6) != 0 {
		t.Fatalf("container if_inet6: %v %v", v6, err)
	}
	v6, err = IfInet6([]byte("26001f1800000000000000000000001502 02 40 00 80 eth0\nfe80000000000000505555fffe4c1d70 02 40 20 80 eth0\n"))
	if err == nil {
		t.Fatalf("a 34-digit address must fail, got %v", v6)
	}
	v6, err = IfInet6([]byte("26001f18000000000000000000000015 02 40 00 80 eth0\nfe80000000000000505555fffe4c1d70 02 40 20 80 eth0\n00000000000000000000000000000001 01 80 10 80 lo\n"))
	if err != nil || len(v6) != 1 || v6[0] != netip.MustParseAddr("2600:1f18::15") {
		t.Fatalf("if_inet6: %v %v", v6, err)
	}
}

func TestJudgePartialReadIsDegraded(t *testing.T) {
	fw, err := Merge(MergeInput{NFT: []byte(`{"nftables":[]}`), IPT4Err: errors.New("iptables-save: Permission denied"), IPT6Err: fmt.Errorf("ip6tables-save: %w", ErrToolMissing)})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(), ctrAddrs)
	got := v.Judge([]state.Listener{lst(hostNS, "tcp", "0.0.0.0", 22), lst(hostNS, "tcp", "127.0.0.1", 25)})
	e := got[lst(hostNS, "tcp", "0.0.0.0", 22).Key]
	if e.Level != model.ExposureBound || !e.Degraded || !slices.Equal(e.Evidence, []string{"bind:any", "fw:unreadable iptables-save: Permission denied", "fw:undetermined read incomplete"}) {
		t.Fatalf("partial read: %+v", e)
	}
	if lo := got[lst(hostNS, "tcp", "127.0.0.1", 25).Key]; lo.Level != model.ExposureLocal || lo.Degraded {
		t.Fatalf("loopback needs no firewall: %+v", lo)
	}
	if c := v.Conditions(); !slices.Equal(c, []string{"fw:unreadable iptables-save: Permission denied"}) {
		t.Fatalf("conditions %v", c)
	}
	full := NewView("start", hostNS, mergeFixtures(t, "", "ufw-docker.v4.txt", "ufw-docker.v6.txt"), nil, vmIfs(), nil)
	if c := full.Conditions(); len(c) != 0 {
		t.Fatalf("full read conditions %v", c)
	}
}

func TestJudgeContainerNotProvablyLocal(t *testing.T) {
	kubeNft := `{"nftables":[{"table":{"family":"ip","name":"kube-proxy"}},
	 {"chain":{"family":"ip","table":"kube-proxy","name":"nat-prerouting","type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
	 {"rule":{"family":"ip","table":"kube-proxy","chain":"nat-prerouting","expr":[{"jump":{"target":"services"}}]}},
	 {"chain":{"family":"ip","table":"kube-proxy","name":"services"}}]}`
	fw, err := Merge(MergeInput{NFT: []byte(kubeNft)})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(), ctrAddrs)
	// An empty kube-proxy nftables table maps nothing (M9: the mode is simulated), but a
	// pod is still not provably local.
	checkJudge(t, v, []state.Listener{lst(ctrNS, "tcp", "0.0.0.0", 8080, ctrProc)}, map[string]want{
		"4026532426/tcp/0.0.0.0:8080": {model.ExposureBound, []string{"fw:undetermined netns mapping (kube-proxy nftables: pod addresses may be routable in the cluster)"}},
	})

	// kube-proxy nftables with a LoadBalancer IP (not the host's) in service-ips: a
	// packet to the host never takes that element, so pods stay undetermined.
	lbNft := `{"nftables":[{"table":{"family":"ip","name":"kube-proxy"}},
	 {"map":{"family":"ip","table":"kube-proxy","name":"service-ips","type":["ipv4_addr","inet_proto","inet_service"],"map":"verdict",
	   "elem":[[{"concat":["203.0.113.10","tcp",443]},{"goto":{"target":"external-LBHASH00-default/lb/tcp/https"}}]]}},
	 {"chain":{"family":"ip","table":"kube-proxy","name":"nat-prerouting","type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
	 {"chain":{"family":"ip","table":"kube-proxy","name":"services"}},
	 {"chain":{"family":"ip","table":"kube-proxy","name":"external-LBHASH00-default/lb/tcp/https"}},
	 {"rule":{"family":"ip","table":"kube-proxy","chain":"nat-prerouting","expr":[{"jump":{"target":"services"}}]}},
	 {"rule":{"family":"ip","table":"kube-proxy","chain":"services","expr":[{"vmap":{"key":{"concat":[{"payload":{"protocol":"ip","field":"daddr"}},{"meta":{"key":"l4proto"}},{"payload":{"protocol":"th","field":"dport"}}]},"data":"@service-ips"}}]}},
	 {"rule":{"family":"ip","table":"kube-proxy","chain":"external-LBHASH00-default/lb/tcp/https","expr":[{"dnat":{"addr":"172.17.0.2","port":8080}}]}}]}`
	fw, err = Merge(MergeInput{NFT: []byte(lbNft)})
	if err != nil {
		t.Fatal(err)
	}
	v = NewView("start", hostNS, fw, nil, vmIfs(), ctrAddrs)
	checkJudge(t, v, []state.Listener{lst(ctrNS, "tcp", "0.0.0.0", 8080, ctrProc)}, map[string]want{
		"4026532426/tcp/0.0.0.0:8080": {model.ExposureBound, []string{
			"nat: dnat target 172.17.0.2:8080 (path not judged)", "fw:undetermined netns mapping (kube-proxy LoadBalancer/external IPs, kube-proxy nftables: pod addresses may be routable in the cluster)"}},
	})

	// A DNAT keyed on an address that is not the host's (a LoadBalancer or elastic IP),
	// with no port match: the simulation cannot reach it.
	lb := "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -d 198.51.100.5/32 -j DNAT --to-destination 172.17.0.2\nCOMMIT\n"
	fw, err = Merge(MergeInput{IPT4: []byte(lb)})
	if err != nil {
		t.Fatal(err)
	}
	v = NewView("start", hostNS, fw, nil, vmIfs(), ctrAddrs)
	checkJudge(t, v, []state.Listener{lst(ctrNS, "tcp", "0.0.0.0", 8080, ctrProc)}, map[string]want{
		"4026532426/tcp/0.0.0.0:8080": {model.ExposureBound, []string{
			"nat: dnat target 172.17.0.2:0 (path not judged)", "fw:undetermined netns mapping (DNAT without a port match)"}},
	})
	nodeIPVS := NewView("start", hostNS, mergeFixtures(t, "", "ufw-docker.v4.txt", "ufw-docker.v6.txt"), nil,
		vmIfs(netif.Interface{Name: "kube-ipvs0", Up: true}), ctrAddrs)
	checkJudge(t, nodeIPVS, []state.Listener{lst(ctrNS, "tcp", "0.0.0.0", 8080, ctrProc)}, map[string]want{
		"4026532426/tcp/0.0.0.0:8080": {model.ExposureBound, []string{"fw:undetermined netns mapping (kube-proxy IPVS mode)"}},
	})
}

func TestJudgeContainerAddressesUnreadable(t *testing.T) {
	fw := mergeFixtures(t, "ufw-docker-nft.json", "ufw-docker.v4.txt", "ufw-docker.v6.txt")
	v := NewView("start", hostNS, fw, nil, vmIfs(), ctrAddrs)
	gone := model.Process{PID: 9999}
	checkJudge(t, v, []state.Listener{
		lst(ctrNS, "tcp", "0.0.0.0", 80, gone),
		lst(ctrNS+1, "tcp", "0.0.0.0", 8080, gone),
		lst(ctrNS+2, "tcp", "0.0.0.0", 8081),
	}, map[string]want{
		"4026532426/tcp/0.0.0.0:80": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/18080 -> 172.17.0.2:80", "bind:192.168.5.15 (eth0)",
			"iptables: accept tcp/18080 from 0/0 (eth0, ip filter DOCKER)", "netns: addresses unreadable (no such process)"}},
		"4026532427/tcp/0.0.0.0:8080": {model.ExposureBound, []string{"netns: addresses unreadable (no such process)"}},
		"4026532428/tcp/0.0.0.0:8081": {model.ExposureBound, []string{"netns: addresses unreadable (no holder process)"}},
	})
}

func TestJudgeEvidenceWording(t *testing.T) {
	fw := mergeFixtures(t, "ufw-docker-nft.json", "ufw-docker.v4.txt", "ufw-docker.v6.txt")
	checkJudge(t, NewView("start", hostNS, fw, nil, vmIfs(), nil), []state.Listener{lst(hostNS, "tcp", "0.0.0.0", 5432)}, map[string]want{
		"4026531840/tcp/0.0.0.0:5432": {model.ExposureBound, []string{
			"bind:any", "iptables: drop tcp/5432 from 0/0 (eth0, policy ip filter INPUT)", "restricted by source (ip filter ufw-user-input)"}},
	})
	native, err := Merge(MergeInput{NFT: readFixture(t, "../nft/testdata/host-firewall.json")})
	if err != nil {
		t.Fatal(err)
	}
	checkJudge(t, NewView("start", hostNS, native, nil, vmIfs(), nil), []state.Listener{lst(hostNS, "tcp", "0.0.0.0", 7000)}, map[string]want{
		"4026531840/tcp/0.0.0.0:7000": {model.ExposureHostFirewallOpen, []string{
			"bind:any", "nft: accept tcp/7000 from 0/0 (eth0, inet pwfx_filter input), rate-limited"}},
	})
}
