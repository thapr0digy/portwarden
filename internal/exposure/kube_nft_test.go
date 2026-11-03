package exposure

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/state"
)

const kubePodsNote = "fw:undetermined netns mapping (kube-proxy nftables: pod addresses may be routable in the cluster)"

// kubePodAddrs maps the kube fixture's pods (by holder pid) to their addresses.
func kubePodAddrs(pid uint32) ([]netip.Addr, error) {
	a, ok := map[uint32]string{
		4300: "10.42.0.9", 4310: "10.42.0.10", 4301: "10.42.0.12",
		4302: "10.42.0.20", 4303: "10.42.0.21", 4304: "10.42.0.30",
	}[pid]
	if !ok {
		return nil, errors.New("no such process")
	}
	return []netip.Addr{netip.MustParseAddr(a)}, nil
}

// kube-proxy-nftables.json is written by hand from kube-proxy's nftables layout
// (Kubernetes release-1.31 pkg/proxy/nftables/proxier.go; testdata/gen/kube-proxy-nftables.py
// writes it and the 1.34 and master variants), not taken from a live cluster: the
// ip and ip6 kube-proxy tables with their base chains, services, the service-ips,
// service-nodeports and nodeport-ips lookups, the endpoint, firewall and ClusterIP
// checks and the masquerade chains; services web (NodePort 30080, two endpoints chosen
// by numgen), redis (ClusterIP only) and api (externalIPs: the node's own address,
// externalTrafficPolicy Local); plus the CNI portmap plugin's nftables table
// (cni_hostport, containernetworking/plugins portmap_nftables.go) with a hostPort
// 8088 -> 10.42.0.12:80 and 192.168.5.15:5353/udp -> 10.42.0.12:53.
func kubeNftView(t *testing.T, edit func(string) string) *View {
	t.Helper()
	return kubeNftFixtureView(t, "kube-proxy-nftables.json", edit)
}

// kubeNftFixtureView builds a view from one of the kube-proxy nftables fixtures
// (testdata/gen/kube-proxy-nftables.py writes all three).
func kubeNftFixtureView(t *testing.T, fixture string, edit func(string) string) *View {
	t.Helper()
	data := string(readFixture(t, fixture))
	if edit != nil {
		data = edit(data)
	}
	fw, err := Merge(MergeInput{NFT: []byte(data)})
	if err != nil {
		t.Fatal(err)
	}
	cni := netif.Interface{Name: "cni0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.42.0.1/24")}}
	return NewView("start", hostNS, fw, nil, vmIfs(cni), kubePodAddrs)
}

func TestJudgeKubernetesNftables(t *testing.T) {
	const webNS, web2NS, hostPortNS, redisNS, apiNS, plainNS = 4026532600, 4026532601, 4026532602, 4026532603, 4026532604, 4026532605
	ls := []state.Listener{
		lst(webNS, "tcp", "0.0.0.0", 8080, model.Process{PID: 4300}),
		lst(web2NS, "tcp", "0.0.0.0", 8080, model.Process{PID: 4310}),
		lst(hostPortNS, "tcp", "0.0.0.0", 80, model.Process{PID: 4301}),
		lst(hostPortNS, "udp", "0.0.0.0", 53, model.Process{PID: 4301}),
		lst(redisNS, "tcp", "0.0.0.0", 6379, model.Process{PID: 4302}),
		lst(apiNS, "tcp", "0.0.0.0", 8443, model.Process{PID: 4303}),
		lst(plainNS, "tcp", "0.0.0.0", 9100, model.Process{PID: 4304}),
		lst(hostNS, "tcp", "0.0.0.0", 22),
	}
	webOpen := func(pod string) want {
		other := map[string]string{"10.42.0.9": "10.42.0.10", "10.42.0.10": "10.42.0.9"}[pod]
		return want{model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/30080 -> " + pod + ":8080", "bind:192.168.5.15 (eth0)",
			"nat: dnat tcp/30080 -> " + other + ":8080",
			"nft: accept tcp/30080 from 0/0 (eth0, policy ip kube-proxy filter-forward)"}}
	}
	wants := map[string]want{
		// NodePort: both endpoints numgen can pick are reached from the outside.
		"4026532600/tcp/0.0.0.0:8080": webOpen("10.42.0.9"),
		"4026532601/tcp/0.0.0.0:8080": webOpen("10.42.0.10"),
		// hostPort through the CNI portmap nftables table, any host address and a host IP.
		"4026532602/tcp/0.0.0.0:80": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/8088 -> 10.42.0.12:80", "bind:192.168.5.15 (eth0)",
			"nft: accept tcp/8088 from 0/0 (eth0, policy ip kube-proxy filter-forward)"}},
		"4026532602/udp/0.0.0.0:53": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat udp/5353 -> 10.42.0.12:53", "bind:192.168.5.15 (eth0)",
			"nft: accept udp/5353 from 0/0 (eth0, policy ip kube-proxy filter-forward)"}},
		// ClusterIP only: its endpoint is a DNAT target no packet to the host reaches,
		// judged as in iptables mode.
		"4026532603/tcp/0.0.0.0:6379": {model.ExposureBound, []string{
			"nat: dnat target 10.42.0.20:6379 (path not judged)", kubePodsNote}},
		// An external IP that is the node's own address, Local traffic policy.
		"4026532604/tcp/0.0.0.0:8443": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/8443 -> 10.42.0.21:8443", "bind:192.168.5.15 (eth0)",
			"nft: accept tcp/8443 from 0/0 (eth0, policy ip kube-proxy filter-forward)"}},
		// No host port maps it, but with kube-proxy present a pod is never called local
		// (its CIDR may be routed to the node): bound, as before M9.
		"4026532605/tcp/0.0.0.0:9100": {model.ExposureBound, []string{kubePodsNote}},
		"4026531840/tcp/0.0.0.0:22": {model.ExposureHostFirewallOpen, []string{
			"bind:any", "nft: accept tcp/22 from 0/0 (eth0, policy ip kube-proxy filter-input)"}},
	}
	checkJudge(t, kubeNftView(t, nil), ls, wants)

	// The same with --nodeport-addresses matching every address: NodePorts on every
	// local address (`fib daddr type local ip daddr != 127.0.0.0/8 meta l4proto . th
	// dport vmap @service-nodeports`).
	const nodePortIPs = `{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@nodeport-ips"}}, {"vmap": {"key": {"concat": [{"meta": {"key": "l4proto"}}, {"payload": {"protocol": "th", "field": "dport"}}]}, "data": "@service-nodeports"}}`
	const fibLocal = `{"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}}, "right": "local"}}, {"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "127.0.0.0", "len": 8}}}}, {"vmap": {"key": {"concat": [{"meta": {"key": "l4proto"}}, {"payload": {"protocol": "th", "field": "dport"}}]}, "data": "@service-nodeports"}}`
	fib := func(data string) string {
		if !strings.Contains(data, nodePortIPs) {
			t.Fatal("fixture lacks the nodeport-ips rule")
		}
		return strings.Replace(data, nodePortIPs, fibLocal, 1)
	}
	checkJudge(t, kubeNftView(t, fib), ls[:1], map[string]want{"4026532600/tcp/0.0.0.0:8080": webOpen("10.42.0.9")})
}

// kubeListeners are the fixtures' pods (one per netns) and a host listener.
func kubeListeners() []state.Listener {
	return []state.Listener{
		lst(4026532600, "tcp", "0.0.0.0", 8080, model.Process{PID: 4300}),
		lst(4026532601, "tcp", "0.0.0.0", 8080, model.Process{PID: 4310}),
		lst(4026532602, "tcp", "0.0.0.0", 80, model.Process{PID: 4301}),
		lst(4026532603, "tcp", "0.0.0.0", 6379, model.Process{PID: 4302}),
		lst(4026532604, "tcp", "0.0.0.0", 8443, model.Process{PID: 4303}),
		lst(4026532605, "tcp", "0.0.0.0", 9100, model.Process{PID: 4304}),
	}
}

// The Kubernetes 1.34 layout (filter-prerouting-pre-dnat / filter-output-pre-dnat at
// dstnat-10, the other filter chains at filter priority, no filter-output-post-dnat)
// with sessionAffinity ClientIP on web: a fresh outside source is in no affinity set,
// so numgen still picks either endpoint. Same results as 1.31.
func TestJudgeKubernetesNftables134WithAffinity(t *testing.T) {
	webOpen := func(pod, other string) want {
		return want{model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/30080 -> " + pod + ":8080", "bind:192.168.5.15 (eth0)",
			"nat: dnat tcp/30080 -> " + other + ":8080",
			"nft: accept tcp/30080 from 0/0 (eth0, policy ip kube-proxy filter-forward)"}}
	}
	checkJudge(t, kubeNftFixtureView(t, "kube-proxy-nftables-1.34.json", nil), kubeListeners(), map[string]want{
		"4026532600/tcp/0.0.0.0:8080": webOpen("10.42.0.9", "10.42.0.10"),
		"4026532601/tcp/0.0.0.0:8080": webOpen("10.42.0.10", "10.42.0.9"),
		"4026532602/tcp/0.0.0.0:80": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/8088 -> 10.42.0.12:80", "bind:192.168.5.15 (eth0)",
			"nft: accept tcp/8088 from 0/0 (eth0, policy ip kube-proxy filter-forward)"}},
		"4026532603/tcp/0.0.0.0:6379": {model.ExposureBound, []string{
			"nat: dnat target 10.42.0.20:6379 (path not judged)", kubePodsNote}},
		"4026532604/tcp/0.0.0.0:8443": {model.ExposureHostFirewallOpen, []string{
			"nat: dnat tcp/8443 -> 10.42.0.21:8443", "bind:192.168.5.15 (eth0)",
			"nft: accept tcp/8443 from 0/0 (eth0, policy ip kube-proxy filter-forward)"}},
		"4026532605/tcp/0.0.0.0:9100": {model.ExposureBound, []string{kubePodsNote}},
	})
}

// kube-proxy's master branch DNATs a service with several endpoints in one rule,
// `dnat ip addr . port to numgen random mod 2 map { … }`, which the model does not read:
// web's pods are never local (nor raised); single-endpoint services keep their plain
// dnat and are still simulated.
func TestJudgeKubernetesNftablesMasterDNATMap(t *testing.T) {
	v := kubeNftFixtureView(t, "kube-proxy-nftables-master.json", nil)
	got := v.Judge(kubeListeners())
	for _, l := range kubeListeners()[:2] {
		e := got[l.Key]
		if e.Level != model.ExposureBound || !slices.ContainsFunc(e.Evidence, func(ev string) bool {
			return strings.HasPrefix(ev, "fw:undetermined netns mapping (") && strings.Contains(ev, "unreadable NAT rule (dnat target)")
		}) {
			t.Errorf("web pod %s: %v %q", l.Key, e.Level, e.Evidence)
		}
	}
	for _, l := range kubeListeners() {
		if got[l.Key].Level == model.ExposureLocal {
			t.Errorf("%s judged local: %q", l.Key, got[l.Key].Evidence)
		}
	}
	api := kubeListeners()[4]
	if e := got[api.Key]; e.Level != model.ExposureHostFirewallOpen || e.Evidence[0] != "nat: dnat tcp/8443 -> 10.42.0.21:8443" {
		t.Errorf("api (single endpoint, plain dnat): %v %q", e.Level, e.Evidence)
	}
}
