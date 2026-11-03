package exposure

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/state"
)

const kubeIptPodsNote = "fw:undetermined netns mapping (" + evKubeIptPods + ")"

// kubePodNS is a pod netns no host port maps (10.42.0.20 is no target in the fixtures).
const kubePodNS = 4026532510

func cniIf() netif.Interface {
	return netif.Interface{Name: "cni0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.42.0.1/24")}}
}

func unmappedPod() state.Listener {
	return lst(kubePodNS, "tcp", "0.0.0.0", 9100, model.Process{PID: 4302})
}

// The wording is shared between the modes, and the nftables text did not change.
func TestKubePodsWordingShared(t *testing.T) {
	if evKubeNftPods != "kube-proxy nftables: pod addresses may be routable in the cluster" {
		t.Errorf("nftables wording changed: %q", evKubeNftPods)
	}
	if evKubeIptPods != "kube-proxy iptables: pod addresses may be routable in the cluster" {
		t.Errorf("iptables wording: %q", evKubeIptPods)
	}
}

// Assumption: the iptables-mode fixture holds both kube-proxy service chains.
func TestAssumptionKubeIptablesFixtureHasServiceChains(t *testing.T) {
	fw, err := Merge(MergeInput{IPT4: readFixture(t, "kube-proxy.v4.txt")})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range fw.Rules.Chains {
		seen[c.Table+" "+c.Name] = true
	}
	for _, k := range []string{"nat KUBE-SERVICES", "nat KUBE-NODEPORTS", "filter KUBE-SERVICES", "filter KUBE-NODEPORTS"} {
		if !seen[k] {
			t.Errorf("fixture lacks %s", k)
		}
	}
}

// Assumption: an iptables-nft host read through nft alone (no iptables-save) is still
// recognised, since the match is on the chain name whatever the origin.
func TestAssumptionKubeIptablesSeenThroughNftDump(t *testing.T) {
	fw, err := Merge(MergeInput{NFT: readFixture(t, "kube-proxy-nft.json")})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(cniIf()), kubePodAddrs)
	// nft shows iptables-nft's DNAT as an xt target it cannot read; that reason was
	// there before, the kube-proxy one is new.
	checkJudge(t, v, []state.Listener{unmappedPod()}, map[string]want{
		"4026532510/tcp/0.0.0.0:9100": {model.ExposureBound, []string{
			"fw:undetermined netns mapping (" + evKubeIptPods + ", unreadable NAT rule (xt DNAT))"}},
	})
}

// Assumption: IPVS mode owns the same service chains; with kube-ipvs0 present only the
// IPVS reason is named.
func TestAssumptionKubeIPVSNamesIPVSOnly(t *testing.T) {
	fw, err := Merge(MergeInput{IPT4: readFixture(t, "kube-proxy.v4.txt")})
	if err != nil {
		t.Fatal(err)
	}
	ipvs := netif.Interface{Name: "kube-ipvs0", Up: true}
	v := NewView("start", hostNS, fw, nil, vmIfs(cniIf(), ipvs), kubePodAddrs)
	checkJudge(t, v, []state.Listener{unmappedPod()}, map[string]want{
		"4026532510/tcp/0.0.0.0:9100": {model.ExposureBound, []string{"fw:undetermined netns mapping (kube-proxy IPVS mode)"}},
	})
}

// Assumption: the kubelet's chains (and kube-proxy's canary, created in every mode) are
// no sign of iptables mode; an unmapped netns there stays local.
func TestAssumptionKubeletChainsAreNotKubeProxy(t *testing.T) {
	rules := strings.Join([]string{
		"*mangle", ":PREROUTING ACCEPT [0:0]", ":KUBE-KUBELET-CANARY - [0:0]", ":KUBE-PROXY-CANARY - [0:0]", "COMMIT",
		"*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", ":KUBE-FIREWALL - [0:0]",
		"-A INPUT -j KUBE-FIREWALL", "COMMIT", "",
	}, "\n")
	fw, err := Merge(MergeInput{IPT4: []byte(rules)})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(cniIf()), kubePodAddrs)
	checkJudge(t, v, []state.Listener{unmappedPod()}, map[string]want{
		"4026532510/tcp/0.0.0.0:9100": {model.ExposureLocal, []string{"netns: no host port mapping"}},
	})
}

// A non-Kubernetes netns (plain Docker, no kube-proxy chains) is still local when no
// host port maps it, for every Docker fixture set.
func TestPlainDockerUnmappedStaysLocal(t *testing.T) {
	for _, set := range [][3]string{
		{"docker-iptables-nft.json", "docker-iptables-nft.v4.txt", "docker-iptables-nft.v6.txt"},
		{"docker-nftables.json", "docker-nftables.v4.txt", "docker-nftables.v6.txt"},
		{"ufw-docker-nft.json", "ufw-docker.v4.txt", "ufw-docker.v6.txt"},
	} {
		fw := mergeFixtures(t, set[0], set[1], set[2])
		for _, c := range fw.Rules.Chains {
			if isKubeProxyIptablesChain(c.Name) || c.Table == "kube-proxy" {
				t.Fatalf("%s: holds kube-proxy chain %s %s", set[0], c.Table, c.Name)
			}
		}
		v := NewView("start", hostNS, fw, nil, vmIfs(), ctrAddrs)
		checkJudge(t, v, []state.Listener{lst(ctrNS, "tcp", "0.0.0.0", 8081, ctrProc)}, map[string]want{
			"4026532426/tcp/0.0.0.0:8081": {model.ExposureLocal, []string{"netns: no host port mapping"}},
		})
	}
}

// Leftovers of both modes (mid-migration): both reasons are listed, the pod is bound.
func TestKubeBothModesListBothReasons(t *testing.T) {
	fw, err := Merge(MergeInput{IPT4: readFixture(t, "kube-proxy.v4.txt"), NFT: readFixture(t, "kube-proxy-nftables.json")})
	if err != nil {
		t.Fatal(err)
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(cniIf()), kubePodAddrs)
	checkJudge(t, v, []state.Listener{unmappedPod()}, map[string]want{
		"4026532510/tcp/0.0.0.0:9100": {model.ExposureBound, []string{
			"fw:undetermined netns mapping (" + evKubeIptPods + ", " + evKubeNftPods + ")"}},
	})
}
