package exposure

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

func withV6Only(l state.Listener, v model.V6Only) state.Listener {
	l.V6Only = v
	return l
}

// ufw + Docker, eth0 with a public IPv6 address too: ufw allows 8443 on both families
// and 9443 only on IPv4 (an extra ip filter rule); nothing allows 80.
func TestJudgeV6OnlyHostListeners(t *testing.T) {
	native := `{"nftables":[{"table":{"family":"ip","name":"f"}},
	 {"chain":{"family":"ip","table":"f","name":"in","type":"filter","hook":"input","prio":0,"policy":"drop"}},
	 {"rule":{"family":"ip","table":"f","chain":"in","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[8443,9443]}}},{"accept":null}]}},
	 {"table":{"family":"ip6","name":"f"}},
	 {"chain":{"family":"ip6","table":"f","name":"in","type":"filter","hook":"input","prio":0,"policy":"drop"}},
	 {"rule":{"family":"ip6","table":"f","chain":"in","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},{"accept":null}]}}]}`
	fw, err := Merge(MergeInput{NFT: []byte(native)})
	if err != nil {
		t.Fatal(err)
	}
	ifs := vmIfs()
	ifs[1].Prefixes = append(ifs[1].Prefixes, netip.MustParsePrefix("2600:1f18::15/64"))
	v := NewView("start", hostNS, fw, nil, ifs, nil)
	checkJudge(t, v, []state.Listener{
		withV6Only(lst(hostNS, "tcp", "::", 9443), model.V6OnlyOn),
		withV6Only(lst(hostNS, "tcp", "::", 8443), model.V6OnlyOn),
		withV6Only(lst(hostNS, "udp", "::", 9443), model.V6OnlyOff),
		withV6Only(lst(hostNS, "tcp", "::", 7443), model.V6OnlyOff),
		lst(hostNS, "tcp", "::", 9444),
		withV6Only(lst(hostNS, "tcp", "0.0.0.0", 9443), model.V6OnlyUnknown),
	}, map[string]want{
		// v6-only: IPv4's accept of 9443 does not reach it.
		"4026531840/tcp/[::]:9443": {model.ExposureBound, []string{
			"bind:any (IPv6 only)", "nft: drop tcp/9443 from 0/0 (eth0, policy ip6 f in)"}},
		"4026531840/tcp/[::]:8443": {model.ExposureHostFirewallOpen, []string{
			"bind:any (IPv6 only)", "nft: accept tcp/8443 from 0/0 (eth0, ip6 f in)"}},
		// Dual-stack: as before, IPv4 too.
		"4026531840/udp/[::]:9443": {model.ExposureBound, []string{
			"bind:any", "nft: drop udp/9443 from 0/0 (eth0, policy ip f in)"}},
		"4026531840/tcp/[::]:7443": {model.ExposureBound, []string{
			"bind:any", "nft: drop tcp/7443 from 0/0 (eth0, policy ip f in)"}},
		// Unknown: judged for both families, and said so.
		"4026531840/tcp/[::]:9444": {model.ExposureBound, []string{
			"bind:any", "bind:v6only unknown (IPv4 judged too)", "nft: drop tcp/9444 from 0/0 (eth0, policy ip f in)"}},
		// An IPv4 socket has no such flag.
		"4026531840/tcp/0.0.0.0:9443": {model.ExposureHostFirewallOpen, []string{
			"bind:any", "nft: accept tcp/9443 from 0/0 (eth0, ip f in)"}},
	})
	// Unknown and accepted on IPv4 only: still judged open (today's overstatement, noted).
	checkJudge(t, v, []state.Listener{lst(hostNS, "tcp", "::", 9443)}, map[string]want{
		"4026531840/tcp/[::]:9443": {model.ExposureHostFirewallOpen, []string{
			"bind:any", "bind:v6only unknown (IPv4 judged too)", "nft: accept tcp/9443 from 0/0 (eth0, ip f in)"}},
	})
	// A host with no external IPv6 address: a v6-only [::] listener has nothing to judge.
	v = NewView("start", hostNS, fw, nil, vmIfs(), nil)
	checkJudge(t, v, []state.Listener{withV6Only(lst(hostNS, "tcp", "::", 9443), model.V6OnlyOn)}, map[string]want{
		"4026531840/tcp/[::]:9443": {model.ExposureBound, []string{"bind:any (IPv6 only)", "firewall: no external interface"}},
	})
}

// A container's [::] listener behind an IPv4 DNAT: a dual-stack one takes it, a
// v6-only one does not.
func TestJudgeV6OnlyContainerListener(t *testing.T) {
	fw := mergeFixtures(t, "ufw-docker-nft.json", "ufw-docker.v4.txt", "ufw-docker.v6.txt")
	addrs := func(pid uint32) ([]netip.Addr, error) {
		if pid == 4242 {
			return []netip.Addr{netip.MustParseAddr("172.17.0.2"), netip.MustParseAddr("fd00::2")}, nil
		}
		return nil, errors.New("no such process")
	}
	v := NewView("start", hostNS, fw, nil, vmIfs(), addrs)
	dual := withV6Only(lst(ctrNS, "tcp", "::", 80, ctrProc), model.V6OnlyOff)
	got := v.Judge([]state.Listener{dual})[dual.Key]
	if got.Level != model.ExposureHostFirewallOpen {
		t.Fatalf("dual-stack container listener behind 18080: %v %q", got.Level, got.Evidence)
	}
	v6 := withV6Only(dual, model.V6OnlyOn)
	got = NewView("start", hostNS, fw, nil, vmIfs(), addrs).Judge([]state.Listener{v6})[v6.Key]
	// Its IPv4 address is not one it listens on, so the DNAT to 172.17.0.2:80 is not it.
	if got.Level != model.ExposureLocal || !slices.Equal(got.Evidence, []string{"netns: no host port mapping"}) {
		t.Fatalf("v6-only container listener must not take the IPv4 DNAT: %v %q", got.Level, got.Evidence)
	}
	unknown := withV6Only(dual, model.V6OnlyUnknown)
	got = NewView("start", hostNS, fw, nil, vmIfs(), addrs).Judge([]state.Listener{unknown})[unknown.Key]
	if got.Level != model.ExposureHostFirewallOpen || got.Evidence[len(got.Evidence)-1] != "bind:v6only unknown (IPv4 judged too)" {
		t.Fatalf("unknown: judged as dual-stack, noted: %v %q", got.Level, got.Evidence)
	}
}

// The inventory reads the v6-only evidence by this constant (probe requests).
func TestV6OnlyEvidenceIsTheSharedConstant(t *testing.T) {
	v := NewView("start", hostNS, nil, nil, vmIfs(), nil)
	l := withV6Only(lst(hostNS, "tcp", "::", 9443), model.V6OnlyOn)
	if e := v.judgeListener(l.Key.Proto, l.Key.Addr, l.Key.Port, l.V6Only); e.Evidence[0] != model.EvidenceV6Only || evV6Only != model.EvidenceV6Only {
		t.Fatalf("%q", e.Evidence)
	}
}
