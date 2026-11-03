//go:build integration && linux

package exposure

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/baseline"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/state"
)

// Runs as root in the VM (make itest): reads the real ruleset with the real tools,
// with a table of its own that drops one port.
func TestReadRealFirewall(t *testing.T) {
	nftCmd(t, "add table inet pw_itest")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "pw_itest").Run() })
	nftCmd(t, "add chain inet pw_itest input { type filter hook input priority 10; policy accept; }")
	nftCmd(t, "add rule inet pw_itest input tcp dport 18093 drop")
	nftCmd(t, "add rule inet pw_itest input udp dport 18094 quota 10 mbytes accept")
	nftCmd(t, "add rule inet pw_itest input udp dport 18094 drop")
	nftCmd(t, "add rule inet pw_itest input udp dport 18096 limit rate 1/second accept")
	nftCmd(t, "add rule inet pw_itest input udp dport 18096 drop")

	hostNS, err := baseline.HostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{HostNetNS: hostNS, Run: ExecRunner, Interfaces: netif.Snapshot, NetnsAddrs: ProcNetnsAddrs("/proc")}
	v := Build(context.Background(), cfg, TriggerStart)
	fw, err := v.Firewall()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fw.Sources, "nft") {
		t.Fatalf("sources %q", fw.Sources)
	}
	t.Logf("sources %s, %d chains, notes %v", fw.Sources, len(fw.Rules.Chains), fw.Notes)

	key := func(proto string, port uint16) model.ListenerKey {
		return model.NewKey(hostNS, proto, netip.MustParseAddr("0.0.0.0"), port)
	}
	ls := []state.Listener{{Key: key("tcp", 18093)}, {Key: key("udp", 18094)}, {Key: key("tcp", 18095)}, {Key: key("udp", 18096)}}
	got := v.Judge(ls)
	if e := got[key("tcp", 18093)]; e.Level != model.ExposureBound || !strings.Contains(strings.Join(e.Evidence, "|"), "nft: drop tcp/18093 from 0/0") {
		t.Errorf("18093: %+v", e)
	}
	if e := got[key("udp", 18094)]; e.Level != model.ExposureBound || !strings.Contains(strings.Join(e.Evidence, "|"), "fw:undetermined quota (nft: udp/18094") {
		t.Errorf("18094: %+v", e)
	}
	if e := got[key("tcp", 18095)]; e.Level != model.ExposureHostFirewallOpen {
		t.Errorf("18095: %+v", e)
	}
	// A rate limit the first packet passes is open, and says so.
	if e := got[key("udp", 18096)]; e.Level != model.ExposureHostFirewallOpen || !strings.HasSuffix(strings.Join(e.Evidence, "|"), ", rate-limited") {
		t.Errorf("18096: %+v", e)
	}

	// The fingerprint follows the rules, not the counters.
	again := Build(context.Background(), cfg, TriggerRecheck)
	if changed(v, again) != "" {
		t.Fatal("an unchanged ruleset read twice differs")
	}
	nftCmd(t, "flush chain inet pw_itest input")
	after := Build(context.Background(), cfg, TriggerRecheck)
	if changed(v, after) != TriggerFirewall {
		t.Fatal("a flushed chain was not noticed")
	}
	if e := after.Judge(ls)[key("tcp", 18093)]; e.Level != model.ExposureHostFirewallOpen {
		t.Errorf("18093 after flush: %+v", e)
	}
}

func nftCmd(t *testing.T, cmd string) {
	t.Helper()
	if out, err := exec.Command("nft", strings.Fields(cmd)...).CombinedOutput(); err != nil {
		t.Fatalf("nft %s: %v: %s", cmd, err, out)
	}
}
