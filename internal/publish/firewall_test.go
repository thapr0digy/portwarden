package publish

import (
	"strings"
	"testing"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/state"
)

var (
	fpA = strings.Repeat("a", 64)
	fpB = strings.Repeat("b", 64)
)

func TestFirewallFingerprintOnHeartbeatsAndHostBlocks(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.SetHost(testHostInfo)
	p.Heartbeat(0) // 1: before any view: absent
	p.SetFirewall(fpA)
	p.Snapshot(snapshotOf(22), nil) // 2
	p.Heartbeat(0)                  // 3
	p.SetFirewall(fpB)              // a fingerprint-only change publishes no host.changed
	c := openedChange(8080)
	c.Exposure = openExposure
	// 4
	p.ExposureChanges([]state.ExposureChange{{Key: c.Key, Procs: c.Procs, Exposure: openExposure, Trigger: "firewall"}})
	p.Heartbeat(0)    // 5
	p.SetFirewall("") // unreadable: present and empty
	p.Heartbeat(0)    // 6

	msgs := readStream(t, port, 6)
	want := []string{"heartbeat", "snapshot", "heartbeat", "exposure.changed", "heartbeat", "heartbeat"}
	for i, m := range msgs {
		if m.subject != "asm."+testHost+"."+want[i] {
			t.Fatalf("message %d on %s, want %s", i, m.subject, want[i])
		}
	}
	var hb0, hbA, hbB, hbE asmv1.Heartbeat
	mustUnmarshal(t, msgs[0].data, &hb0)
	mustUnmarshal(t, msgs[2].data, &hbA)
	mustUnmarshal(t, msgs[4].data, &hbB)
	mustUnmarshal(t, msgs[5].data, &hbE)
	if hb0.FirewallFingerprint != nil {
		t.Fatalf("heartbeat before any view carries a fingerprint: %v", &hb0)
	}
	if hbA.GetFirewallFingerprint() != fpA || hbB.GetFirewallFingerprint() != fpB {
		t.Fatalf("heartbeats carry %q, %q", hbA.GetFirewallFingerprint(), hbB.GetFirewallFingerprint())
	}
	if hbE.FirewallFingerprint == nil || hbE.GetFirewallFingerprint() != "" {
		t.Fatalf("unreadable firewall: heartbeat fingerprint must be present and empty: %v", &hbE)
	}
	var s asmv1.Snapshot
	mustUnmarshal(t, msgs[1].data, &s)
	if s.GetHost().GetFirewallFingerprint() != fpA || s.GetHost().GetInstanceId() != "i-0abc" {
		t.Fatalf("snapshot host = %v", s.GetHost())
	}
	var ev asmv1.ExposureEvent
	mustUnmarshal(t, msgs[3].data, &ev)
	if ev.GetHost().GetFirewallFingerprint() != fpB {
		t.Fatalf("exposure event host = %v", ev.GetHost())
	}
}

func TestHostChangedCarriesFirewallFingerprint(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.SetFirewall(fpA)
	p.SetHost(testHostInfo.Clone())
	h := testHostInfo.Clone()
	h.Conditions = []string{"fw:unreadable iptables-save: Permission denied"}
	p.SetFirewall("")
	p.SetHost(h)

	msgs := readStream(t, port, 1)
	var ev asmv1.HostEvent
	mustUnmarshal(t, msgs[0].data, &ev)
	if ev.GetHost().FirewallFingerprint == nil || ev.GetHost().GetFirewallFingerprint() != "" || len(ev.GetHost().GetConditions()) != 1 {
		t.Fatalf("host.changed host = %v", ev.GetHost())
	}
}
