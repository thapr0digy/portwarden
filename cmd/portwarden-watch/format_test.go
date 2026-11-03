package main

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

const hostID = "0123456789abcdef0123456789abcdef"

var at = timestamppb.New(time.Date(2026, 10, 30, 14, 2, 11, 418_000_000, time.UTC))

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func openedEvent(run string, seq uint64) *asmv1.ListenerEvent {
	return &asmv1.ListenerEvent{
		HostId: hostID, RunId: run, Seq: seq, ObservedAt: at, Kind: asmv1.Kind_OPENED,
		Listener:  &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 8443},
		Processes: []*asmv1.Process{{Pid: 4410, Exe: "/opt/app/bin/server"}},
	}
}

func TestFormatOpened(t *testing.T) {
	got, err := formatEvent("asm."+hostID+".listener.opened", mustMarshal(t, openedEvent("r1", 42)))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=42 OPENED tcp 0.0.0.0:8443 pid=4410 /opt/app/bin/server"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatClosedIPv6AndNoProcess(t *testing.T) {
	ev := &asmv1.ListenerEvent{
		HostId: hostID, RunId: "r1", Seq: 3, ObservedAt: at, Kind: asmv1.Kind_CLOSED,
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "::", Port: 80},
	}
	got, err := formatEvent("asm."+hostID+".listener.closed", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=3 CLOSED tcp [::]:80"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatSnapshot(t *testing.T) {
	snap := &asmv1.Snapshot{HostId: hostID, RunId: "r1", Seq: 1, TakenAt: at}
	for i := 0; i < 12; i++ {
		snap.Listeners = append(snap.Listeners, &asmv1.ListenerState{})
	}
	got, err := formatEvent("asm."+hostID+".snapshot", mustMarshal(t, snap))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=1 SNAPSHOT n=12 tcp=0 udp=0"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatHeartbeat(t *testing.T) {
	hb := &asmv1.Heartbeat{HostId: hostID, RunId: "r1", Seq: 9, At: at}
	// The deprecated foreign-netns count is no longer shown.
	hb.DroppedForeignNetns = 5
	got, err := formatEvent("asm."+hostID+".heartbeat", mustMarshal(t, hb))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=9 HEARTBEAT drops=0/0"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatHeartbeatTamper(t *testing.T) {
	hb := &asmv1.Heartbeat{HostId: hostID, RunId: "r1", Seq: 9, At: at, Tamper: &asmv1.TamperStatus{
		Flags: []*asmv1.TamperFlag{{Kind: "ptraced", Subject: "self"}, {Kind: "probe_detached", Subject: "on_connect4"}}}}
	got, err := formatEvent("asm."+hostID+".heartbeat", mustMarshal(t, hb))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=9 HEARTBEAT drops=0/0 tamper=ptraced:self,probe_detached:on_connect4"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	// A clean status says so, so a log shows the checks run.
	hb.Tamper = &asmv1.TamperStatus{Checks: []string{"probes"}}
	got, _ = formatEvent("asm."+hostID+".heartbeat", mustMarshal(t, hb))
	if want := "2026-10-30T14:02:11.418Z 01234567 seq=9 HEARTBEAT drops=0/0 tamper=ok"; got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatTamper(t *testing.T) {
	ev := &asmv1.TamperEvent{HostId: hostID, RunId: "r1", Seq: 12, ObservedAt: at,
		Raised:  []*asmv1.TamperFlag{{Kind: "binary_replaced", Subject: "/usr/bin/portwarden-agent", Detail: "sha256 ab12 on disk, running 9f00"}},
		Cleared: []*asmv1.TamperFlag{{Kind: "ptraced", Subject: "self"}},
		Status:  &asmv1.TamperStatus{Flags: []*asmv1.TamperFlag{{Kind: "binary_replaced", Subject: "/usr/bin/portwarden-agent"}}}}
	got, err := formatEvent("asm."+hostID+".tamper", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=12 TAMPER raised=binary_replaced:/usr/bin/portwarden-agent cleared=ptraced:self " +
		"now=binary_replaced:/usr/bin/portwarden-agent detail=sha256 ab12 on disk, running 9f00"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatOwnerChanged(t *testing.T) {
	ev := &asmv1.ListenerEvent{
		HostId: hostID, RunId: "r1", Seq: 7, ObservedAt: at, Kind: asmv1.Kind_OWNER_CHANGED,
		Listener: &asmv1.Listener{Netns: 4026531840, Proto: "tcp", Addr: "0.0.0.0", Port: 22},
		Processes: []*asmv1.Process{
			{Pid: 1, Comm: "systemd", Exe: "/usr/lib/systemd/systemd", Unit: "ssh.service", SocketUnit: "ssh.socket"},
		},
		PreviousProcesses: []*asmv1.Process{
			{Pid: 1, Comm: "systemd", Exe: "/usr/lib/systemd/systemd", Unit: "ssh.service", SocketUnit: "ssh.socket"},
			{Pid: 812, Comm: "sshd", Exe: "/usr/sbin/sshd", Unit: "ssh.service"},
		},
	}
	got, err := formatEvent("asm."+hostID+".listener.owner_changed", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=7 OWNER_CHANGED tcp 0.0.0.0:22 pid=1 /usr/lib/systemd/systemd" +
		" unit=ssh.service sock=ssh.socket was=1/systemd,812/sshd"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatOwnerChangedFromNoOwner(t *testing.T) {
	ev := &asmv1.ListenerEvent{
		HostId: hostID, RunId: "r1", Seq: 4, ObservedAt: at, Kind: asmv1.Kind_OWNER_CHANGED,
		Listener:  &asmv1.Listener{Proto: "udp", Addr: "0.0.0.0", Port: 4789},
		Processes: []*asmv1.Process{{Pid: 900, Comm: "flanneld"}},
	}
	got, err := formatEvent("asm."+hostID+".listener.owner_changed", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=4 OWNER_CHANGED udp 0.0.0.0:4789 pid=900 flanneld was=-"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatUDPWithUnitAndContainer(t *testing.T) {
	ev := &asmv1.ListenerEvent{
		HostId: hostID, RunId: "r1", Seq: 8, ObservedAt: at, Kind: asmv1.Kind_OPENED,
		Listener: &asmv1.Listener{Netns: 4026532301, Proto: "udp", Addr: "10.0.0.5", Port: 5353},
		Processes: []*asmv1.Process{{
			Pid: 3120, Comm: "mdns", Exe: "/usr/bin/mdns",
			Unit:      "docker-0123456789abcdef0123.scope",
			Container: &asmv1.Container{Runtime: "docker", Id: "0123456789abcdef0123456789abcdef"},
		}},
	}
	got, err := formatEvent("asm."+hostID+".listener.opened", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=8 OPENED udp 10.0.0.5:5353 pid=3120 /usr/bin/mdns" +
		" netns=4026532301 unit=docker-0123456789abcdef0123.scope ctr=docker:0123456789ab"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatSnapshotCountsProtocols(t *testing.T) {
	snap := &asmv1.Snapshot{HostId: hostID, RunId: "r1", Seq: 1, TakenAt: at}
	for _, proto := range []string{"tcp", "udp", "tcp", "tcp", "udp"} {
		snap.Listeners = append(snap.Listeners, &asmv1.ListenerState{Listener: &asmv1.Listener{Proto: proto}})
	}
	got, err := formatEvent("asm."+hostID+".snapshot", mustMarshal(t, snap))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=1 SNAPSHOT n=5 tcp=3 udp=2"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatErrors(t *testing.T) {
	if _, err := formatEvent("asm.h.unknown", nil); err == nil {
		t.Fatal("unknown subject accepted")
	}
	if _, err := formatEvent("asm.h.snapshot", []byte{0xff, 0xff}); err == nil {
		t.Fatal("garbage payload accepted")
	}
}

func TestGapDetected(t *testing.T) {
	var g gapTracker
	var lines []string
	for _, seq := range []uint64{1, 2, 4} {
		ev := openedEvent("runA", seq)
		if l := g.check(ev.RunId, ev.Seq); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 || lines[0] != "GAP run=runA expected=3 got=4" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestNewRunNoGap(t *testing.T) {
	var g gapTracker
	g.check("runA", 7)
	if l := g.check("runB", 1); l != "" {
		t.Fatalf("new run produced %q", l)
	}
	if l := g.check("runB", 2); l != "" {
		t.Fatalf("contiguous produced %q", l)
	}
	if strings.Contains(g.check("runB", 2), "GAP") {
		t.Fatal("duplicate seq must not be a gap")
	}
}

func TestFormatExposureChanged(t *testing.T) {
	ev := &asmv1.ExposureEvent{
		HostId: hostID, RunId: "r1", Seq: 7, ObservedAt: at, Trigger: "firewall",
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 8093, Netns: initNetNS},
		Exposure: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN,
			Evidence: []string{"bind:any", "nft: accept tcp/8093 from 0/0 (eth0, inet pw_e2e input)"}},
		Previous: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_BOUND},
	}
	got, err := formatEvent("asm."+hostID+".exposure.changed", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=7 EXPOSURE tcp 0.0.0.0:8093 bound->host_firewall_open trigger=firewall evidence=bind:any; nft: accept tcp/8093 from 0/0 (eth0, inet pw_e2e input)"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	ev.Previous, ev.Trigger, ev.Listener.Netns = nil, "opened", 4026532300
	ev.Exposure = &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_LOCAL}
	got, _ = formatEvent("asm."+hostID+".exposure.changed", mustMarshal(t, ev))
	want = "2026-10-30T14:02:11.418Z 01234567 seq=7 EXPOSURE tcp 0.0.0.0:8093 new->local trigger=opened netns=4026532300"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatHostChanged(t *testing.T) {
	ev := &asmv1.HostEvent{HostId: hostID, RunId: "r1", Seq: 2, ObservedAt: at, Host: &asmv1.HostInfo{
		Cloud: "aws", InstanceId: "i-0abc",
		PublicIps: []*asmv1.PublicIP{{Ip: "54.1.2.3", Via: "imds", Dir: "in"}, {Ip: "2600:1f18::15", Via: "netlink", Dir: "in", Iface: "eth0"}},
	}}
	got, err := formatEvent("asm."+hostID+".host.changed", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=2 HOST cloud=aws id=i-0abc ips=54.1.2.3/imds/in,2600:1f18::15/netlink/in/eth0"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	ev.Host = nil
	got, _ = formatEvent("asm."+hostID+".host.changed", mustMarshal(t, ev))
	if !strings.HasSuffix(got, " HOST ips=-") {
		t.Fatalf("got %q", got)
	}
}

func TestFormatHostConditions(t *testing.T) {
	ev := &asmv1.HostEvent{HostId: hostID, RunId: "r1", Seq: 3, ObservedAt: at, Host: &asmv1.HostInfo{Conditions: []string{"fw:unreadable iptables-save: Permission denied"}}}
	got, err := formatEvent("asm."+hostID+".host.changed", mustMarshal(t, ev))
	if err != nil || !strings.HasSuffix(got, " HOST ips=- conditions=fw:unreadable iptables-save: Permission denied") {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestFormatBackendEvents(t *testing.T) {
	ev := &asmv1.ExposureEvent{
		HostId: hostID, RunId: "cloud-run", ObservedAt: at, Trigger: "cloud", Origin: "cloud",
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 443, Netns: initNetNS},
		Exposure: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN,
			Evidence: []string{"cloud: sg-1 allows tcp/443 from 0.0.0.0/0"}},
		Previous: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN},
	}
	got, err := formatEvent("pwb.cloud."+hostID+".exposure", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=0 EXPOSURE tcp 0.0.0.0:443 host_firewall_open->cloud_open trigger=cloud origin=cloud evidence=cloud: sg-1 allows tcp/443 from 0.0.0.0/0"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	c := &asmv1.ExposureConfirmation{
		HostId: hostID, RunId: "v1", ObservedAt: at, Origin: "verifier",
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Netns: initNetNS},
		Result:   "confirmed", Target: "10.231.0.1:22", Probe: "tcp-connect", RttMs: 3,
		Banner: "SSH-2.0-OpenSSH_9.6", Checker: "probe-1",
	}
	got, err = formatEvent("pwb.verifier."+hostID+".exposure", mustMarshal(t, c))
	if err != nil {
		t.Fatal(err)
	}
	want = `2026-10-30T14:02:11.418Z 01234567 seq=0 PROBE tcp 0.0.0.0:22 result=confirmed target=10.231.0.1:22 probe=tcp-connect rtt=3ms checker=probe-1 banner="SSH-2.0-OpenSSH_9.6"`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	c.Result, c.Banner, c.Detail = "unreachable", "", "connect: connection timed out"
	got, _ = formatEvent("asm."+hostID+".exposure.confirmed", mustMarshal(t, c))
	want = `2026-10-30T14:02:11.418Z 01234567 seq=0 PROBE tcp 0.0.0.0:22 result=unreachable target=10.231.0.1:22 probe=tcp-connect rtt=3ms checker=probe-1 detail="connect: connection timed out"`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestGapTrackerIgnoresSeqZero(t *testing.T) {
	var g gapTracker
	for _, s := range []uint64{0, 0, 0} {
		if gap := g.check("verifier-run", s); gap != "" {
			t.Fatalf("seq 0 (backend events) must never be a gap: %s", gap)
		}
	}
}

func TestHostSuffixRegion(t *testing.T) {
	got := hostSuffix(&asmv1.HostInfo{Cloud: "aws", InstanceId: "i-1", Region: "eu-west-1"})
	if got != " cloud=aws id=i-1 region=eu-west-1 ips=-" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatFirewallFingerprint(t *testing.T) {
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	empty := ""
	hb := &asmv1.Heartbeat{HostId: hostID, RunId: "r1", Seq: 9, At: at, FirewallFingerprint: &fp,
		Tamper: &asmv1.TamperStatus{Checks: []string{"probes"}}}
	got, _ := formatEvent("asm."+hostID+".heartbeat", mustMarshal(t, hb))
	if want := "2026-10-30T14:02:11.418Z 01234567 seq=9 HEARTBEAT drops=0/0 tamper=ok fw=0123456789ab"; got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	hb.FirewallFingerprint = &empty // the firewall is not fully readable
	got, _ = formatEvent("asm."+hostID+".heartbeat", mustMarshal(t, hb))
	if want := "2026-10-30T14:02:11.418Z 01234567 seq=9 HEARTBEAT drops=0/0 tamper=ok fw=-"; got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	for _, bad := range []string{"abc", strings.ToUpper(fp), "\x1b[31mred" + fp[11:]} {
		hb.FirewallFingerprint = &bad
		got, _ = formatEvent("asm."+hostID+".heartbeat", mustMarshal(t, hb))
		if want := "2026-10-30T14:02:11.418Z 01234567 seq=9 HEARTBEAT drops=0/0 tamper=ok fw=?"; got != want {
			t.Fatalf("invalid %q: got %q, want %q", bad, got, want)
		}
	}
	snap := &asmv1.Snapshot{HostId: hostID, RunId: "r1", Seq: 1, TakenAt: at, Host: &asmv1.HostInfo{FirewallFingerprint: &fp}}
	got, _ = formatEvent("asm."+hostID+".snapshot", mustMarshal(t, snap))
	if want := "2026-10-30T14:02:11.418Z 01234567 seq=1 SNAPSHOT n=0 tcp=0 udp=0 fw=0123456789ab"; got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
