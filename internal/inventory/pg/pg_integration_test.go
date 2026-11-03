//go:build integration

package pg

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/inventory"
)

// open connects to the database dev/itest.sh creates for this run (a throwaway database
// and role with a generated password, PORTWARDEN_TEST_PG) and empties it.
func open(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("PORTWARDEN_TEST_PG")
	if dsn == "" {
		t.Fatal("PORTWARDEN_TEST_PG is not set; run the integration tests through dev/itest.sh")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.pool.Exec(ctx, "TRUNCATE hosts, listeners, exposure_history, proxies, quarantine, forgotten_hosts"); err != nil {
		t.Fatal(err)
	}
	return s
}

const h1 = "host1"

func lst(port uint32, unit string) *asmv1.ListenerState {
	return &asmv1.ListenerState{
		Listener:  &asmv1.Listener{Netns: 1, Proto: "tcp", Addr: "0.0.0.0", Port: port, Key: "1/tcp/0.0.0.0:" + itoa(port)},
		Processes: []*asmv1.Process{{Pid: 10, Exe: "/usr/bin/app", Unit: unit}},
		Exposure:  &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN, Evidence: []string{"bind:any"}},
	}
}

func itoa(n uint32) string { return strconv.Itoa(int(n)) }

var streamSeq uint64

func apply(t *testing.T, s *Store, cur *inventory.Cursor, kind string, m proto.Message) {
	t.Helper()
	streamSeq++
	origin := ""
	switch kind {
	case "cloud", "verifier":
		origin, kind = kind, "exposure"
	}
	e := inventory.Event{Meta: inventory.Meta{Host: h1, Kind: kind, Origin: origin, StreamSeq: streamSeq, StreamTime: time.Now()}, Cursor: cur, Msg: m}
	if err := s.Apply(context.Background(), e); err != nil {
		t.Fatalf("%s: %v", kind, err)
	}
}

func listener(t *testing.T, s *Store, port int) inventory.ListenerView {
	t.Helper()
	ls, err := s.Listeners(context.Background(), inventory.ListenerFilter{Host: h1, Port: port})
	if err != nil || len(ls) != 1 {
		t.Fatalf("listener :%d: %v %v", port, ls, err)
	}
	return ls[0]
}

func TestMigrateTwice(t *testing.T) {
	s := open(t)
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestStoreLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	host := &asmv1.HostInfo{Cloud: "aws", InstanceId: "i-1", Region: "eu-west-1", PublicIps: []*asmv1.PublicIP{{Ip: "54.1.2.3", Via: "imds", Dir: "in"}}}
	snap := &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 1, Host: host,
		Listeners: []*asmv1.ListenerState{lst(22, "ssh.service"), lst(8080, "app.service")},
		Proxies:   []*asmv1.ProxyState{{Proxy: &asmv1.Proxy{Id: "nginx/1/x", Kind: "nginx"}, RouteCount: 1}}}
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 1}, "snapshot", snap)

	cur, ok, err := s.Cursor(ctx, h1)
	if err != nil || !ok || cur.LastSeq != 1 || cur.RunID != "01A" {
		t.Fatalf("cursor %+v %v %v", cur, ok, err)
	}
	hv, ok, err := s.Host(ctx, h1)
	if err != nil || !ok || hv.Listeners != 2 || hv.Region != "eu-west-1" || hv.LastSnapshotAt == nil {
		t.Fatalf("host %+v %v %v", hv, ok, err)
	}
	if l := listener(t, s, 22); l.Level != "host_firewall_open" || l.AgentLevel != "host_firewall_open" {
		t.Fatalf("22: %+v", l)
	}
	byUnit, err := s.Listeners(ctx, inventory.ListenerFilter{Unit: "app.service"})
	if err != nil || len(byUnit) != 1 || byUnit[0].Port != 8080 {
		t.Fatalf("by unit: %+v %v", byUnit, err)
	}
	injected, err := s.Listeners(ctx, inventory.ListenerFilter{Unit: "x'); DROP TABLE hosts; --", Exe: "' OR 1=1 --"})
	if err != nil || len(injected) != 0 {
		t.Fatalf("injection filter: %+v %v", injected, err)
	}
	if _, ok, _ := s.Host(ctx, h1); !ok {
		t.Fatal("hosts table damaged")
	}

	// Cloud verdict, then the verifier: the effective level rises to 4, then 5.
	cloud := &asmv1.ExposureEvent{HostId: h1, RunId: "cloud-1", Origin: "cloud", Trigger: "cloud",
		Listener: snap.Listeners[1].Listener,
		Exposure: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN, Evidence: []string{"cloud: sg-1 allows tcp/8080 from 0.0.0.0/0"}}}
	apply(t, s, nil, "cloud", cloud)
	streamSeq-- // a redelivery of the same stream message
	apply(t, s, nil, "cloud", cloud)
	if l := listener(t, s, 8080); l.Level != "cloud_open" || l.CloudLevel != "cloud_open" {
		t.Fatalf("after cloud: %+v", l)
	}
	apply(t, s, nil, "verifier", &asmv1.ExposureConfirmation{HostId: h1, RunId: "verifier-1", Result: "confirmed",
		Listener: snap.Listeners[1].Listener, Target: "54.1.2.3:8080", Probe: "tcp-connect", Banner: "HTTP/1.0 200"})
	if l := listener(t, s, 8080); l.Level != "confirmed" || l.ProbeResult != "confirmed" || l.ProbeAt == nil {
		t.Fatalf("after probe: %+v", l)
	}
	hist, err := s.History(ctx, inventory.HistoryQuery{Host: h1, Key: snap.Listeners[1].Listener.Key})
	if err != nil || len(hist) != 3 { // snapshot, cloud (once), verifier
		t.Fatalf("history %+v %v", hist, err)
	}
	if hist[0].Origin != "verifier" || hist[1].Origin != "cloud" || hist[2].Origin != "agent" {
		t.Fatalf("history order %+v", hist)
	}

	// Agent drops the level: effective stays at the probe's.
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 2}, "exposure.changed", &asmv1.ExposureEvent{HostId: h1, RunId: "01A", Seq: 2,
		Listener: snap.Listeners[0].Listener, Trigger: "firewall",
		Exposure: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_BOUND}, Previous: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN}})
	if l := listener(t, s, 22); l.Level != "bound" {
		t.Fatalf("22 after firewall: %+v", l)
	}
	high, err := s.Listeners(ctx, inventory.ListenerFilter{MinLevel: 3})
	if err != nil || len(high) != 1 || high[0].Port != 8080 {
		t.Fatalf("min_level 3: %+v %v", high, err)
	}

	// Closed; a listener opened; a second snapshot without :8080 removes it.
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 3}, "listener.closed", &asmv1.ListenerEvent{HostId: h1, RunId: "01A", Seq: 3,
		Kind: asmv1.Kind_CLOSED, Listener: snap.Listeners[0].Listener})
	if ls, _ := s.Listeners(ctx, inventory.ListenerFilter{Host: h1, Port: 22}); len(ls) != 0 {
		t.Fatal(":22 still there after CLOSED")
	}
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 4}, "snapshot", &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 4,
		Listeners: []*asmv1.ListenerState{lst(9090, "")}})
	if ls, _ := s.Listeners(ctx, inventory.ListenerFilter{Host: h1}); len(ls) != 1 || ls[0].Port != 9090 {
		t.Fatalf("after snapshot: %+v", ls)
	}
	if ps, _ := s.Proxies(ctx, h1, ""); len(ps) != 0 {
		t.Fatalf("proxy not in the snapshot kept: %+v", ps)
	}

	// Proxy routes.
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 5}, "proxy.routes", &asmv1.ProxyRoutes{HostId: h1, RunId: "01A", Seq: 5,
		Proxy: &asmv1.Proxy{Id: "nginx/1/y", Kind: "nginx"}, Trigger: "started",
		Routes: []*asmv1.ProxyRoute{{Path: "/", Kind: "proxy", Target: "http://app"}}})
	ps, err := s.Proxies(ctx, h1, "nginx/1/y")
	if err != nil || len(ps) != 1 || ps[0].RouteCount != 1 || !strings.Contains(string(ps[0].Routes), `"target":"http://app"`) &&
		!strings.Contains(string(ps[0].Routes), `"target": "http://app"`) {
		t.Fatalf("proxies %+v %v", ps, err)
	}
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 6}, "proxy.routes", &asmv1.ProxyRoutes{HostId: h1, RunId: "01A", Seq: 6,
		Proxy: &asmv1.Proxy{Id: "nginx/1/y"}, Removed: true})
	if ps, _ := s.Proxies(ctx, h1, ""); len(ps) != 0 {
		t.Fatal("removed proxy kept")
	}

	// Heartbeats and silence.
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 7}, "heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: 7, QueueDrops: 3})
	last, err := s.LastHeartbeats(ctx)
	if err != nil || last[h1].IsZero() {
		t.Fatalf("last heartbeats %v %v", last, err)
	}
	if err := s.SetSilent(ctx, h1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if hv, _, _ := s.Host(ctx, h1); !hv.Silent || hv.QueueDrops != 3 {
		t.Fatalf("host after silence %+v", hv)
	}
	if err := s.SetSilent(ctx, h1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if hv, _, _ := s.Host(ctx, h1); hv.Silent {
		t.Fatal("host still silent")
	}

	ch, ok, err := s.CloudHost(ctx, h1)
	if err != nil || !ok || ch.InstanceID != "i-1" || ch.Resource != "" || len(ch.Listeners) != 1 {
		t.Fatalf("cloud host %+v %v %v", ch, ok, err)
	}

	// M10: the cloud resource round-trips to the look-up and the API.
	gcp := &asmv1.HostInfo{Cloud: "gcp", InstanceId: "4419012345678", Region: "us-central1",
		CloudResource: "projects/acme-prod/zones/us-central1-a/instances/4419012345678"}
	apply(t, s, &inventory.Cursor{RunID: "01A", LastSeq: 2}, "host.changed", &asmv1.HostEvent{HostId: h1, RunId: "01A", Seq: 2, Host: gcp})
	ch, _, err = s.CloudHost(ctx, h1)
	if err != nil || ch.Resource != gcp.CloudResource || ch.Cloud != "gcp" {
		t.Fatalf("cloud host after host.changed %+v %v", ch, err)
	}
	if hv, _, _ := s.Host(ctx, h1); hv.CloudResource != gcp.CloudResource {
		t.Fatalf("api host %+v", hv)
	}
}

// NUL bytes and invalid UTF-8 (which PostgreSQL rejects) are cleaned, so one host's bad
// strings never stop the consumer; the cursor's new fields round-trip.
func TestBadStringsAndCursorFields(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	bad := &asmv1.ListenerState{
		Listener:  &asmv1.Listener{Netns: 1, Proto: "tcp", Addr: "0.0.0.0", Port: 80, Key: "1/tcp/0.0.0.0:80\x00evil"},
		Processes: []*asmv1.Process{{Pid: 1, Exe: "/bin/a\x00b\xff", Cmdline: []string{"x\x00y"}}},
		Exposure:  &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_BOUND, Evidence: []string{"nul\x00here"}},
	}
	cur := &inventory.Cursor{RunID: "01A", LastSeq: 1, BootID: "boot-1", RunNumber: 4, Retired: []string{"01Z"}}
	apply(t, s, cur, "snapshot", &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 1, Listeners: []*asmv1.ListenerState{bad},
		Host: &asmv1.HostInfo{Region: "eu\x00", PublicIps: []*asmv1.PublicIP{{Ip: "203.0.113.7", Dir: "in"}}}})
	ls, err := s.Listeners(ctx, inventory.ListenerFilter{Host: h1})
	if err != nil || len(ls) != 1 || ls[0].Key != "1/tcp/0.0.0.0:80evil" {
		t.Fatalf("%+v %v", ls, err)
	}
	got, ok, err := s.Cursor(ctx, h1)
	if err != nil || !ok || got.BootID != "boot-1" || got.RunNumber != 4 || len(got.Retired) != 1 || got.Retired[0] != "01Z" {
		t.Fatalf("cursor %+v %v %v", got, ok, err)
	}
	in, ok, err := s.ProbeInput(ctx, h1, ls[0].Key)
	if err != nil || !ok || in.Level != 2 || len(in.InboundIPs) != 1 || in.InboundIPs[0] != "203.0.113.7" {
		t.Fatalf("probe input %+v %v %v", in, ok, err)
	}
	stale, err := s.StaleProbes(ctx, time.Now(), 10)
	if err != nil || len(stale) != 1 {
		t.Fatalf("stale %v %v", stale, err)
	}
	if err := s.Quarantine(ctx, 42, "asm.h.x\x00", "bad\x00", []byte{0, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM quarantine WHERE stream_seq = 42").Scan(&n)
	if n != 1 {
		t.Fatal("quarantine row missing")
	}
}

// Through the consumer: a message carrying NUL bytes is applied (cleaned), and the next
// message after it is applied too.
func TestConsumerNULDoesNotStall(t *testing.T) {
	s := open(t)
	c := &inventory.Consumer{Store: s}
	ctx := context.Background()
	msgs := []struct {
		subject string
		m       proto.Message
	}{
		{"asm." + h1 + ".snapshot", &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 1}},
		{"asm." + h1 + ".listener.opened", &asmv1.ListenerEvent{HostId: h1, RunId: "01A", Seq: 2, Kind: asmv1.Kind_OPENED,
			Listener:  &asmv1.Listener{Netns: 1, Proto: "tcp", Addr: "0.0.0.0", Port: 81, Key: "k\x0081"},
			Processes: []*asmv1.Process{{Comm: "nul\x00comm"}}}},
		{"asm." + h1 + ".listener.opened", &asmv1.ListenerEvent{HostId: h1, RunId: "01A", Seq: 3, Kind: asmv1.Kind_OPENED,
			Listener: &asmv1.Listener{Netns: 1, Proto: "tcp", Addr: "0.0.0.0", Port: 82, Key: "k82"}}},
	}
	for i, m := range msgs {
		b, _ := proto.Marshal(m.m)
		if err := c.Handle(ctx, m.subject, b, inventory.Meta{StreamSeq: uint64(1000 + i), StreamTime: time.Now()}); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	ls, err := s.Listeners(ctx, inventory.ListenerFilter{Host: h1})
	if err != nil || len(ls) != 2 {
		t.Fatalf("%+v %v", ls, err)
	}
}

// M7: the host's firewall fingerprint and when it last changed, through the consumer so
// run and sequence order apply as in production.
func TestFirewallFingerprint(t *testing.T) {
	s := open(t)
	c := &inventory.Consumer{Store: s}
	ctx := context.Background()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	var n uint64
	send := func(kind string, m proto.Message, at time.Time) {
		t.Helper()
		n++
		subject := "asm." + h1 + "." + kind
		if kind == "cloud" {
			subject = "pwb.cloud." + h1 + ".exposure"
		}
		b, _ := proto.Marshal(m)
		if err := c.Handle(ctx, subject, b, inventory.Meta{StreamSeq: 2000 + n, StreamTime: at}); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	fp := func(s string) *string { return &s }
	host := func() inventory.HostView {
		t.Helper()
		hv, ok, err := s.Host(ctx, h1)
		if err != nil || !ok {
			t.Fatalf("host %v %v", ok, err)
		}
		return hv
	}
	beat := func(seq uint64, f *string) *asmv1.Heartbeat {
		return &asmv1.Heartbeat{HostId: h1, RunId: "01A", Seq: seq, BootId: "b1", RunNumber: 3, FirewallFingerprint: f}
	}
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)

	// An agent without M7: nothing known.
	send("snapshot", &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 1, BootId: "b1", RunNumber: 3, Host: &asmv1.HostInfo{Cloud: "aws"}}, t0)
	if hv := host(); hv.FirewallFingerprint != nil || hv.FirewallChangedAt != nil {
		t.Fatalf("no fingerprint sent, stored %v %v", hv.FirewallFingerprint, hv.FirewallChangedAt)
	}
	// First sight sets both.
	send("heartbeat", beat(2, fp(a)), t0.Add(time.Minute))
	if hv := host(); hv.FirewallFingerprint == nil || *hv.FirewallFingerprint != a || !hv.FirewallChangedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("first sight: %+v", hv)
	}
	// The same value (heartbeat, a snapshot's host block) leaves changed_at; a heartbeat
	// without one (absent) leaves both.
	send("heartbeat", beat(3, fp(a)), t0.Add(2*time.Minute))
	send("snapshot", &asmv1.Snapshot{HostId: h1, RunId: "01A", Seq: 4, BootId: "b1", RunNumber: 3, Host: &asmv1.HostInfo{FirewallFingerprint: fp(a)}}, t0.Add(3*time.Minute))
	send("heartbeat", beat(5, nil), t0.Add(4*time.Minute))
	if hv := host(); *hv.FirewallFingerprint != a || !hv.FirewallChangedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("unchanged: %+v", hv)
	}
	// A cloud verdict's host block is never the agent's firewall.
	send("cloud", &asmv1.ExposureEvent{HostId: h1, RunId: "cloud-1", Trigger: "cloud", Listener: &asmv1.Listener{Key: "k"},
		Exposure: &asmv1.Exposure{}, Host: &asmv1.HostInfo{FirewallFingerprint: fp(b)}}, t0.Add(5*time.Minute))
	if hv := host(); *hv.FirewallFingerprint != a {
		t.Fatalf("cloud event set it: %+v", hv)
	}
	// A change (an exposure event's host block) moves changed_at to the message's time.
	send("exposure.changed", &asmv1.ExposureEvent{HostId: h1, RunId: "01A", Seq: 7, BootId: "b1", RunNumber: 3, Trigger: "firewall",
		Listener: &asmv1.Listener{Key: "k"}, Exposure: &asmv1.Exposure{}, Host: &asmv1.HostInfo{FirewallFingerprint: fp(b)}}, t0.Add(6*time.Minute))
	if hv := host(); *hv.FirewallFingerprint != b || !hv.FirewallChangedAt.Equal(t0.Add(6*time.Minute)) {
		t.Fatalf("changed: %+v", hv)
	}
	// seq 6 arrives late (after 7, a gap): skipped, so it cannot roll the value back.
	send("heartbeat", beat(6, fp(a)), t0.Add(7*time.Minute))
	// A leftover of an earlier run of the same boot: skipped.
	send("heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "00Z", Seq: 99, BootId: "b1", RunNumber: 2, FirewallFingerprint: fp(a)}, t0.Add(8*time.Minute))
	if hv := host(); *hv.FirewallFingerprint != b || !hv.FirewallChangedAt.Equal(t0.Add(6*time.Minute)) {
		t.Fatalf("a stale message rolled it back: %+v", hv)
	}
	// Unreadable ("") is unknown: the last good value stays and changed_at does not move.
	send("heartbeat", beat(8, fp("")), t0.Add(9*time.Minute))
	send("heartbeat", beat(9, fp(b)), t0.Add(10*time.Minute)) // X, "", X: no change
	if hv := host(); *hv.FirewallFingerprint != b || !hv.FirewallChangedAt.Equal(t0.Add(6*time.Minute)) {
		t.Fatalf("X, \"\", X: %+v", hv)
	}
	// Invalid values are ignored; the message's other effects still apply.
	send("heartbeat", beat(10, fp("iptables -A INPUT -j ACCEPT")), t0.Add(11*time.Minute))
	send("heartbeat", beat(11, fp(strings.ToUpper(a))), t0.Add(12*time.Minute))
	if hv := host(); *hv.FirewallFingerprint != b || hv.LastSeq != 11 {
		t.Fatalf("invalid fingerprint stored or message dropped: %+v", hv)
	}
	// A restart (a new run) with the same rules: no change.
	send("snapshot", &asmv1.Snapshot{HostId: h1, RunId: "01B", Seq: 1, BootId: "b1", RunNumber: 4, Host: &asmv1.HostInfo{FirewallFingerprint: fp(b)}}, t0.Add(13*time.Minute))
	if hv := host(); hv.RunID != "01B" || *hv.FirewallFingerprint != b || !hv.FirewallChangedAt.Equal(t0.Add(6*time.Minute)) {
		t.Fatalf("a restart with the same rules moved changed_at: %+v", hv)
	}
	// X, "", Y: one change, at Y.
	send("heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01B", Seq: 2, BootId: "b1", RunNumber: 4, FirewallFingerprint: fp("")}, t0.Add(14*time.Minute))
	send("heartbeat", &asmv1.Heartbeat{HostId: h1, RunId: "01B", Seq: 3, BootId: "b1", RunNumber: 4, FirewallFingerprint: fp(a)}, t0.Add(15*time.Minute))
	if hv := host(); *hv.FirewallFingerprint != a || !hv.FirewallChangedAt.Equal(t0.Add(15*time.Minute)) {
		t.Fatalf("X, \"\", Y: %+v", hv)
	}
}
