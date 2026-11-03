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
	if _, err := s.pool.Exec(ctx, "TRUNCATE hosts, listeners, exposure_history, proxies"); err != nil {
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
	e := inventory.Event{Meta: inventory.Meta{Host: h1, Kind: kind, StreamSeq: streamSeq, StreamTime: time.Now()}, Cursor: cur, Msg: m}
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
	apply(t, s, nil, "exposure.changed", cloud)
	streamSeq-- // a redelivery of the same stream message
	apply(t, s, nil, "exposure.changed", cloud)
	if l := listener(t, s, 8080); l.Level != "cloud_open" || l.CloudLevel != "cloud_open" {
		t.Fatalf("after cloud: %+v", l)
	}
	apply(t, s, nil, "exposure.confirmed", &asmv1.ExposureConfirmation{HostId: h1, RunId: "verifier-1", Result: "confirmed",
		Listener: snap.Listeners[1].Listener, Target: "54.1.2.3:8080", Probe: "tcp-connect", Banner: "HTTP/1.0 200"})
	if l := listener(t, s, 8080); l.Level != "confirmed" || l.ProbeResult != "confirmed" || l.ProbeAt == nil {
		t.Fatalf("after probe: %+v", l)
	}
	hist, err := s.History(ctx, h1, snap.Listeners[1].Listener.Key, 0)
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
	if err != nil || !ok || ch.InstanceID != "i-1" || len(ch.Listeners) != 1 {
		t.Fatalf("cloud host %+v %v %v", ch, ok, err)
	}
}
