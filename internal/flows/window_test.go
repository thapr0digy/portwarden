package flows

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
)

var t0 = time.Date(2026, 11, 19, 14, 0, 0, 0, time.UTC)

const testHost = "4f1c2a9e7b3d4c5e8f9a0b1c2d3e4f5a"

// checkValid holds each event to Signal's validator, as the door would.
func checkValid(t *testing.T, flows []*eventsv1.HostFlows) {
	t.Helper()
	for i, f := range flows {
		e := &eventsv1.Event{
			Id: fmt.Sprintf("01JC8Z6X4Q000000000000%04d", i), Type: "asm.host.flows",
			Source: "urn:asm:agent:" + testHost, Subject: "host:" + testHost,
			Time: f.GetWindowEnd(), Sequence: &eventsv1.Sequence{RunId: "01JC8Z6X4P9QK2M3N5R7T8V0WA", Seq: uint64(i + 1)},
			Data: &eventsv1.Event_HostFlows{HostFlows: f},
		}
		if err := validate.Event(e, validate.Options{Now: func() time.Time { return f.GetWindowEnd().AsTime() }}); err != nil {
			t.Fatalf("event %d: Signal refuses it: %v", i, err)
		}
	}
}

func out(remote string, at time.Duration) Conn {
	return Conn{Direction: Out, Exe: "/opt/billing/bin/billing", Comm: "billing", Unit: "billing.service",
		Remote: netip.MustParseAddrPort(remote), App: AppTLS, Service: "ledger.internal.example", At: t0.Add(at)}
}

func in(remote string, port uint16, at time.Duration) Conn {
	return Conn{Direction: In, Exe: "/usr/sbin/nginx", Comm: "nginx", Unit: "nginx.service", LocalPort: port,
		Remote: netip.MustParseAddrPort(remote), At: t0.Add(at)}
}

func TestWindowAggregatesByKey(t *testing.T) {
	w := NewWindow(t0)
	w.Add(out("10.0.0.9:443", time.Minute))
	w.Add(out("10.0.0.9:443", 30*time.Minute))
	w.Add(out("10.0.0.9:443", 10*time.Minute))
	named := out("10.0.0.9:443", 5*time.Minute)
	named.Service = "other.internal.example"
	w.Add(named)
	w.Add(in("10.0.0.7:51234", 443, 2*time.Minute))
	w.Add(in("10.0.0.7:51999", 443, 3*time.Minute)) // another ephemeral port: the same row
	got := w.Flush(t0.Add(time.Hour))
	checkValid(t, got)
	if len(got) != 1 || len(got[0].GetFlows()) != 3 {
		t.Fatalf("flows = %v", got)
	}
	f := got[0].GetFlows()
	if f[0].GetDirection() != In || f[0].GetCount() != 2 || f[0].GetLocalPort() != 443 || f[0].GetRemotePort() != 0 || f[0].GetRemoteAddr() != "10.0.0.7" {
		t.Errorf("in row = %v", f[0])
	}
	if f[1].GetServiceName() != "ledger.internal.example" || f[1].GetCount() != 3 || f[1].GetLocalPort() != 0 || f[1].GetRemotePort() != 443 ||
		!f[1].GetFirstSeen().AsTime().Equal(t0.Add(time.Minute)) || !f[1].GetLastSeen().AsTime().Equal(t0.Add(30*time.Minute)) {
		t.Errorf("out row = %v", f[1])
	}
	if f[2].GetServiceName() != "other.internal.example" || f[2].GetCount() != 1 {
		t.Errorf("second out row = %v", f[2])
	}
}

// An inbound row never names a public client: they are summed per port into remote_addr "".
func TestWindowSumsPublicInboundClients(t *testing.T) {
	w := NewWindow(t0)
	for i, a := range []string{"203.0.113.5:1000", "198.51.100.7:1001", "[2001:db8::5]:1002", "8.8.8.8:1003"} {
		w.Add(in(a, 443, time.Duration(i)*time.Minute))
	}
	w.Add(in("10.0.0.7:1004", 443, time.Minute))
	w.Add(out("203.0.113.5:443", time.Minute)) // outbound keeps the public address
	got := w.Flush(t0.Add(time.Hour))
	checkValid(t, got)
	f := got[0].GetFlows()
	if len(f) != 3 || f[0].GetRemoteAddr() != "" || f[0].GetCount() != 4 || f[1].GetRemoteAddr() != "10.0.0.7" || f[2].GetRemoteAddr() != "203.0.113.5" {
		t.Fatalf("flows = %v", f)
	}
}

// The agent's public rule is Signal's: every non-public peer is kept, and Signal takes it.
func TestPublicRuleMatchesSignal(t *testing.T) {
	for _, a := range []string{"10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "100.127.255.254", "127.0.0.1",
		"169.254.1.1", "::1", "fe80::1", "fd12::1", "::ffff:10.0.0.1", "203.0.113.5", "100.128.0.1", "2001:db8::1", "1.1.1.1"} {
		w := NewWindow(t0)
		w.Add(in(netip.AddrPortFrom(netip.MustParseAddr(a), 1).String(), 22, 0))
		got := w.Flush(t0.Add(time.Hour))
		checkValid(t, got)
		kept := got[0].GetFlows()[0].GetRemoteAddr() != ""
		if kept == publicIP(netip.MustParseAddr(a)) {
			t.Errorf("%s: kept %v", a, kept)
		}
	}
}

// A host serving many clients cannot crowd out the connections it makes.
func TestWindowCapsEachDirection(t *testing.T) {
	w := NewWindow(t0)
	for i := range MaxFlowsPerDirection + 10 {
		w.Add(in(fmt.Sprintf("10.%d.%d.1:1", i/256, i%256), 443, 0))
	}
	w.Add(out("10.0.0.9:443", 0))
	got := w.Flush(t0.Add(time.Hour))
	checkValid(t, got)
	var ins, outs int
	for _, e := range got {
		for _, f := range e.GetFlows() {
			if f.GetDirection() == In {
				ins++
			} else {
				outs++
			}
		}
	}
	if ins != MaxFlowsPerDirection || outs != 1 || got[0].GetDropped() != 10 {
		t.Errorf("in %d, out %d, dropped %d", ins, outs, got[0].GetDropped())
	}
}

// A window too large for one event is split over several with the same bounds, each under
// Signal's 1 MiB cap, together holding every row once.
func TestWindowSplitsUnderTheEventCap(t *testing.T) {
	w := NewWindow(t0)
	long := "/opt/" + strings.Repeat("a", 900)
	for i := range 2 * MaxFlowsPerDirection {
		c := out(fmt.Sprintf("10.%d.%d.1:443", i/256, i%256), 0)
		c.Exe = long
		if i%2 == 1 {
			c = in(fmt.Sprintf("10.%d.%d.2:1", i/256, i%256), 443, 0)
			c.Exe = long
		}
		w.Add(c)
	}
	got := w.Flush(t0.Add(time.Hour))
	checkValid(t, got)
	if len(got) < 2 {
		t.Fatalf("%d events, want a split", len(got))
	}
	total := 0
	for _, e := range got {
		total += len(e.GetFlows())
		if !e.GetWindowStart().AsTime().Equal(t0) || !e.GetWindowEnd().AsTime().Equal(t0.Add(time.Hour)) {
			t.Errorf("bounds %v-%v", e.GetWindowStart().AsTime(), e.GetWindowEnd().AsTime())
		}
	}
	if total != 2*MaxFlowsPerDirection {
		t.Errorf("%d rows, want %d", total, 2*MaxFlowsPerDirection)
	}
}

// Process fields Signal would refuse (control characters, invalid UTF-8, over its caps) are
// made valid, so one odd process name never loses the whole window.
func TestWindowCleansProcessFields(t *testing.T) {
	w := NewWindow(t0)
	c := out("10.0.0.9:443", 0)
	c.Comm, c.Exe, c.Unit = "a\x1bb\xffcdefghijklmnopq", "/opt/"+strings.Repeat("x", maxExe), "bad\nunit.service"
	w.Add(c)
	got := w.Flush(t0.Add(time.Hour))
	checkValid(t, got)
	f := got[0].GetFlows()[0]
	if f.GetComm() != "a?b?cdefghijklmn" || f.GetExe() != "" || f.GetUnit() != "bad?unit.service" {
		t.Errorf("comm %q exe %q unit %q", f.GetComm(), f.GetExe(), f.GetUnit())
	}
}

// An empty window is still a window: Signal tells "none" from "not observed".
func TestWindowEmptyIsSent(t *testing.T) {
	got := NewWindow(t0).Flush(t0.Add(time.Hour))
	checkValid(t, got)
	if len(got) != 1 || !got[0].GetRead() || len(got[0].GetFlows()) != 0 {
		t.Errorf("empty window = %v", got)
	}
}

// Times are held within the window, so a clock step never makes Signal refuse it.
func TestWindowClampsTimes(t *testing.T) {
	w := NewWindow(t0)
	w.Add(out("10.0.0.9:443", -time.Minute))
	w.Add(out("10.0.0.9:443", 2*time.Hour))
	got := w.Flush(t0.Add(time.Hour))
	checkValid(t, got)
	f := got[0].GetFlows()[0]
	if !f.GetFirstSeen().AsTime().Equal(t0) || !f.GetLastSeen().AsTime().Equal(t0.Add(time.Hour)) {
		t.Errorf("first %v last %v", f.GetFirstSeen().AsTime(), f.GetLastSeen().AsTime())
	}
}

func TestWindowFlushStartsTheNext(t *testing.T) {
	w := NewWindow(t0)
	w.Add(out("10.0.0.9:443", 0))
	w.Flush(t0.Add(time.Hour))
	got := w.Flush(t0.Add(2 * time.Hour))
	if !got[0].GetWindowStart().AsTime().Equal(t0.Add(time.Hour)) || len(got[0].GetFlows()) != 0 || got[0].GetDropped() != 0 {
		t.Errorf("next window = %v", got[0])
	}
}
