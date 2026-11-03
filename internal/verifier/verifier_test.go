package verifier

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestTargets(t *testing.T) {
	s := Scope{Allow: prefixes("203.0.113.0/24", "2001:db8::/32", "10.231.0.0/24"),
		HostAddresses: map[string][]netip.Addr{"h1": {netip.MustParseAddr("10.231.0.1"), netip.MustParseAddr("192.168.9.9")}}}
	hi := &asmv1.HostInfo{PublicIps: []*asmv1.PublicIP{
		{Ip: "203.0.113.7", Dir: "in"}, {Ip: "2001:db8::7", Dir: "in"}, {Ip: "198.51.100.4", Dir: "out"}}}
	l := func(addr string, port uint32) *asmv1.Listener {
		return &asmv1.Listener{Proto: "tcp", Addr: addr, Port: port, Key: addr}
	}
	str := func(ts []Target) string {
		var out []string
		for _, t := range ts {
			out = append(out, t.Proto+":"+t.String())
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		l    *asmv1.Listener
		lvl  int
		ev   []string
		want string
	}{
		{l("0.0.0.0", 443), 3, nil, "tcp:203.0.113.7:443,tcp:10.231.0.1:443"},
		{l("::", 443), 3, nil, "tcp:203.0.113.7:443,tcp:[2001:db8::7]:443,tcp:10.231.0.1:443"},
		{l("203.0.113.9", 22), 2, nil, "tcp:203.0.113.9:22"},
		{l("192.168.9.9", 22), 2, nil, ""}, // outside the allowlist
		{l("127.0.0.1", 22), 2, nil, ""},   // loopback
		{l("0.0.0.0", 22), 1, nil, ""},     // local
		{l("0.0.0.0", 80), 3, []string{"bind:any", "nat: dnat tcp/18090 -> 172.17.0.2:80"}, "tcp:203.0.113.7:18090,tcp:10.231.0.1:18090"},
	}
	for _, c := range cases {
		got, why := s.Targets("h1", c.l, c.lvl, c.ev, hi)
		if str(got) != c.want || (c.want == "" && why == "") {
			t.Errorf("%s:%d lvl %d: got %q (%s), want %q", c.l.Addr, c.l.Port, c.lvl, str(got), why, c.want)
		}
	}
	if got, _ := (Scope{}).Targets("h1", l("203.0.113.9", 22), 3, nil, hi); len(got) != 0 {
		t.Fatal("an empty allowlist must allow nothing")
	}
}

func loopback(port int) Target {
	return Target{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: uint16(port)}
}

func TestTCPProbes(t *testing.T) {
	p := NewProber()
	p.Timeout, p.BannerWait = time.Second, 300*time.Millisecond
	// A server that speaks first.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n\x00\xff"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	r := p.Probe(context.Background(), loopback(port))
	if r.Result != ResultConfirmed || r.Banner != `SSH-2.0-OpenSSH_9.6\r\n\x00\xff` || r.Probe != "tcp-connect" {
		t.Fatalf("%+v", r)
	}
	// Closed port.
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()
	if r := p.Probe(context.Background(), loopback(closed)); r.Result != ResultUnreachable || r.Detail != "connect: connection refused" {
		t.Fatalf("closed: %+v", r)
	}
	// HTTP: HEAD with the fixed User-Agent, status line only, redirect not followed.
	var ua string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ua = r.Header.Get("User-Agent") + " " + r.Method
		mu.Unlock()
		http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
	}))
	defer srv.Close()
	hp := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	p.HTTPPorts = map[uint16]bool{hp.Port(): true}
	r = p.Probe(context.Background(), loopback(int(hp.Port())))
	mu.Lock()
	defer mu.Unlock()
	if r.Result != ResultConfirmed || r.Probe != "http-head" || r.Banner != `HTTP/1.0 302 Found\r\n` || ua != "portwarden-verifier/1 HEAD" {
		t.Fatalf("http: %+v ua %q", r, ua)
	}
}

func TestUDPProbes(t *testing.T) {
	p := NewProber()
	p.Timeout = 500 * time.Millisecond
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 512)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		got <- append([]byte(nil), buf[:n]...)
		// A DNS answer: same id, QR set, rcode 0, one answer.
		pc.WriteTo([]byte{0x50, 0x57, 0x80, 0x00, 0, 1, 0, 1, 0, 0, 0, 0}, from)
	}()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	// Point the DNS probe at this port by probing as port 53's protocol.
	orig := udpProbes[53]
	udpProbes[port] = orig
	defer delete(udpProbes, port)
	r := p.Probe(context.Background(), Target{Proto: "udp", Addr: netip.MustParseAddr("127.0.0.1"), Port: port})
	if r.Result != ResultConfirmed || r.Banner != "dns: rcode=0 answers=1" || r.Probe != "dns" {
		t.Fatalf("%+v", r)
	}
	if q := <-got; string(q) != string(orig.data) {
		t.Fatalf("sent %x", q)
	}
	// Silence is no_response, never closed.
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	r = p.Probe(context.Background(), Target{Proto: "udp", Addr: netip.MustParseAddr("127.0.0.1"), Port: uint16(silent.LocalAddr().(*net.UDPAddr).Port)})
	if r.Result != ResultNoResponse || !strings.Contains(r.Detail, "not closed") {
		t.Fatalf("silent: %+v", r)
	}
	// A closed port answers with ICMP port unreachable.
	c, _ := net.ListenPacket("udp", "127.0.0.1:0")
	closed := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()
	if r := p.Probe(context.Background(), Target{Proto: "udp", Addr: netip.MustParseAddr("127.0.0.1"), Port: closed}); r.Result != ResultUnreachable {
		t.Fatalf("closed udp: %+v", r)
	}
}

func TestVerifierSchedulesAndLimits(t *testing.T) {
	var mu sync.Mutex
	var probed []string
	var published []*asmv1.ExposureConfirmation
	probe := func(_ context.Context, t Target) Result {
		mu.Lock()
		probed = append(probed, t.String())
		mu.Unlock()
		if t.Addr.Is6() {
			return Result{Result: ResultUnreachable, Probe: "tcp-connect", Target: t, Detail: "connect: connection refused"}
		}
		return Result{Result: ResultConfirmed, Probe: "tcp-connect", Target: t, Banner: "hi"}
	}
	pub := func(_ context.Context, subject, _ string, m proto.Message) error {
		mu.Lock()
		defer mu.Unlock()
		if subject != "asm.h1.exposure.confirmed" {
			t.Errorf("subject %s", subject)
		}
		published = append(published, m.(*asmv1.ExposureConfirmation))
		return nil
	}
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	v := New(Scope{Allow: prefixes("0.0.0.0/0", "::/0")}, probe, pub, "verifier-run", "probe-1", Limits{GlobalPerSecond: 1000, PerHostPerMinute: 6000})
	v.Now = func() time.Time { return now }
	ev := &asmv1.ExposureEvent{
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "::", Port: 443, Key: "k443"},
		Exposure: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN},
		Host:     &asmv1.HostInfo{PublicIps: []*asmv1.PublicIP{{Ip: "2001:db8::7", Dir: "in"}, {Ip: "203.0.113.7", Dir: "in"}}},
	}
	ctx := context.Background()
	v.Exposure(ctx, "h1", ev)
	v.Wait()
	v.Exposure(ctx, "h1", ev) // within MinGap: skipped
	v.Wait()
	if len(probed) != 2 || len(published) != 1 {
		t.Fatalf("probed %v published %d", probed, len(published))
	}
	c := published[0]
	if c.GetResult() != ResultConfirmed || c.GetTarget() != "203.0.113.7:443" || c.GetSeq() != 0 || c.GetOrigin() != "verifier" ||
		c.GetExposure().GetLevel() != asmv1.ExposureLevel_EXPOSURE_CONFIRMED || !strings.Contains(c.GetDetail(), "[2001:db8::7]:443 unreachable") {
		t.Fatalf("published %v", c)
	}
	// A snapshot within Reprobe does not probe again; after it, it does.
	snap := &asmv1.Snapshot{Host: ev.Host, Listeners: []*asmv1.ListenerState{{Listener: ev.Listener, Exposure: ev.Exposure}}}
	now = now.Add(time.Hour)
	v.Snapshot(ctx, "h1", snap)
	v.Wait()
	if len(published) != 1 {
		t.Fatal("snapshot re-probed within reprobe")
	}
	now = now.Add(25 * time.Hour)
	v.Snapshot(ctx, "h1", snap)
	v.Wait()
	if len(published) != 2 {
		t.Fatal("snapshot did not re-probe after reprobe")
	}
}

func TestPerHostRateLimit(t *testing.T) {
	var mu sync.Mutex
	var n int
	probe := func(_ context.Context, t Target) Result {
		mu.Lock()
		n++
		mu.Unlock()
		return Result{Result: ResultConfirmed, Target: t}
	}
	v := New(Scope{Allow: prefixes("0.0.0.0/0")}, probe, func(context.Context, string, string, proto.Message) error { return nil },
		"r", "c", Limits{GlobalPerSecond: 1000, PerHostPerMinute: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for port := uint32(1); port <= 5; port++ {
		v.Exposure(ctx, "h1", &asmv1.ExposureEvent{Listener: &asmv1.Listener{Proto: "tcp", Addr: "203.0.113.1", Port: port, Key: string(rune('a' + port))},
			Exposure: &asmv1.Exposure{Level: asmv1.ExposureLevel_EXPOSURE_BOUND}})
	}
	v.Wait()
	if n != 2 {
		t.Fatalf("per-host limit 2/min allowed %d probes in 300 ms", n)
	}
}
