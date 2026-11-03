package verifier

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
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

func req(addr string, port uint32, lvl asmv1.ExposureLevel, addrs []string, ports ...uint32) *asmv1.ProbeRequest {
	return &asmv1.ProbeRequest{Listener: &asmv1.Listener{Proto: "tcp", Addr: addr, Port: port, Key: addr + ":" + strconv.Itoa(int(port))},
		Level: lvl, Addresses: addrs, Ports: ports, Proto: "tcp"}
}

func TestTargets(t *testing.T) {
	s := Scope{Allow: prefixes("54.239.1.0/24", "2600:1f18::/32", "10.231.0.0/24", "10.9.0.0/16"),
		HostAddresses: map[string][]netip.Addr{"h1": {netip.MustParseAddr("10.231.0.1"), netip.MustParseAddr("192.168.9.9")}}}
	str := func(ts []Target) string {
		var out []string
		for _, t := range ts {
			out = append(out, t.Proto+":"+t.String())
		}
		return strings.Join(out, ",")
	}
	open := asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN
	cases := []struct {
		r    *asmv1.ProbeRequest
		want string
	}{
		{req("0.0.0.0", 443, open, []string{"54.239.1.7"}, 443), "tcp:54.239.1.7:443,tcp:10.231.0.1:443"},
		{req("::", 443, open, []string{"54.239.1.7", "2600:1f18::7"}, 443), "tcp:54.239.1.7:443,tcp:[2600:1f18::7]:443,tcp:10.231.0.1:443"},
		// A private address the request names but the operator did not list is refused,
		// even inside the allowlist; a public one outside the allowlist too.
		{req("10.9.0.5", 22, open, []string{"10.9.0.5"}, 22), ""},
		{req("0.0.0.0", 22, open, []string{"198.51.100.1"}, 22), "tcp:10.231.0.1:22"},
		{req("0.0.0.0", 22, asmv1.ExposureLevel_EXPOSURE_LOCAL, nil, 22), ""},
		{req("0.0.0.0", 80, open, []string{"54.239.1.7"}, 18090), "tcp:54.239.1.7:18090,tcp:10.231.0.1:18090"},
	}
	for _, c := range cases {
		got, why := s.Targets("h1", c.r)
		if str(got) != c.want || (c.want == "" && why == "") {
			t.Errorf("%s: got %q (%s), want %q", c.r.Listener.Key, str(got), why, c.want)
		}
	}
	// Caps: at most 4 addresses x 4 ports whatever the request says.
	var many []string
	for i := range 20 {
		many = append(many, "54.239.1."+strconv.Itoa(i+1))
	}
	big := req("0.0.0.0", 1, open, many, 1, 2, 3, 4, 5, 6, 7, 8)
	if got, _ := (Scope{Allow: prefixes("54.239.1.0/24")}).Targets("h9", big); len(got) != MaxAddresses*MaxPorts {
		t.Fatalf("caps: %d targets", len(got))
	}
	if got, _ := (Scope{}).Targets("h1", req("54.239.1.9", 22, open, []string{"54.239.1.9"}, 22)); len(got) != 0 {
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

func TestVerifierRequestsAndLimits(t *testing.T) {
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
		if subject != "pwb.verifier.h1.exposure" {
			t.Errorf("subject %s", subject)
		}
		published = append(published, m.(*asmv1.ExposureConfirmation))
		return nil
	}
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	v := New(Scope{Allow: prefixes("0.0.0.0/0", "::/0")}, probe, pub, "verifier-run", "probe-1", Limits{GlobalPerSecond: 1000, PerHostPerMinute: 6000})
	v.Now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := v.Start(ctx)
	r := req("::", 443, asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN, []string{"2600:1f18::7", "54.239.1.7"}, 443)
	v.Request("h1", r)
	v.Wait()
	v.Request("h1", r) // within MinGap: skipped
	v.Wait()
	if len(probed) != 2 || len(published) != 1 {
		t.Fatalf("probed %v published %d", probed, len(published))
	}
	c := published[0]
	if c.GetResult() != ResultConfirmed || c.GetTarget() != "54.239.1.7:443" || c.GetSeq() != 0 || c.GetOrigin() != "verifier" ||
		c.GetExposure().GetLevel() != asmv1.ExposureLevel_EXPOSURE_CONFIRMED || !strings.Contains(c.GetDetail(), "[2600:1f18::7]:443 unreachable") {
		t.Fatalf("published %v", c)
	}
	now = now.Add(time.Minute)
	v.Request("h1", r)
	v.Wait()
	if len(published) != 2 {
		t.Fatal("not probed again after MinGap")
	}
	cancel()
	wait()
}

// The queue is bounded: with no worker running, requests beyond it are dropped and
// counted, never blocking the consumer.
func TestBoundedQueue(t *testing.T) {
	v := New(Scope{Allow: prefixes("0.0.0.0/0")}, func(context.Context, Target) Result { return Result{} },
		func(context.Context, string, string, proto.Message) error { return nil }, "r", "c", Limits{Queue: 3})
	for i := range 10 {
		v.Request("h", req("54.239.1.1", uint32(1000+i), asmv1.ExposureLevel_EXPOSURE_BOUND, []string{"54.239.1.1"}))
	}
	if v.Dropped.Load() != 7 || len(v.queue) != 3 {
		t.Fatalf("dropped %d queued %d", v.Dropped.Load(), len(v.queue))
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
	wait := v.Start(ctx)
	for port := uint32(1); port <= 5; port++ {
		v.Request("h1", req("54.239.1.1", port, asmv1.ExposureLevel_EXPOSURE_BOUND, []string{"54.239.1.1"}))
	}
	<-ctx.Done()
	wait()
	if n != 2 {
		t.Fatalf("per-host limit 2/min allowed %d probes in 300 ms", n)
	}
}

func TestHostHeaderBrackets(t *testing.T) {
	if h := hostHeader(Target{Addr: netip.MustParseAddr("2001:db8::1")}); h != "[2001:db8::1]" {
		t.Fatal(h)
	}
}
