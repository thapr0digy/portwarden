//go:build linux && integration

package baseline

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/exposure"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/probes"
	"github.com/thapr0digy/portwarden/internal/state"
)

// v6Socket opens a [::] socket of the given type with IPV6_V6ONLY set as asked, binds
// it to an explicit free port (a UDP socket bound to port 0 is a client, never a
// listener) and listens, for TCP; it returns its fd, port and cookie.
func v6Socket(t *testing.T, typ int, v6only bool) (int, uint16, uint64) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	flag := 0
	if v6only {
		flag = 1
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, flag); err != nil {
		t.Fatal(err)
	}
	bound := false
	for port := 41000 + os.Getpid()%1000; port < 49000 && !bound; port += 7 {
		bound = unix.Bind(fd, &unix.SockaddrInet6{Port: port}) == nil
	}
	if !bound {
		t.Fatal("no free port")
	}
	if typ == unix.SOCK_STREAM {
		if err := unix.Listen(fd, 8); err != nil {
			t.Fatal(err)
		}
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	return fd, uint16(sa.(*unix.SockaddrInet6).Port), cookie
}

// Real [::] sockets, v6-only and dual-stack, TCP and UDP: the live probe and the
// baseline snapshot both report the kernel's IPV6_V6ONLY, and the judgement of a host
// with an IPv4-only uplink and no filter rules follows it: a dual-stack socket is open
// on IPv4, a v6-only one has no external address to be reached on.
func TestV6OnlyRealSockets(t *testing.T) {
	p, err := probes.Start()
	if err != nil {
		t.Fatalf("probes: %+v", err)
	}
	defer p.Close()

	type sock struct {
		name   string
		proto  string
		typ    int
		v6only bool
		port   uint16
		cookie uint64
	}
	socks := []*sock{
		{name: "tcp v6-only", proto: model.ProtoTCP, typ: unix.SOCK_STREAM, v6only: true},
		{name: "tcp dual-stack", proto: model.ProtoTCP, typ: unix.SOCK_STREAM},
		{name: "udp v6-only", proto: model.ProtoUDP, typ: unix.SOCK_DGRAM, v6only: true},
		{name: "udp dual-stack", proto: model.ProtoUDP, typ: unix.SOCK_DGRAM},
	}
	byCookie := map[uint64]*sock{}
	for _, s := range socks {
		_, s.port, s.cookie = v6Socket(t, s.typ, s.v6only)
		byCookie[s.cookie] = s
	}
	want := func(s *sock) model.V6Only {
		if s.v6only {
			return model.V6OnlyOn
		}
		return model.V6OnlyOff
	}

	// The live probe's Opened events.
	seen := map[uint64]bool{}
	deadline := time.After(2 * time.Second)
	for len(seen) < len(socks) {
		select {
		case o := <-p.Events():
			s, ok := byCookie[o.Cookie]
			if !ok || o.Kind != model.Opened {
				continue
			}
			seen[o.Cookie] = true
			if o.V6Only != want(s) {
				t.Errorf("probe, %s: V6Only %v, want %v", s.name, o.V6Only, want(s))
			}
		case <-deadline:
			for _, s := range socks {
				if !seen[s.cookie] {
					t.Errorf("probe: no Opened for %s (port %d, cookie %#x)", s.name, s.port, s.cookie)
				}
			}
			t.Fatalf("probe saw %d of %d sockets", len(seen), len(socks))
		}
	}

	// The baseline snapshot (inet_diag for TCP, iter/udp for UDP, owner records).
	obs, err := Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	table := state.New(0)
	found := map[uint64]bool{}
	for _, o := range obs {
		s, ok := byCookie[o.Cookie]
		if !ok {
			continue
		}
		found[o.Cookie] = true
		if o.V6Only != want(s) {
			t.Errorf("snapshot, %s: V6Only %v, want %v", s.name, o.V6Only, want(s))
		}
		table.Apply(o)
	}
	if len(found) != len(socks) {
		t.Fatalf("snapshot listed %d of %d sockets", len(found), len(socks))
	}

	// The judgement.
	hostNS, err := HostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	fw, err := exposure.Merge(exposure.MergeInput{NFT: []byte(`{"nftables":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	ifs := []netif.Interface{
		{Name: "eth0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}},
		{Name: "lo", Up: true, Loopback: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
	}
	judged := exposure.NewView("start", hostNS, fw, nil, ifs, nil).Judge(table.Snapshot())
	for _, s := range socks {
		k := model.NewKey(hostNS, s.proto, netip.IPv6Unspecified(), s.port)
		e, ok := judged[k]
		if !ok {
			t.Fatalf("%s: not judged", s.name)
		}
		wantLevel, wantEv := model.ExposureHostFirewallOpen, "bind:any"
		if s.v6only {
			wantLevel, wantEv = model.ExposureBound, "bind:any (IPv6 only)"
		}
		if e.Level != wantLevel || len(e.Evidence) == 0 || e.Evidence[0] != wantEv {
			t.Errorf("%s: %v %q, want %v starting %q", s.name, e.Level, e.Evidence, wantLevel, wantEv)
		}
	}
}
