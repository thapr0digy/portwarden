//go:build linux && integration

package baseline

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/listener-watch/internal/model"
	"github.com/thapr0digy/listener-watch/internal/probes"
)

// listen opens a listener the way Go does by default, which is MPTCP when the kernel
// supports it: the fd is the MPTCP socket and its TCP subflow is the listener inet_diag
// and the probe see.
func listen(t *testing.T, address string) (*net.TCPListener, uint16) {
	t.Helper()
	return listenWith(t, net.ListenConfig{}, address)
}

func listenWith(t *testing.T, lc net.ListenConfig, address string) (*net.TCPListener, uint16) {
	t.Helper()
	ln, err := lc.Listen(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.(*net.TCPListener), uint16(ln.Addr().(*net.TCPAddr).Port)
}

// sockopt reads an integer SOL_SOCKET option of the listener's fd.
func sockopt(t *testing.T, ln *net.TCPListener, get func(fd int) (uint64, error)) uint64 {
	t.Helper()
	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value uint64
	var sockErr error
	if err := raw.Control(func(fd uintptr) { value, sockErr = get(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatalf("getsockopt: %v", sockErr)
	}
	return value
}

func listenerCookie(t *testing.T, ln *net.TCPListener) uint64 {
	t.Helper()
	return sockopt(t, ln, func(fd int) (uint64, error) {
		return unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	})
}

func isMPTCP(t *testing.T, ln *net.TCPListener) bool {
	t.Helper()
	protocol := sockopt(t, ln, func(fd int) (uint64, error) {
		p, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
		return uint64(p), err
	})
	return protocol == unix.IPPROTO_MPTCP
}

func snapshot(t *testing.T) []model.Observation {
	t.Helper()
	obs, err := Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %+v", err)
	}
	return obs
}

func ownObservations(obs []model.Observation) []model.Observation {
	var own []model.Observation
	for _, o := range obs {
		if o.Proc.PID == uint32(os.Getpid()) {
			own = append(own, o)
		}
	}
	return own
}

func TestSnapshotSeesOwnListener(t *testing.T) {
	plainTCP := net.ListenConfig{}
	plainTCP.SetMultipathTCP(false)
	cases := []struct {
		name string
		lc   net.ListenConfig
	}{
		{"mptcp (Go default)", net.ListenConfig{}},
		{"plain tcp", plainTCP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, port := listenWith(t, tc.lc, "127.0.0.1:0")
			if got := isMPTCP(t, ln); got != tc.lc.MultipathTCP() {
				t.Fatalf("listener is MPTCP = %v, want %v", got, tc.lc.MultipathTCP())
			}
			checkOwnListener(t, ln, port)
		})
	}
}

func checkOwnListener(t *testing.T, ln *net.TCPListener, port uint16) {
	t.Helper()
	netns, err := HostNetNS()
	if err != nil {
		t.Fatal(err)
	}

	own := ownObservations(snapshot(t))
	if len(own) != 1 {
		t.Fatalf("got %d observations owned by this process, want 1: %+v", len(own), own)
	}
	o := own[0]
	wantKey := model.NewKey(netns, "tcp", netip.MustParseAddr("127.0.0.1"), port)
	if o.Kind != model.Opened || o.Source != model.SourceBaseline || o.Key != wantKey || o.At.IsZero() || o.Cookie == 0 {
		t.Errorf("observation = %+v, want baseline Opened %v with a cookie and a time", o, wantKey)
	}
	// SO_COOKIE of an MPTCP fd is the MPTCP socket's own cookie, not its subflow's.
	if !isMPTCP(t, ln) && o.Cookie != listenerCookie(t, ln) {
		t.Errorf("Cookie = %#x, want SO_COOKIE %#x", o.Cookie, listenerCookie(t, ln))
	}
	comm, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSuffix(string(comm), "\n"); o.Proc.Comm != want {
		t.Errorf("Comm = %q, want %q", o.Proc.Comm, want)
	}
	if exe, _ := os.Executable(); o.Proc.Exe != exe {
		t.Errorf("Exe = %q, want %q", o.Proc.Exe, exe)
	}
	if o.Proc.UID != uint32(os.Getuid()) {
		t.Errorf("UID = %d, want %d", o.Proc.UID, os.Getuid())
	}
}

// An MPTCP listener's subflow has no cookie until something asks for one, and the owners
// iterator can only read it (bpf/owners.bpf.c). In the VM's host netns Lima's guest agent
// lists listeners and so assigns cookies; a fresh netns is listed by nobody else.
func TestSnapshotOwnsUnlistedMPTCPListener(t *testing.T) {
	type result struct {
		port uint16
		obs  []model.Observation
		err  error
	}
	done := make(chan result, 1)
	go func() {
		// The thread stays locked and is discarded when the goroutine exits.
		runtime.LockOSThread()
		var r result
		r.port, r.obs, r.err = snapshotInFreshNetns()
		done <- r
	}()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	own := ownObservations(r.obs)
	if len(own) != 1 || own[0].Key.Port != r.port || own[0].Cookie == 0 {
		t.Fatalf("snapshot observations owned by this process = %+v, want one on port %d with a cookie", own, r.port)
	}
}

// snapshotInFreshNetns moves the calling (locked) thread into a new network namespace,
// opens an MPTCP listener there and takes a snapshot from that thread.
func snapshotInFreshNetns() (uint16, []model.Observation, error) {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return 0, nil, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, nil, err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return 0, nil, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return 0, nil, err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return 0, nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	defer ln.Close()
	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var protocol int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		protocol, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	}); err != nil {
		return 0, nil, err
	}
	if sockErr != nil || protocol != unix.IPPROTO_MPTCP {
		return 0, nil, fmt.Errorf("listener in the fresh netns has protocol %d (%v), want MPTCP", protocol, sockErr)
	}
	obs, err := Snapshot()
	return uint16(ln.Addr().(*net.TCPAddr).Port), obs, err
}

func TestSnapshotCookieMatchesEBPF(t *testing.T) {
	netns, err := HostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	p, err := probes.Start(netns)
	if err != nil {
		t.Fatalf("probes.Start: %+v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("probes.Close: %v", err)
		}
	})

	_, port := listen(t, "[::]:0")
	var probeCookie uint64
	deadline := time.After(time.Second)
	for probeCookie == 0 {
		select {
		case o, ok := <-p.Events():
			if !ok {
				t.Fatalf("probe events closed: %v", p.Err())
			}
			if o.Kind == model.Opened && o.Key.Port == port && o.Proc.PID == uint32(os.Getpid()) {
				probeCookie = o.Cookie
			}
		case <-deadline:
			t.Fatal("no probe observation for the listener")
		}
	}

	own := ownObservations(snapshot(t))
	if len(own) != 1 || own[0].Key.Port != port {
		t.Fatalf("snapshot observations owned by this process = %+v, want one on port %d", own, port)
	}
	if own[0].Cookie != probeCookie {
		t.Errorf("snapshot cookie %#x != probe cookie %#x", own[0].Cookie, probeCookie)
	}
}

func TestSnapshotIgnoresEstablished(t *testing.T) {
	ln, port := listen(t, "127.0.0.1:0")
	const connections = 100
	accepted := make(chan net.Conn, connections)
	go func() {
		for range connections {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range connections {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	for range connections {
		select {
		case c := <-accepted:
			t.Cleanup(func() { _ = c.Close() })
		case <-time.After(5 * time.Second):
			t.Fatal("connections not accepted")
		}
	}

	own := ownObservations(snapshot(t))
	if len(own) != 1 || own[0].Key.Port != port {
		t.Fatalf("snapshot observations owned by this process = %+v, want only the listener on port %d", own, port)
	}

	socks, err := Listeners()
	if err != nil {
		t.Fatal(err)
	}
	onPort := 0
	for _, s := range socks {
		if s.Port == port {
			onPort++
		}
	}
	if onPort != 1 {
		t.Errorf("dump holds %d sockets on port %d, want only the listener", onPort, port)
	}
}

func TestSnapshotIPv6Loopback(t *testing.T) {
	_, port := listen(t, "[::1]:0")
	own := ownObservations(snapshot(t))
	if len(own) != 1 || own[0].Key.Port != port {
		t.Fatalf("snapshot observations owned by this process = %+v, want one on port %d", own, port)
	}
	if own[0].Key.Addr != netip.IPv6Loopback() {
		t.Errorf("Addr = %v, want ::1", own[0].Key.Addr)
	}
}

func TestSnapshotV4MappedKeysAsIPv4(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
		t.Fatal(err)
	}
	mapped := netip.MustParseAddr("::ffff:127.0.0.1")
	if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: mapped.As16()}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(sa.(*unix.SockaddrInet6).Port)

	own := ownObservations(snapshot(t))
	if len(own) != 1 || own[0].Key.Port != port {
		t.Fatalf("snapshot observations owned by this process = %+v, want one on port %d", own, port)
	}
	if own[0].Key.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Addr = %v, want 127.0.0.1 (unmapped)", own[0].Key.Addr)
	}
}
