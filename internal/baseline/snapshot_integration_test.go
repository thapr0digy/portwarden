//go:build linux && integration

package baseline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/probes"
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
	var port uint16
	var obs []model.Observation
	err := inFreshNetns(func() error {
		var err error
		port, obs, err = snapshotWithMPTCPListener()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	own := ownObservations(obs)
	if len(own) != 1 || own[0].Key.Port != port || own[0].Cookie == 0 {
		t.Fatalf("snapshot observations owned by this process = %+v, want one on port %d with a cookie", own, port)
	}
}

// inFreshNetns runs f on a locked thread moved into a new network namespace (with its
// loopback up), then moves the thread back before the goroutine exits. The runtime
// discards a thread whose locked goroutine exits, except the main thread, which it parks
// instead; left in the fresh netns, that thread would make /proc/self/ns/net (HostNetNS)
// name the wrong namespace for every later test. Copied from internal/probes' tests.
func inFreshNetns(f func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		done <- func() error {
			orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			defer unix.Close(orig)
			if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
				return err
			}
			ferr := loopbackUp()
			if ferr == nil {
				ferr = f()
			}
			if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
				return errors.Join(ferr, fmt.Errorf("restore netns: %w", err))
			}
			return ferr
		}()
	}()
	return <-done
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// snapshotWithMPTCPListener opens an MPTCP listener in the calling thread's netns and
// takes a snapshot from that thread.
func snapshotWithMPTCPListener() (uint16, []model.Observation, error) {
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
	p, err := probes.Start()
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

func TestSnapshotHasUDPBind(t *testing.T) {
	netns, err := HostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9433})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	own := ownObservations(snapshot(t))
	if len(own) != 1 {
		t.Fatalf("got %d observations owned by this process, want 1: %+v", len(own), own)
	}
	o := own[0]
	if want := model.NewKey(netns, model.ProtoUDP, netip.MustParseAddr("127.0.0.1"), 9433); o.Key != want {
		t.Errorf("Key = %v, want %v", o.Key, want)
	}
	if want := udpCookie(t, conn); o.Cookie != want {
		t.Errorf("Cookie = %#x, want SO_COOKIE %#x", o.Cookie, want)
	}
	if o.Proc.CgroupID == 0 || o.Proc.Comm == "" || o.Proc.UID != uint32(os.Getuid()) {
		t.Errorf("Proc = %+v, want comm, uid %d and a cgroup id", o.Proc, os.Getuid())
	}
}

func udpCookie(t *testing.T, c *net.UDPConn) uint64 {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatalf("getsockopt SO_COOKIE: %v", sockErr)
	}
	return cookie
}

// A dialled UDP socket is autobound to an ephemeral port: a client, not a listener.
func TestSnapshotSkipsUDPClientSocket(t *testing.T) {
	conn, err := net.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	for _, o := range snapshot(t) {
		if o.Key.Proto == model.ProtoUDP && o.Key.Port == port {
			t.Errorf("client socket reported: %+v", o)
		}
	}
}

// A listener in another netns (as in a container) is keyed with that netns, from the
// owners iterator alone: the host's inet_diag dump does not list it.
func TestSnapshotHasContainerNetnsListener(t *testing.T) {
	host, err := HostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	var netns uint32
	var port uint16
	err = inFreshNetns(func() error {
		var st unix.Stat_t
		if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
			return err
		}
		netns = uint32(st.Ino)
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			return err
		}
		if err := unix.Listen(fd, 16); err != nil {
			return err
		}
		sa, err := unix.Getsockname(fd)
		if err != nil {
			return err
		}
		port = uint16(sa.(*unix.SockaddrInet4).Port)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if netns == host {
		t.Fatalf("fresh netns %d is the host netns", netns)
	}

	own := ownObservations(snapshot(t))
	if len(own) != 1 {
		t.Fatalf("got %d observations owned by this process, want 1: %+v", len(own), own)
	}
	if want := model.NewKey(netns, model.ProtoTCP, netip.MustParseAddr("127.0.0.1"), port); own[0].Key != want || own[0].Cookie == 0 {
		t.Errorf("observation = %+v, want key %v with a cookie", own[0], want)
	}
}

// A VXLAN device's UDP socket is the kernel's: it has no file, so no owner, and only
// iter/udp sees it.
func TestSnapshotHasKernelUDPSocket(t *testing.T) {
	netns, err := HostNetNS()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ip", "link", "add", "pwvx0", "type", "vxlan", "id", "42", "dstport", "4789", "dev", "lo").CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Unknown device type") {
			t.Skipf("vxlan module unavailable: ip link add: %s", strings.TrimSpace(string(out)))
		}
		t.Fatalf("ip link add pwvx0: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "link", "del", "pwvx0").CombinedOutput(); err != nil {
			t.Errorf("ip link del pwvx0: %v: %s", err, out)
		}
	})
	if out, err := exec.Command("ip", "link", "set", "pwvx0", "up").CombinedOutput(); err != nil {
		t.Fatalf("ip link set pwvx0 up: %v: %s", err, out)
	}

	var found []model.Observation
	for _, o := range snapshot(t) {
		if o.Key.Proto == model.ProtoUDP && o.Key.Port == 4789 {
			found = append(found, o)
		}
	}
	if len(found) == 0 {
		t.Fatal("no udp observation on port 4789")
	}
	for _, o := range found {
		if o.Key.NetNS != netns || !o.Key.Addr.IsUnspecified() || !o.Proc.IsZero() || o.Cookie == 0 {
			t.Errorf("observation = %+v, want host udp 0.0.0.0:4789 or [::]:4789 with a cookie and no process", o)
		}
	}
}
