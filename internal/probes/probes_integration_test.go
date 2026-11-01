//go:build linux && integration

package probes

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/listener-watch/internal/model"
)

const eventWait = 500 * time.Millisecond

func hostNetNS(t *testing.T) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatalf("stat netns: %v", err)
	}
	return uint32(st.Ino)
}

func startProbes(t *testing.T) *Probes {
	t.Helper()
	p, err := Start(hostNetNS(t))
	if err != nil {
		t.Fatalf("Start: %+v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return p
}

// collectOwn gathers this process's observations until the window elapses.
func collectOwn(t *testing.T, p *Probes, window time.Duration) []model.Observation {
	t.Helper()
	var got []model.Observation
	deadline := time.After(window)
	for {
		select {
		case o, ok := <-p.Events():
			if !ok {
				t.Fatal("events channel closed")
			}
			if o.Proc.PID == uint32(os.Getpid()) {
				got = append(got, o)
			}
		case <-deadline:
			return got
		}
	}
}

// waitFor returns the first observation of this process matching match, or fails after eventWait.
func waitFor(t *testing.T, p *Probes, match func(model.Observation) bool) model.Observation {
	t.Helper()
	deadline := time.After(eventWait)
	var seen []model.Observation
	for {
		select {
		case o, ok := <-p.Events():
			if !ok {
				t.Fatal("events channel closed")
			}
			if o.Proc.PID == uint32(os.Getpid()) && match(o) {
				return o
			}
			seen = append(seen, o)
		case <-deadline:
			drops, foreign := p.Counters()
			t.Fatalf("no matching observation within %s (pid %d); saw %+v; ringbuf drops %d, foreign netns %d",
				eventWait, os.Getpid(), seen, drops, foreign)
			return model.Observation{}
		}
	}
}

func openedOnPort(port uint16) func(model.Observation) bool {
	return func(o model.Observation) bool { return o.Kind == model.Opened && o.Key.Port == port }
}

func closedWithCookie(cookie uint64) func(model.Observation) bool {
	return func(o model.Observation) bool { return o.Kind == model.Closed && o.Cookie == cookie }
}

func socketCookie(t *testing.T, fd int) uint64 {
	t.Helper()
	c, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatalf("SO_COOKIE: %v", err)
	}
	return c
}

func boundPort(t *testing.T, fd int) uint16 {
	t.Helper()
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return uint16(a.Port)
	case *unix.SockaddrInet6:
		return uint16(a.Port)
	}
	t.Fatalf("unexpected sockaddr %T", sa)
	return 0
}

func tcp4Socket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func TestOpenBoundPort(t *testing.T) {
	p := startProbes(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	o := waitFor(t, p, openedOnPort(port))
	if o.Key.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Addr = %v, want 127.0.0.1", o.Key.Addr)
	}
	if o.Key.Proto != "tcp" || o.Key.NetNS != hostNetNS(t) {
		t.Errorf("Key = %v, want tcp in host netns", o.Key)
	}
	if o.Source != model.SourceEBPF || o.Cookie == 0 || o.At.IsZero() {
		t.Errorf("observation = %+v, want ebpf source, a cookie and a time", o)
	}
	if exe, _ := os.Executable(); o.Proc.Exe != exe {
		t.Errorf("Exe = %q, want %q", o.Proc.Exe, exe)
	}
	if o.Proc.UID != uint32(os.Getuid()) {
		t.Errorf("UID = %d, want %d", o.Proc.UID, os.Getuid())
	}
}

func TestOpenAutoPort(t *testing.T) {
	p := startProbes(t)
	fd := tcp4Socket(t)
	if err := unix.Listen(fd, 16); err != nil {
		t.Fatal(err)
	}
	port := boundPort(t, fd)
	if port == 0 {
		t.Fatal("kernel assigned port 0")
	}
	cookie := socketCookie(t, fd)
	o := waitFor(t, p, func(o model.Observation) bool { return o.Kind == model.Opened && o.Cookie == cookie })
	if o.Key.Port != port {
		t.Errorf("Port = %d, want %d", o.Key.Port, port)
	}
}

func TestFailedListenEmitsNothing(t *testing.T) {
	p := startProbes(t)
	first, second := tcp4Socket(t), tcp4Socket(t)
	for _, fd := range []int{first, second} {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Bind(first, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	port := boundPort(t, first)
	if err := unix.Bind(second, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: int(port)}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(first, 16); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(second, 16); !errors.Is(err, unix.EADDRINUSE) {
		t.Fatalf("second listen: err = %v, want EADDRINUSE", err)
	}

	var opened, closed int
	for _, o := range collectOwn(t, p, eventWait) {
		switch o.Kind {
		case model.Opened:
			opened++
		case model.Closed:
			closed++
		}
	}
	if opened != 1 || closed != 0 {
		t.Errorf("got %d opened, %d closed; want 1 and 0", opened, closed)
	}
}

func TestCloseEmitted(t *testing.T) {
	p := startProbes(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		t.Fatal(err)
	}
	cookie := socketCookie(t, fd)
	waitFor(t, p, func(o model.Observation) bool { return o.Kind == model.Opened && o.Cookie == cookie })

	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	o := waitFor(t, p, closedWithCookie(cookie))
	if o.Key != (model.ListenerKey{}) {
		t.Errorf("close Key = %v, want zero", o.Key)
	}
	if o.Source != model.SourceEBPF || o.At.IsZero() {
		t.Errorf("close observation = %+v, want ebpf source and a time", o)
	}
}

func TestShutdownReadEmitsClosed(t *testing.T) {
	p := startProbes(t)
	fd := tcp4Socket(t)
	if err := unix.Listen(fd, 16); err != nil {
		t.Fatal(err)
	}
	cookie := socketCookie(t, fd)
	waitFor(t, p, func(o model.Observation) bool { return o.Kind == model.Opened && o.Cookie == cookie })

	if err := unix.Shutdown(fd, unix.SHUT_RD); err != nil {
		t.Fatal(err)
	}
	waitFor(t, p, closedWithCookie(cookie))

	if err := unix.Listen(fd, 16); err != nil {
		t.Fatal(err)
	}
	waitFor(t, p, func(o model.Observation) bool { return o.Kind == model.Opened && o.Cookie == cookie })
}

// enableBPFStats turns on kernel.bpf_stats_enabled and restores the previous value at cleanup.
func enableBPFStats(t *testing.T) {
	t.Helper()
	const path = "/proc/sys/kernel/bpf_stats_enabled"
	prev, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(path, prev, 0); err != nil {
			t.Errorf("restore bpf_stats_enabled: %v", err)
		}
	})
}

func runCounts(t *testing.T, p *Probes) (open, close uint64) {
	t.Helper()
	open, close, err := p.RunCounts()
	if err != nil {
		t.Fatal(err)
	}
	return open, close
}

func TestConnectionsRunNoProgram(t *testing.T) {
	enableBPFStats(t)
	p := startProbes(t)
	open0, close0 := runCounts(t, p)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	const roundTrips = 1000
	go func() {
		for range roundTrips {
			c, err := ln.Accept()
			if err != nil {
				accepted <- err
				return
			}
			c.Close()
		}
		accepted <- nil
	}()
	for range roundTrips {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}

	open1, close1 := runCounts(t, p)
	if open1-open0 != 1 || close1 != close0 {
		t.Errorf("after %d connections: open runs +%d, close runs +%d; want +1 and +0", roundTrips, open1-open0, close1-close0)
	}
	ln.Close()
	if _, close2 := runCounts(t, p); close2-close0 != 1 {
		t.Errorf("after closing the listener: close runs +%d, want +1", close2-close0)
	}
}

func TestDualStackSingleListener(t *testing.T) {
	p := startProbes(t)
	ln, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var opened []model.Observation
	for _, o := range collectOwn(t, p, eventWait) {
		if o.Kind == model.Opened && o.Key.Port == port {
			opened = append(opened, o)
		}
	}
	if len(opened) != 1 {
		t.Fatalf("got %d opened for port %d, want 1: %+v", len(opened), port, opened)
	}
	if opened[0].Key.Addr != netip.IPv6Unspecified() {
		t.Errorf("Addr = %v, want ::", opened[0].Key.Addr)
	}
}

// inFreshNetns runs f on a locked thread moved into a new network namespace, then moves
// the thread back before the goroutine exits. The runtime discards a thread whose locked
// goroutine exits, except the main thread, which it parks instead; left in the fresh
// netns, that thread would make /proc/self/ns/net (the thread-group leader's) name the
// wrong namespace for every later test.
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
			ferr := f()
			if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
				return errors.Join(ferr, fmt.Errorf("restore netns: %w", err))
			}
			return ferr
		}()
	}()
	return <-done
}

// listenInNewNetns listens on 127.0.0.1 inside a fresh network namespace.
func listenInNewNetns() error {
	return inFreshNetns(func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
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
		if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			return err
		}
		return unix.Listen(fd, 16)
	})
}

func TestOtherNetnsDropped(t *testing.T) {
	p := startProbes(t)
	if err := listenInNewNetns(); err != nil {
		t.Fatal(err)
	}
	if got := collectOwn(t, p, eventWait); len(got) != 0 {
		t.Errorf("got %d observations from another netns, want none: %+v", len(got), got)
	}
	if _, foreign := p.Counters(); foreign < 1 {
		t.Errorf("foreignNetns = %d, want >= 1", foreign)
	}
}

// tcp6Listener listens on addr (port 0) with a raw AF_INET6 socket, IPV6_V6ONLY off, and
// returns its fd and port.
func tcp6Listener(t *testing.T, addr netip.Addr) (int, uint16) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: addr.As16()}); err != nil {
		t.Fatalf("bind %v: %v", addr, err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		t.Fatal(err)
	}
	return fd, boundPort(t, fd)
}

func TestOpenIPv6Loopback(t *testing.T) {
	p := startProbes(t)
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	o := waitFor(t, p, openedOnPort(port))
	if o.Key.Addr != netip.IPv6Loopback() {
		t.Errorf("Addr = %v, want ::1", o.Key.Addr)
	}
	if want := model.NewKey(hostNetNS(t), "tcp", netip.IPv6Loopback(), port); o.Key != want {
		t.Errorf("Key = %v, want %v", o.Key, want)
	}
}

func TestOpenV4MappedKeysAsIPv4(t *testing.T) {
	p := startProbes(t)
	fd, port := tcp6Listener(t, netip.MustParseAddr("::ffff:127.0.0.1"))
	cookie := socketCookie(t, fd)

	o := waitFor(t, p, func(o model.Observation) bool { return o.Kind == model.Opened && o.Cookie == cookie })
	if o.Key.Addr != netip.MustParseAddr("127.0.0.1") || o.Key.Port != port {
		t.Errorf("Key = %v, want 127.0.0.1:%d (unmapped)", o.Key, port)
	}
	if o.Key.String() != model.NewKey(hostNetNS(t), "tcp", netip.MustParseAddr("127.0.0.1"), port).String() {
		t.Errorf("Key string = %q", o.Key.String())
	}
}
