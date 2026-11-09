//go:build linux && integration

package admin

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/caddy"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/discover"
	"github.com/thapr0digy/portwarden/internal/proxy/haproxy"
)

// The live tests run as root in the VM (dev/itest.sh) against real Caddy and HAProxy
// processes they start, through the production Host: openat2 and SO_PEERCRED for Unix
// sockets, /proc/<pid>/net/tcp and the fd table for TCP.

func liveHost() ProcHost {
	p := discover.NewProcFS("/proc")
	return ProcHost{ProcRoot: "/proc", PPIDFunc: p.PPID, ExeFunc: p.Exe}
}

func selfNetNS(t *testing.T) uint32 {
	t.Helper()
	fi, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	return uint32(fi.Sys().(*syscall.Stat_t).Ino)
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).AddrPort().Port()
}

// start runs a proxy in the foreground for the test and returns its pid and executable.
func start(t *testing.T, name string, args ...string) (uint32, string) {
	t.Helper()
	bin, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not installed", name)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root (dev/itest.sh)")
	}
	cmd := exec.Command(bin, args...) // stdout and stderr discarded (Caddy logs every request)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	exe, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	return uint32(cmd.Process.Pid), exe
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	for range 100 {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never listened", addr)
}

func waitFile(t *testing.T, p string) {
	t.Helper()
	for range 100 {
		if _, err := os.Stat(p); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", p)
}

func startCaddy(t *testing.T) (Proxy, uint16) {
	t.Helper()
	adminPort, sitePort := freePort(t), freePort(t)
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	src := "{\n\tadmin 127.0.0.1:" + strconv.Itoa(int(adminPort)) + "\n\tauto_https off\n}\n" +
		"http://live.example:" + strconv.Itoa(int(sitePort)) + " {\n\treverse_proxy 127.0.0.1:9000\n}\n"
	if err := os.WriteFile(cf, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, exe := start(t, "caddy", "run", "--config", cf, "--adapter", "caddyfile")
	waitTCP(t, "127.0.0.1:"+strconv.Itoa(int(adminPort)))
	ns := selfNetNS(t)
	p := Proxy{PIDs: []uint32{pid}, Exe: exe, Root: "/", NetNS: ns, SameNetNS: true,
		Listeners: []model.ListenerKey{model.NewKey(ns, "tcp", netip.MustParseAddr("127.0.0.1"), adminPort)}}
	return p, adminPort
}

func TestLiveCaddyAdmin(t *testing.T) {
	p, port := startCaddy(t)
	ep := Endpoint{Network: "tcp", Addr: "127.0.0.1:" + strconv.Itoa(int(port))}
	ans, err := Read(context.Background(), liveHost(), p, ep, Query{HTTPPath: caddy.ConfigPath})
	if err != nil {
		t.Fatal(Note(err))
	}
	res, err := caddy.Parse(ans.Body, ans.Via, conf.LoadNames(nil))
	if err != nil {
		t.Fatal(err)
	}
	got := conf.Render(res)
	if !strings.Contains(got, "names=live.example") || !strings.Contains(got, "-> 127.0.0.1:9000 127.0.0.1:9000") {
		t.Errorf("routes:\n%s", got)
	}
	// Caddy's origin check also accepts the default endpoint form (localhost:<port>).
	ep.Addr = "localhost:" + strconv.Itoa(int(port))
	if _, err := Read(context.Background(), liveHost(), p, ep, Query{HTTPPath: caddy.ConfigPath}); err != nil {
		t.Errorf("localhost form: %s", Note(err))
	}
}

// An impostor holding a port the proxy is said to hold, or serving a socket the config
// names, is caught by the kernel's account of the other end, and nothing is sent to it.
func TestLiveAdminPeerMismatch(t *testing.T) {
	p, _ := startCaddy(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			n, _ := c.Read(make([]byte, 64))
			got <- n
			c.Close()
		}
	}()
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	p.Listeners = append(p.Listeners, model.NewKey(p.NetNS, "tcp", ap.Addr(), ap.Port()))
	_, err = Read(context.Background(), liveHost(), p, Endpoint{Network: "tcp", Addr: ap.String()}, Query{HTTPPath: caddy.ConfigPath})
	if e, ok := err.(*Error); !ok || !e.Mismatch {
		t.Fatalf("TCP impostor: %v", err)
	}
	if n := <-got; n != 0 {
		t.Errorf("%d bytes were sent to the impostor", n)
	}

	sock := filepath.Join(t.TempDir(), "admin.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, err = Read(context.Background(), liveHost(), p, Endpoint{Network: "unix", Addr: sock}, Query{Command: "show servers state"})
	if e, ok := err.(*Error); !ok || !e.Mismatch || !strings.Contains(e.Reason, "served by pid "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("Unix impostor: %v", err)
	}
}

func TestLiveHAProxyRuntime(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "admin.sock")
	cliPort, fePort := freePort(t), freePort(t)
	cfg := filepath.Join(dir, "haproxy.cfg")
	src := "global\n\tstats socket " + sock + " mode 600 level admin\n\tstats socket ipv4@127.0.0.1:" + strconv.Itoa(int(cliPort)) + " level operator\n" +
		"defaults\n\tmode http\n\ttimeout connect 1s\n\ttimeout client 5s\n\ttimeout server 5s\n" +
		"frontend web\n\tbind 127.0.0.1:" + strconv.Itoa(int(fePort)) + "\n\tdefault_backend app\n" +
		"backend app\n\tserver s1 127.0.0.1:7001\n\tserver s2 127.0.0.1:7002\n"
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, exe := start(t, "haproxy", "-db", "-f", cfg)
	waitFile(t, sock)
	waitTCP(t, "127.0.0.1:"+strconv.Itoa(int(cliPort)))
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("set server app/s2 addr 127.0.0.9 port 7009\n"))
	c.Read(make([]byte, 256))
	c.Close()

	ns := selfNetNS(t)
	p := Proxy{PIDs: []uint32{pid}, Exe: exe, Root: "/", NetNS: ns, SameNetNS: true,
		Listeners: []model.ListenerKey{model.NewKey(ns, "tcp", netip.MustParseAddr("127.0.0.1"), cliPort)}}
	for _, ep := range []Endpoint{{Network: "unix", Addr: sock}, {Network: "tcp", Addr: "127.0.0.1:" + strconv.Itoa(int(cliPort))}} {
		ans, err := Read(context.Background(), liveHost(), p, ep, Query{Command: "show servers state"})
		if err != nil {
			t.Fatalf("%s: %s", ep, Note(err))
		}
		rs, err := haproxy.ParseServersState(ans.Body)
		if err != nil {
			t.Fatalf("%s: %v\n%s", ep, err, ans.Body)
		}
		if len(rs) != 2 || rs[1].Addr != netip.MustParseAddrPort("127.0.0.9:7009") {
			t.Errorf("%s: servers = %+v", ep, rs)
		}
	}
}
