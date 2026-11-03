//go:build linux && integration

package probes

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const helperEnv = "PW_PROXYCONN_HELPER_CGROUP"

// TestProxyConnHelper is the "proxy worker" child of the test below: it moves itself into
// the cgroup named by the environment, then makes the TCP connects its stdin asks for.
func TestProxyConnHelper(t *testing.T) {
	cg := os.Getenv(helperEnv)
	if cg == "" {
		t.Skip("helper process only")
	}
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		fmt.Println("error", err)
		return
	}
	fmt.Println("ready")
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var addr string
		var n int
		if _, err := fmt.Sscan(in.Text(), &addr, &n); err != nil {
			return
		}
		for range n {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			_ = c.Close()
		}
		fmt.Println("ok")
	}
}

type helper struct {
	in  io.WriteCloser
	out *bufio.Scanner
	cmd *exec.Cmd
}

func startHelper(t *testing.T, cgroupDir string) *helper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProxyConnHelper$")
	cmd.Env = append(os.Environ(), helperEnv+"="+cgroupDir)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &helper{in: in, out: bufio.NewScanner(outPipe), cmd: cmd}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Wait()
	})
	h.expect(t, "ready")
	return h
}

func (h *helper) expect(t *testing.T, want string) {
	t.Helper()
	for h.out.Scan() {
		line := h.out.Text()
		if line == want {
			return
		}
		if strings.HasPrefix(line, "error") {
			t.Fatalf("helper: %s", line)
		}
	}
	t.Fatalf("helper ended before %q", want)
}

func (h *helper) connect(t *testing.T, addr net.Addr, n int) {
	t.Helper()
	if _, err := fmt.Fprintf(h.in, "%s %d\n", addr, n); err != nil {
		t.Fatal(err)
	}
	h.expect(t, "ok")
}

func acceptAll(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln
}

func totalRuns(t *testing.T, p *ProxyConns) uint64 {
	t.Helper()
	counts, err := p.RunCounts()
	if err != nil {
		t.Fatal(err)
	}
	return counts["on_connect4"] + counts["on_connect6"]
}

func counted(t *testing.T, p *ProxyConns) map[string]ProxyConn {
	t.Helper()
	conns, err := p.Read()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]ProxyConn)
	for _, c := range conns {
		out[c.Addr.String()] = c
	}
	return out
}

// The connect programs run only for processes in an attached cgroup, count a connect
// only for a tracked tgid or its child, and aggregate per destination.
func TestProxyConnCountsTrackedProxiesOnly(t *testing.T) {
	enableBPFStats(t)
	p, err := StartProxyConns()
	if err != nil {
		t.Fatalf("StartProxyConns: %+v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	cg := fmt.Sprintf("/pw-itest-proxyconn-%d", os.Getpid())
	dir := filepath.Join(CgroupRoot, cg)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The helper has exited by now (its cleanup ran first), so the cgroup is empty.
		for range 50 {
			if err := os.Remove(dir); err == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Errorf("cgroup %s not removed", dir)
	})
	ln4 := acceptAll(t, "tcp4", "127.0.0.1:0")
	ln6 := acceptAll(t, "tcp6", "[::1]:0")
	h := startHelper(t, dir)

	if err := p.SetCgroups([]string{cg}); err != nil {
		t.Fatal(err)
	}
	// The test process is the helper's parent: the helper is its "worker".
	if err := p.SetPIDs([]uint32{uint32(os.Getpid())}); err != nil {
		t.Fatal(err)
	}
	h.connect(t, ln4.Addr(), 3)
	h.connect(t, ln6.Addr(), 2)
	got := counted(t, p)
	c4, c6 := got[ln4.Addr().String()], got[ln6.Addr().String()]
	if c4.Count != 3 || c4.Proxy != uint32(os.Getpid()) || time.Since(c4.Last) > 10*time.Second || c6.Count != 2 || len(got) != 2 {
		t.Fatalf("counted = %+v", got)
	}
	if c6.Addr.Addr() != netip.IPv6Loopback() {
		t.Fatalf("v6 address = %s", c6.Addr)
	}

	// Processes outside the attached cgroup never run the programs.
	before := totalRuns(t, p)
	for range 20 {
		c, err := net.Dial("tcp", ln4.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	if after := totalRuns(t, p); after != before {
		t.Fatalf("connects outside the proxy cgroups ran the programs %d times", after-before)
	}

	// In the cgroup but not tracked: the program runs and counts nothing; untracking
	// drops the old counts.
	if err := p.SetPIDs(nil); err != nil {
		t.Fatal(err)
	}
	if got := counted(t, p); len(got) != 0 {
		t.Fatalf("counts after untracking = %+v", got)
	}
	h.connect(t, ln4.Addr(), 4)
	if got := counted(t, p); len(got) != 0 {
		t.Fatalf("untracked connects counted: %+v", got)
	}
	if after := totalRuns(t, p); after != before+4 {
		t.Fatalf("runs = %d, want %d", after, before+4)
	}

	// Detached: nothing runs.
	if err := p.SetCgroups(nil); err != nil {
		t.Fatal(err)
	}
	h.connect(t, ln4.Addr(), 2)
	if after := totalRuns(t, p); after != before+4 {
		t.Fatalf("runs after detach = %d, want %d", after, before+4)
	}
}
