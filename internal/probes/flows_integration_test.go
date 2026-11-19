//go:build linux && integration

package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/flows"
	"github.com/thapr0digy/portwarden/internal/procinfo"
)

// collectFlows reads f's events until want reports it has what it needs, or fails after 5 s.
func collectFlows(t *testing.T, f *Flows, want func([]flows.Event) bool) []flows.Event {
	t.Helper()
	var got []flows.Event
	deadline := time.After(5 * time.Second)
	for !want(got) {
		select {
		case e, ok := <-f.Events():
			if !ok {
				t.Fatalf("events closed: %v", f.Err())
			}
			got = append(got, e)
		case <-deadline:
			t.Fatalf("timed out; got %+v", got)
		}
	}
	return got
}

func startFlows(t *testing.T) *Flows {
	t.Helper()
	f, err := StartFlows()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

// The programs load and attach on this kernel, and a TLS connection this process makes is
// reported once each way: made (with the server name its ClientHello carried, joined by
// cookie) and accepted, both attributed to this process.
func TestFlowsTLSConnection(t *testing.T) {
	f := startFlows(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)

	// The test certificate does not name ledger.internal.example, so the handshake fails
	// after the ClientHello; only the ClientHello matters here.
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	if c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "ledger.internal.example", RootCAs: roots}); err == nil {
		_ = c.Close()
	}

	var out, in *flows.Event
	got := collectFlows(t, f, func(es []flows.Event) bool {
		for i := range es {
			e := &es[i]
			switch {
			case e.Kind == flows.KindOut && e.Remote.Port() == port && e.TGID == uint32(os.Getpid()):
				out = e
			case e.Kind == flows.KindIn && e.LocalPort == port && e.TGID == uint32(os.Getpid()):
				in = e
			}
		}
		if out == nil || in == nil {
			return false
		}
		for _, e := range es {
			if e.Kind == flows.KindHead && e.Cookie == out.Cookie {
				return true
			}
		}
		return false
	})
	if out.Cookie == 0 || !out.Remote.Addr().IsLoopback() || out.Comm == "" {
		t.Errorf("made = %+v", *out)
	}
	if in.Remote.Port() == 0 || !in.Remote.Addr().IsLoopback() {
		t.Errorf("accepted = %+v", *in)
	}
	for _, e := range got {
		if e.Kind == flows.KindHead && e.Cookie == out.Cookie && (e.App != flows.AppTLS || e.Service != "ledger.internal.example") {
			t.Errorf("first bytes named %q %q", e.App, e.Service)
		}
	}
}

// A plaintext HTTP request is named by its Host; a client that sends nothing (a
// server-first protocol) is reported made, with no first bytes.
func TestFlowsHTTPAndSilentClient(t *testing.T) {
	f := startFlows(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/secret/path?token=x", nil)
	req.Host = "billing.internal.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	silent, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	var made []flows.Event
	var named *flows.Event
	collectFlows(t, f, func(es []flows.Event) bool {
		made = made[:0]
		for i := range es {
			if es[i].Kind == flows.KindOut && es[i].Remote.Port() == port {
				made = append(made, es[i])
			}
		}
		for i := range es {
			for _, m := range made {
				if es[i].Kind == flows.KindHead && es[i].Cookie == m.Cookie {
					named = &es[i]
				}
			}
		}
		return len(made) == 2 && named != nil
	})
	if named.App != flows.AppHTTP || named.Service != "billing.internal.example" {
		t.Errorf("first bytes named %q %q", named.App, named.Service)
	}
}

const loadEnv = "PW_FLOWS_LOAD_CONNECTIONS"

// TestFlowsLoadHelper is the busy host of the test below, in a child process so its CPU is
// not the agent's: it serves on loopback and makes the connections its environment asks
// for, each sending an HTTP request line and Host, and prints its server's port.
func TestFlowsLoadHelper(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv(loadEnv))
	if err != nil {
		t.Skip("helper process only")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	req := []byte("GET /load HTTP/1.1\r\nHost: load.internal.example\r\n\r\n")
	for range n {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(req)
		_ = c.Close()
	}
}

// runLoad runs the helper for n connections and returns its server's port and wall time.
func runLoad(t *testing.T, n int) (uint16, time.Duration) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFlowsLoadHelper$")
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d", loadEnv, n))
	start := time.Now()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("load helper: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscan(string(out), &port); err != nil {
		t.Fatalf("load helper printed %q", out)
	}
	return port, time.Since(start)
}

type countingSink struct {
	mu      sync.Mutex
	windows []*eventsv1.HostFlows
}

func (s *countingSink) HostFlows(f *eventsv1.HostFlows) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.windows = append(s.windows, f)
}

func cpuTime(t *testing.T) time.Duration {
	t.Helper()
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// The cost on a busy host (README "Connection flows", "Cost"): 20,000 loopback connections,
// each sending an HTTP request, as fast as one client makes them. Measured and logged: the
// client's slowdown with the probes attached, the agent's own CPU per 1,000 connections, its
// heap, and each program's average run time (kernel.bpf_stats_enabled). Every connection is
// counted, in a row or as dropped, and the agent's memory stays bounded.
func TestFlowsOverheadOnABusyHost(t *testing.T) {
	const n = 20000
	_, base := runLoad(t, n)

	if old, err := os.ReadFile("/proc/sys/kernel/bpf_stats_enabled"); err == nil {
		_ = os.WriteFile("/proc/sys/kernel/bpf_stats_enabled", []byte("1"), 0o644)
		defer os.WriteFile("/proc/sys/kernel/bpf_stats_enabled", old, 0o644) //nolint:errcheck // best effort
	}
	f := startFlows(t)
	sink := &countingSink{}
	resolver := procinfo.NewResolver("/proc", "/sys/fs/cgroup", 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		flows.Run(ctx, flows.Config{Drops: f.Drops, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Identify: func(tgid uint32, cg uint64) flows.Process {
				exe, unit := resolver.Identity(tgid, cg)
				return flows.Process{Exe: exe, Unit: unit}
			}}, f.Events(), sink)
		close(done)
	}()
	cpu0 := cpuTime(t)
	port, loaded := runLoad(t, n)
	time.Sleep(time.Second) // the reader drains the ring
	cpu := cpuTime(t) - cpu0
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	counts, _ := f.RunCounts()
	stats := map[string]string{}
	for _, prog := range f.programs() {
		if st, err := prog.prog.Stats(); err == nil && st.RunCount > 0 {
			stats[prog.name] = fmt.Sprintf("%d runs, %d ns avg", st.RunCount, st.Runtime.Nanoseconds()/int64(st.RunCount))
		}
	}
	cancel()
	<-done

	var out, in, named, dropped uint64
	for _, w := range sink.windows {
		dropped += w.GetDropped()
		for _, r := range w.GetFlows() {
			switch {
			case r.GetDirection() == flows.Out && r.GetRemotePort() == uint32(port):
				out += r.GetCount()
				if r.GetServiceName() == "load.internal.example" {
					named += r.GetCount()
				}
			case r.GetDirection() == flows.In && r.GetLocalPort() == uint32(port):
				in += r.GetCount()
			}
		}
	}
	t.Logf("%d connections: client %v without probes, %v with (%+.1f%%); agent CPU %v (%v per 1,000 connections, %.1f%% of one core over the run); heap in use %d KiB; drops %d; programs %v (counts %v)",
		n, base.Round(time.Millisecond), loaded.Round(time.Millisecond), 100*(float64(loaded)/float64(base)-1),
		cpu.Round(time.Millisecond), (cpu / (n / 1000)).Round(time.Microsecond), 100*float64(cpu)/float64(loaded),
		ms.HeapInuse>>10, dropped, stats, counts)
	t.Logf("out %d (named %d), in %d", out, named, in)
	if out+dropped < n || out > n || in > n {
		t.Errorf("out %d + dropped %d, in %d: want every one of %d connections counted once", out, dropped, in, n)
	}
	if ms.HeapInuse > 64<<20 {
		t.Errorf("heap in use %d MiB", ms.HeapInuse>>20)
	}
}
