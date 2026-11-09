package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/backend/testnats"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// TestMain doubles as the verifier binary for the child-process tests: with
// PW_TEST_HELPER set it runs the real main with --config PW_TEST_CONFIG.
func TestMain(m *testing.M) {
	if os.Getenv("PW_TEST_HELPER") == "1" {
		os.Args = []string{os.Args[0], "--config", os.Getenv("PW_TEST_CONFIG")}
		main()
		return
	}
	os.Exit(m.Run())
}

func TestBuildScope(t *testing.T) {
	if _, err := buildScope(Config{}); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	s, err := buildScope(Config{AllowCIDRs: []string{"203.0.113.9/24"}, HostAddresses: map[string][]string{"h": {"::ffff:10.0.0.1"}}})
	if err != nil || s.Allow[0].String() != "203.0.113.0/24" || s.HostAddresses["h"][0].String() != "10.0.0.1" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := buildScope(Config{AllowCIDRs: []string{"nope"}}); err == nil {
		t.Fatal("bad cidr accepted")
	}
	if _, err := buildScope(Config{AllowCIDRs: []string{"10.0.0.0/8"}, HostAddresses: map[string][]string{"h": {"nope"}}}); err == nil || !strings.Contains(err.Error(), "host_addresses[h]") {
		t.Fatalf("bad host address: %v", err)
	}
}

// writeConfig writes cfg as the JSON config file and returns its path.
func writeConfig(t *testing.T, cfg any) string {
	t.Helper()
	var b []byte
	switch c := cfg.(type) {
	case string:
		b = []byte(c)
	default:
		var err error
		if b, err = json.Marshal(c); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(t.TempDir(), "verifier.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadBadConfig(t *testing.T) {
	if _, err := load(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	for name, body := range map[string]string{
		"bad json":         `{"allow_cidrs": [`,
		"unknown key":      `{"allow_cidrs": ["10.0.0.0/8"], "allow_cidr": []}`,
		"negative min_gap": `{"allow_cidrs": ["10.0.0.0/8"], "min_gap": "-1s"}`,
		"numeric timeout":  `{"allow_cidrs": ["10.0.0.0/8"], "timeouts": {"connect": 3}}`,
	} {
		p := writeConfig(t, body)
		if _, err := load(p); err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("%s: %v (want an error naming the file)", name, err)
		}
	}
}

func TestLoadValidation(t *testing.T) {
	for name, body := range map[string]string{
		"no allowlist":   `{}`,
		"empty list":     `{"allow_cidrs": []}`,
		"bad cidr":       `{"allow_cidrs": ["10.0.0.0/33"]}`,
		"bad host addrs": `{"allow_cidrs": ["10.0.0.0/8"], "host_addresses": {"h": ["10.0.0.300"]}}`,
	} {
		if _, err := load(writeConfig(t, body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLoadDefaultsAndSettings(t *testing.T) {
	st, err := load(writeConfig(t, `{"allow_cidrs": ["10.0.0.0/8"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(st.cfg.Checker, "portwarden-verifier@") || st.prober.Timeout != 3*time.Second || st.prober.BannerWait != 2*time.Second || len(st.prober.HTTPPorts) != 0 {
		t.Fatalf("defaults: checker %q timeout %v banner %v http %v", st.cfg.Checker, st.prober.Timeout, st.prober.BannerWait, st.prober.HTTPPorts)
	}
	st, err = load(writeConfig(t, `{"allow_cidrs": ["10.0.0.0/8"], "checker": "pv@probe-1", "user_agent": "ua/1",
		"timeouts": {"connect": "1s", "banner": "500ms"}, "http_ports": [8080, 80]}`))
	if err != nil {
		t.Fatal(err)
	}
	if st.cfg.Checker != "pv@probe-1" || st.prober.UserAgent != "ua/1" || st.prober.Timeout != time.Second ||
		st.prober.BannerWait != 500*time.Millisecond || !st.prober.HTTPPorts[8080] || !st.prober.HTTPPorts[80] {
		t.Fatalf("settings: %+v %+v", st.cfg, st.prober)
	}
}

func TestExitCode(t *testing.T) {
	if exitCode(nil) != 0 || exitCode(context.Canceled) != 0 || exitCode(errors.Join(errors.New("x"), context.Canceled)) != 0 {
		t.Fatal("a clean stop must exit 0")
	}
	if exitCode(errors.New("allow_cidrs is empty")) != 1 {
		t.Fatal("an error must exit 1")
	}
}

// natsConfig is the config's nats block for the verifier user of ts.
func natsConfig(ts *testnats.Server) svc.NATS {
	return svc.NATS{URL: ts.URL, NkeyFile: ts.Seeds[natsauth.RoleVerifier]}
}

func TestRunMissingCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	missing := filepath.Join(t.TempDir(), "verifier.nk")
	for name, nc := range map[string]svc.NATS{
		"missing seed":      {URL: "nats://127.0.0.1:1", NkeyFile: missing},
		"missing creds":     {URL: "nats://127.0.0.1:1", CredsFile: missing},
		"creds and nkey":    {URL: "nats://127.0.0.1:1", CredsFile: missing, NkeyFile: missing},
		"cert without key":  {URL: "nats://127.0.0.1:1", CertFile: missing},
		"unreadable seed":   {URL: "nats://127.0.0.1:1", NkeyFile: writeConfig(t, "not a seed")},
		"malformed address": {URL: "nats://[::1"},
	} {
		p := writeConfig(t, Config{NATS: nc, AllowCIDRs: []string{"10.0.0.0/8"}})
		if err := run(ctx, p); err == nil || errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The verifier connects with its own seed, waits for the stream, creates its durable
// consumer, probes a requested listener inside its allowlist and publishes the result;
// on cancel it returns context.Canceled (exit 0).
func TestRunWiringAndShutdown(t *testing.T) {
	ts := testnats.Start(t)
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
			c.Close()
		}
	}()
	port := uint32(ln.Addr().(*net.TCPAddr).Port)
	p := writeConfig(t, Config{NATS: natsConfig(ts), Checker: "pv@test", AllowCIDRs: []string{"127.0.0.0/8"},
		HostAddresses: map[string][]string{testnats.Host: {"127.0.0.1"}}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, p) }()
	// Started before the stream exists: it waits for it.
	time.Sleep(100 * time.Millisecond)
	stream := ts.CreateStream(t)
	ts.WaitConsumer(t, natsauth.ConsumerVerifier)

	req := &asmv1.ProbeRequest{EventId: "e1", HostId: testnats.Host, Level: asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN,
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: port, Key: "1/tcp/0.0.0.0:1"}}
	b, _ := proto.Marshal(req)
	// A forged request (body names another host) is dropped; the real one is probed.
	forged, _ := proto.Marshal(&asmv1.ProbeRequest{HostId: "other", Listener: req.Listener, Level: req.Level})
	for _, data := range [][]byte{forged, []byte("\xff not proto"), b} {
		if _, err := ts.AdminJS.Publish(ctx, bus.ProbeSubject(testnats.Host), data); err != nil {
			t.Fatal(err)
		}
	}
	var got asmv1.ExposureConfirmation
	deadline := time.Now().Add(10 * time.Second)
	for {
		m, err := stream.GetLastMsgForSubject(ctx, bus.VerifierSubject(testnats.Host))
		if err == nil {
			if err := proto.Unmarshal(m.Data, &got); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no verifier result published")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got.GetResult() != "confirmed" || got.GetChecker() != "pv@test" || got.GetHostId() != testnats.Host {
		t.Fatalf("result %+v", &got)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || exitCode(err) != 0 {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

// Cancelled while waiting for the stream: a clean stop too.
func TestRunShutdownWhileWaitingForStream(t *testing.T) {
	ts := testnats.Start(t)
	p := writeConfig(t, Config{NATS: natsConfig(ts), AllowCIDRs: []string{"127.0.0.0/8"}})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := run(ctx, p); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

// startChild runs the test binary as the verifier and waits for want on its stderr.
func startChild(t *testing.T, config, want string) (*exec.Cmd, chan struct{}) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "PW_TEST_HELPER=1", "PW_TEST_CONFIG="+config)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		once := false
		for sc.Scan() {
			if !once && strings.Contains(sc.Text(), want) {
				once = true
				close(seen)
			}
		}
		if !once {
			close(seen)
		}
	}()
	return cmd, seen
}

func waitExit(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatal(err)
		}
		return cmd.ProcessState.ExitCode()
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit")
	}
	return -1
}

// A real SIGTERM or SIGINT stops the verifier cleanly with exit status 0; a bad config
// exits 1.
func TestMainSignals(t *testing.T) {
	ts := testnats.Start(t)
	ts.CreateStream(t)
	p := writeConfig(t, Config{NATS: natsConfig(ts), AllowCIDRs: []string{"127.0.0.0/8"}})
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		cmd, seen := startChild(t, p, "verifier running")
		select {
		case <-seen:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatal("verifier never ran")
		}
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
		if code := waitExit(t, cmd); code != 0 {
			t.Fatalf("%v: exit %d, want 0", sig, code)
		}
	}
	cmd, _ := startChild(t, writeConfig(t, `{}`), "allow_cidrs")
	if code := waitExit(t, cmd); code != 1 {
		t.Fatalf("bad config: exit %d, want 1", code)
	}
}
