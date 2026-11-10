package inventory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/backend/testnats"
	"github.com/thapr0digy/portwarden/internal/cmd/cli"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// TestMain doubles as the inventory binary for the child-process tests: with
// PW_TEST_HELPER set it runs the real Run (with an in-memory store, or PostgreSQL with
// PW_TEST_REAL_PG) on the arguments in
// PW_TEST_ARGS (separated by newlines).
func TestMain(m *testing.M) {
	if os.Getenv("PW_TEST_HELPER") == "1" {
		openStore = opener(newFakeStore())
		if os.Getenv("PW_TEST_REAL_PG") == "1" {
			openStore = openPG // the two-instance tests (handover_integration_test.go)
		}
		os.Exit(cli.Code(Run(context.Background(), strings.Split(os.Getenv("PW_TEST_ARGS"), "\n"), os.Stdout, os.Stderr)))
	}
	os.Exit(m.Run())
}

const (
	readToken  = "read-token-0123456789"
	adminTok   = "admin-token-0123456789"
	fakeDSNEnv = "postgres://inventory@127.0.0.1/pw_test"
)

// clearEnv keeps the developer's own PORTWARDEN_* settings out of the tests.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PORTWARDEN_INVENTORY_DSN", "PORTWARDEN_INVENTORY_TOKEN", adminTokenEnv,
		"GOOGLE_APPLICATION_CREDENTIALS", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_TENANT_ID", "AZURE_CLIENT_ID"} {
		t.Setenv(k, "")
	}
}

func configFile(t *testing.T, cfg any) string {
	t.Helper()
	if s, ok := cfg.(string); ok {
		return writeFile(t, "inventory.json", s)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "inventory.json", string(b))
}

// freeAddr is a loopback address nothing listens on (it was free a moment ago).
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// goodConfig is a config that starts, for the inventory user of ts.
func goodConfig(t *testing.T, ts *testnats.Server, listen string) Config {
	t.Helper()
	cfg := Config{NATS: svc.NATS{URL: "nats://127.0.0.1:1"}, Listen: listen, PostgresDSNFile: writeFile(t, "dsn", fakeDSNEnv+"\n"),
		TokenFile: writeFile(t, "token", readToken+"\n")}
	if ts != nil {
		cfg.NATS = svc.NATS{URL: ts.URL, NkeyFile: ts.Seeds[natsauth.RoleInventory]}
	}
	return cfg
}

func TestLoadBadConfig(t *testing.T) {
	clearEnv(t)
	if _, err := load(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	for name, body := range map[string]string{
		"bad json":          `{"listen": `,
		"unknown key":       `{"listen_addr": "127.0.0.1:1"}`,
		"negative duration": `{"silent_after": "-5s"}`,
		"wrong type":        `{"retention": {"batch": "many"}}`,
	} {
		p := configFile(t, body)
		if _, err := load(p); err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("%s: %v (want an error naming the file)", name, err)
		}
	}
}

func TestLoadValidation(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_INVENTORY_DSN", fakeDSNEnv)
	t.Setenv("PORTWARDEN_INVENTORY_TOKEN", readToken)
	for name, c := range map[string]struct{ body, want string }{
		"short interval":  {`{"retention": {"interval": "30s"}}`, "retention.interval"},
		"batch too large": {`{"retention": {"batch": 10001}}`, "retention.batch"},
		"negative batch":  {`{"retention": {"batch": -1}}`, "retention.batch"},
		"bad vpn range":   {`{"cloud": {"vpn_cidrs": ["10.0.0.0/40"]}}`, "cloud.vpn_cidrs"},
		"open listen":     {`{"listen": "0.0.0.0:8740"}`, "not loopback"},
		"malformed":       {`{"listen": "nope"}`, "listen:"},
	} {
		if _, err := load(configFile(t, c.body)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
	st, err := load(configFile(t, `{"listen": "0.0.0.0:8740", "allow_insecure_listen": true}`))
	if err != nil || st.cfg.Listen != "0.0.0.0:8740" {
		t.Fatalf("allowed insecure listen: %+v %v", st.cfg, err)
	}
	st, err = load(configFile(t, `{}`))
	if err != nil || st.cfg.Listen != defaultListen || st.dsn != fakeDSNEnv || st.token != readToken {
		t.Fatalf("defaults: %+v %v", st, err)
	}
}

func TestLoadMissingCredentials(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	empty := writeFile(t, "empty", "  \n")
	for name, c := range map[string]struct {
		cfg  Config
		want string
	}{
		"no dsn":         {Config{TokenFile: writeFile(t, "t", readToken)}, "postgres dsn: set PORTWARDEN_INVENTORY_DSN"},
		"empty dsn file": {Config{PostgresDSNFile: empty}, "postgres dsn: " + empty + " is empty"},
		"dsn file gone":  {Config{PostgresDSNFile: filepath.Join(dir, "nope")}, "postgres dsn: "},
		"no token":       {Config{PostgresDSNFile: writeFile(t, "d", fakeDSNEnv)}, "api token: set PORTWARDEN_INVENTORY_TOKEN"},
		"empty token":    {Config{PostgresDSNFile: writeFile(t, "d", fakeDSNEnv), TokenFile: empty}, "api token: "},
	} {
		if _, err := load(configFile(t, c.cfg)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
	// The environment wins over the files.
	t.Setenv("PORTWARDEN_INVENTORY_DSN", " "+fakeDSNEnv+" ")
	st, err := load(configFile(t, Config{PostgresDSNFile: empty, TokenFile: writeFile(t, "t", readToken)}))
	if err != nil || st.dsn != fakeDSNEnv {
		t.Fatalf("env dsn: %+v %v", st, err)
	}
}

// The production opener reports a bad DSN without connecting anywhere.
func TestOpenPGBadDSN(t *testing.T) {
	if s, err := openPG(context.Background(), "postgres://%zz"); err == nil || s != nil || !strings.Contains(err.Error(), "pg: dsn") {
		t.Fatalf("%v %v", s, err)
	}
}

func TestExitCode(t *testing.T) {
	if exitCode(nil) != 0 || exitCode(context.Canceled) != 0 || exitCode(fmt.Errorf("consume: %w", context.Canceled)) != 0 {
		t.Fatal("a clean stop must exit 0")
	}
	if exitCode(errors.New("postgres dsn: set PORTWARDEN_INVENTORY_DSN")) != 1 {
		t.Fatal("an error must exit 1")
	}
}

// Failures after the config is read: each is returned (exit 1), and nothing is left
// listening.
func TestRunStartFailures(t *testing.T) {
	clearEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ts := testnats.Start(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	missingSeed := filepath.Join(t.TempDir(), "inventory.nk")

	cases := map[string]struct {
		edit func(*Config)
		open openStoreFunc
		want string
	}{
		"store down":          {nil, failingOpener, "connection refused"},
		"missing seed":        {func(c *Config) { c.NATS.NkeyFile = missingSeed }, nil, "bus: "},
		"creds and nkey":      {func(c *Config) { c.NATS.CredsFile = missingSeed }, nil, "exclusive"},
		"admin file gone":     {func(c *Config) { c.API.AdminTokenFile = missingSeed }, nil, "api admin token: "},
		"admin is read token": {func(c *Config) { c.API.AdminTokenFile = writeFile(t, "a", readToken) }, nil, "must differ"},
		"listen in use":       {func(c *Config) { c.Listen = busy.Addr().String() }, nil, "address already in use"},
		"gcp without project": {func(c *Config) { c.Cloud.GCP.Enabled = true }, nil, "cloud.gcp: projects is required"},
	}
	for name, c := range cases {
		cfg := goodConfig(t, ts, freeAddr(t))
		if c.edit != nil {
			c.edit(&cfg)
		}
		open := c.open
		store := newFakeStore()
		if open == nil {
			open = opener(store)
		}
		if name == "gcp without project" {
			ts.CreateStream(t)
		}
		err := run(ctx, configFile(t, cfg), open)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
		if exitCode(err) != 1 {
			t.Errorf("%s: exit %d", name, exitCode(err))
		}
		if _, _, _, closed, _ := store.snapshot(); c.open == nil && !closed {
			t.Errorf("%s: store left open", name)
		}
		if name != "listen in use" {
			if conn, err := net.DialTimeout("tcp", cfg.Listen, 200*time.Millisecond); err == nil {
				conn.Close()
				t.Errorf("%s: API still listening on %s", name, cfg.Listen)
			}
		}
	}
}

func get(t *testing.T, url, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The inventory serves its API before the stream exists, connects with its own seed,
// creates its durable consumer, stores a host's heartbeat, quarantines an undecodable
// message, forgets a host through the admin API (announcing it on the bus), runs the
// cloud look-up when a provider is on, and on cancel stops its workers before closing the
// store and returns context.Canceled (exit 0).
func TestRunWiringAndShutdown(t *testing.T) {
	clearEnv(t)
	ts := testnats.Start(t)
	addr := freeAddr(t)
	cfg := goodConfig(t, ts, addr)
	cfg.PostgresDSNFile = ""
	t.Setenv("PORTWARDEN_INVENTORY_DSN", fakeDSNEnv)
	cfg.API.AdminTokenFile = writeFile(t, "admin", adminTok)
	cfg.Cloud.GCP = GCPConfig{Enabled: true, Projects: []string{"acme-prod"}}
	store := newFakeStore()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, configFile(t, cfg), opener(store)) }()

	base := "http://" + addr
	waitFor(t, "the API", func() bool {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	if dsn := store.openedWith(); dsn != fakeDSNEnv {
		t.Fatalf("store opened with %q", dsn)
	}
	// The constant-time token check, through the real wiring.
	for token, want := range map[string]int{"": 401, "wrong-token-0123456789": 401, adminTok: 401, readToken: 200} {
		if got := get(t, base+"/v1/hosts", token); got != want {
			t.Errorf("token %q: %d, want %d", token, got, want)
		}
	}

	stream := ts.CreateStream(t)
	ts.WaitConsumer(t, natsauth.ConsumerInventory)
	hb, _ := proto.Marshal(&asmv1.Heartbeat{EventId: "hb1", HostId: testnats.Host, RunId: "run-1", Seq: 1, At: timestamppb.Now()})
	for _, data := range [][]byte{hb, []byte("\xff not proto")} {
		if _, err := ts.HostJS.Publish(ctx, bus.Subject(testnats.Host, bus.KindHeartbeat), data); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the heartbeat stored and the bad message quarantined", func() bool {
		a, q, _, _, _ := store.snapshot()
		return a > 0 && q > 0
	})

	req, _ := http.NewRequest(http.MethodDelete, base+"/v1/hosts/"+testnats.Host+"?force=true", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forget: %d", resp.StatusCode)
	}
	if _, err := stream.GetLastMsgForSubject(ctx, bus.ForgottenSubject(testnats.Host)); err != nil {
		t.Fatalf("no forgotten announcement: %v", err)
	}
	waitFor(t, "the host forgotten in the store", func() bool { _, _, f, _, _ := store.snapshot(); return f > 0 })

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || exitCode(err) != 0 {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	if _, _, _, closed, after := store.snapshot(); !closed || after != 0 {
		t.Fatalf("store closed %v, %d calls after close", closed, after)
	}
	if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("API still listening after shutdown")
	}
}

// Cancelled while waiting for the stream (the API is up meanwhile): a clean stop.
func TestRunShutdownWhileWaitingForStream(t *testing.T) {
	clearEnv(t)
	ts := testnats.Start(t)
	store := newFakeStore()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := run(ctx, configFile(t, goodConfig(t, ts, freeAddr(t))), opener(store)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if _, _, _, closed, _ := store.snapshot(); !closed {
		t.Fatal("store left open")
	}
}

func startChild(t *testing.T, want string, args ...string) (*exec.Cmd, chan struct{}) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "PW_TEST_HELPER=1", "PW_TEST_ARGS="+strings.Join(args, "\n"))
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

// A real SIGTERM stops the inventory cleanly with exit status 0; a bad config and a bad
// forget-host call exit 1.
func TestMainSignals(t *testing.T) {
	clearEnv(t)
	ts := testnats.Start(t)
	ts.CreateStream(t)
	p := configFile(t, goodConfig(t, ts, freeAddr(t)))
	cmd, seen := startChild(t, `"consuming"`, "--config", p)
	select {
	case <-seen:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("inventory never ran")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, cmd); code != 0 {
		t.Fatalf("SIGTERM: exit %d, want 0", code)
	}
	cmd, _ = startChild(t, "", "--config", configFile(t, `{"listen": "0.0.0.0:1"}`))
	if code := waitExit(t, cmd); code != 1 {
		t.Fatalf("bad config: exit %d, want 1", code)
	}
	cmd, _ = startChild(t, "", "forget-host")
	if code := waitExit(t, cmd); code != 1 {
		t.Fatalf("forget-host without a host: exit %d, want 1", code)
	}
}
