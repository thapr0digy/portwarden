//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/alerter"
	"github.com/thapr0digy/portwarden/internal/alerter/pgstate"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/backend/testnats"
)

// hookLog records every webhook POST: alert id and listener port.
type hookLog struct {
	mu    sync.Mutex
	posts []hookPost
}

type hookPost struct {
	ID   string
	Port uint32
}

func (h *hookLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var a struct {
		Listener struct {
			Port uint32 `json:"port"`
		} `json:"listener"`
	}
	_ = json.Unmarshal(b, &a)
	h.mu.Lock()
	h.posts = append(h.posts, hookPost{ID: r.Header.Get("X-Portwarden-Alert-Id"), Port: a.Listener.Port})
	h.mu.Unlock()
}

// forPort is how many POSTs (and distinct alert ids) carried port.
func (h *hookLog) forPort(port uint32) (posts, ids int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[string]bool{}
	for _, p := range h.posts {
		if p.Port == port {
			posts++
			seen[p.ID] = true
		}
	}
	return posts, len(seen)
}

func realDSN(t *testing.T) string {
	t.Helper()
	d := os.Getenv("PORTWARDEN_TEST_PG")
	if d == "" {
		t.Fatal("PORTWARDEN_TEST_PG is not set; run the integration tests through dev/itest.sh")
	}
	return d
}

// leaderPID is the backend pid holding the alerter's leader lock (a bigint key shows in
// pg_locks as classid = high 32 bits, objid = low 32 bits, objsubid = 1).
func leaderPID(t *testing.T, ctx context.Context, conn *pgx.Conn) int32 {
	t.Helper()
	var pid int32
	if err := conn.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 1
		AND ((classid::bigint << 32) | objid::bigint) = $1`, int64(pgstate.LeaderLock)).Scan(&pid); err != nil {
		t.Fatalf("leader lock holder: %v", err)
	}
	return pid
}

// TestTwoAlertersHandover is the two-instance test of the design: alerter A (a child
// process) leads and B stands by; A pages port 443; A is killed with SIGKILL and B leads
// within seconds, pages port 8443 and does not page 443 again for a repeat of its event;
// then B's lock session is terminated (a dropped database connection): B stops with
// "lost leadership", a third instance C leads and pages port 9443. Every port is paged
// exactly once, with one alert id.
func TestTwoAlertersHandover(t *testing.T) {
	clearEnv(t)
	dsn := realDSN(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	adm, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close(ctx)
	if s, err := pgstate.Open(ctx, dsn); err != nil { // migrate before the truncate
		t.Fatal(err)
	} else {
		s.Close()
	}
	if _, err := adm.Exec(ctx, "TRUNCATE alerter_pages, alerter_dedupe, alerter_probe, alerter_forgotten, alerter_runs"); err != nil {
		t.Fatal(err)
	}

	ts := testnats.Start(t)
	ts.CreateStream(t)
	hooks := &hookLog{}
	srv := httptest.NewServer(hooks)
	defer srv.Close()
	secret := writeFile(t, "secret", webhookSecret)
	config := func(health string) string {
		cfg := Config{NATS: natsConfig(ts), HealthListen: &health,
			Leader: svc.Leader{Poll: svc.Duration(200 * time.Millisecond), Check: svc.Duration(200 * time.Millisecond)}}
		cfg.Webhook.URL, cfg.Webhook.AllowInsecure, cfg.Webhook.SecretFile = srv.URL, true, secret
		return configFile(t, cfg)
	}
	addrA, addrB, addrC := freeAddr(t), freeAddr(t), freeAddr(t)

	childA := exec.Command(os.Args[0])
	childA.Env = append(os.Environ(), "PW_TEST_HELPER=1", "PW_TEST_REAL_PG=1", "PW_TEST_CONFIG="+config(addrA))
	childA.Stdout, childA.Stderr = io.Discard, io.Discard
	if err := childA.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = childA.Process.Kill(); _ = childA.Wait() }()
	waitUntil(t, "A to lead", func() bool { return healthOf(t, addrA).Role == "leader" })

	ctxB, cancelB := context.WithCancel(ctx)
	defer cancelB()
	doneB := make(chan error, 1)
	go func() { doneB <- run(ctxB, config(addrB), openPG) }()
	waitUntil(t, "B to stand by", func() bool { return healthOf(t, addrB).Role == "standby" })

	publish := func(kind string, data []byte) {
		t.Helper()
		if _, err := ts.HostJS.Publish(ctx, bus.Subject(host, kind), data); err != nil {
			t.Fatal(err)
		}
	}
	open, bound := asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN, asmv1.ExposureLevel_EXPOSURE_BOUND
	pageOnce := func(port uint32) {
		t.Helper()
		publish(bus.KindExposureChanged, marshal(t, exposure(port, open, bound, "")))
		waitUntil(t, "a page for the port", func() bool { n, _ := hooks.forPort(port); return n >= 1 })
	}
	publish(bus.KindHeartbeat, marshal(t, &asmv1.Heartbeat{HostId: host, RunId: "r1"}))
	pageOnce(443)

	killed := time.Now()
	if err := childA.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "B to lead after A's SIGKILL", func() bool { return healthOf(t, addrB).Role == "leader" })
	t.Logf("handover after SIGKILL: %s", time.Since(killed).Round(time.Millisecond))
	pageOnce(8443)
	// The same event again, as a redelivery of a message A had decided: deduped.
	publish(bus.KindExposureChanged, marshal(t, exposure(443, open, bound, "")))

	ctxC, cancelC := context.WithCancel(ctx)
	defer cancelC()
	doneC := make(chan error, 1)
	go func() { doneC <- run(ctxC, config(addrC), openPG) }()
	waitUntil(t, "C to stand by", func() bool { return healthOf(t, addrC).Role == "standby" })
	dropped := time.Now()
	if _, err := adm.Exec(ctx, "SELECT pg_terminate_backend($1)", leaderPID(t, ctx, adm)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-doneB:
		if err == nil || !strings.Contains(err.Error(), "lost leadership") || !errors.Is(err, leader.ErrLost) {
			t.Fatalf("B after its lock session dropped: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("B kept working after its lock session was terminated")
	}
	waitUntil(t, "C to lead after B's lock session dropped", func() bool { return healthOf(t, addrC).Role == "leader" })
	t.Logf("handover after the lock session dropped: %s", time.Since(dropped).Round(time.Millisecond))
	pageOnce(9443)

	time.Sleep(2 * time.Second) // room for a duplicate to show up
	for _, port := range []uint32{443, 8443, 9443} {
		if posts, ids := hooks.forPort(port); posts != 1 || ids != 1 {
			t.Errorf("port %d: %d posts, %d alert ids, want exactly one", port, posts, ids)
		}
	}
	var queued int
	if err := adm.QueryRow(ctx, "SELECT count(*) FROM alerter_pages WHERE payload->>'kind' = $1", alerter.KindNewlyReachable).Scan(&queued); err != nil || queued != 3 {
		t.Errorf("%d listener pages queued (%v), want 3", queued, err)
	}
	cancelC()
	if err := <-doneC; !errors.Is(err, context.Canceled) {
		t.Fatalf("C's stop: %v", err)
	}
}
