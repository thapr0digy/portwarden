package alerter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/alerter"
	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/backend/testnats"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

type pingFunc func(context.Context) error

func (f pingFunc) Ping(ctx context.Context) error { return f(ctx) }

func getHealth(t *testing.T, h http.Handler) (int, healthBody, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var b healthBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return rec.Code, b, rec.Header().Get("X-Portwarden-Role")
}

// The health endpoint shows the role and epoch, and 503 when the database is down.
func TestHealthEndpoint(t *testing.T) {
	var role leader.State
	var down atomic.Bool
	h := healthHandler(pingFunc(func(context.Context) error {
		if down.Load() {
			return errors.New("dial tcp: connection refused")
		}
		return nil
	}), &role)
	if code, b, hdr := getHealth(t, h); code != 200 || !b.OK || b.Role != "standby" || b.Epoch != 0 || hdr != "standby" {
		t.Fatalf("standby: %d %+v %q", code, b, hdr)
	}
	role.Set(leader.Leader, 4)
	if code, b, hdr := getHealth(t, h); code != 200 || b.Role != "leader" || b.Epoch != 4 || hdr != "leader" {
		t.Fatalf("leader: %d %+v %q", code, b, hdr)
	}
	down.Store(true)
	if code, b, _ := getHealth(t, h); code != 503 || b.OK || b.Error != "database unreachable" || b.Role != "leader" {
		t.Fatalf("db down: %d %+v", code, b)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func healthOf(t *testing.T, addr string) healthBody {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		return healthBody{}
	}
	defer resp.Body.Close()
	var b healthBody
	_ = json.NewDecoder(resp.Body).Decode(&b)
	return b
}

func waitUntil(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A standby serves its health endpoint and touches neither NATS nor the outbox; once it
// leads it creates its consumers and says "leader".
func TestRunStandbyDoesNoWorkUntilItLeads(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	ts := testnats.Start(t)
	ts.CreateStream(t)
	addr := freeAddr(t)
	cfg := Config{NATS: natsConfig(ts), HealthListen: &addr}
	store := newFakeStore()
	store.standby = make(chan struct{})
	queued(store, "queued-before", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, configFile(t, cfg), opener(store), os.Stdout) }()
	waitUntil(t, "the standby's health endpoint", func() bool { return healthOf(t, addr).Role == "standby" })
	time.Sleep(1500 * time.Millisecond) // a working instance would have delivered and consumed by now
	if store.pages()[0].delivered {
		t.Fatal("a standby delivered a page")
	}
	if names := consumerNames(t, ts); len(names) != 0 {
		t.Fatalf("a standby created consumers: %v", names)
	}
	close(store.standby)
	ts.WaitConsumer(t, natsauth.ConsumerAlerter)
	ts.WaitConsumer(t, natsauth.ConsumerAlerterHB)
	waitUntil(t, "the leader's health", func() bool { b := healthOf(t, addr); return b.Role == "leader" && b.Epoch == 1 })
	waitUntil(t, "the queued page delivered by the new leader", func() bool { return store.pages()[0].delivered })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || exitCode(err) != 0 {
		t.Fatalf("shutdown: %v", err)
	}
	if !store.lease.isReleased() {
		t.Fatal("a clean stop did not release the lock")
	}
}

// Losing the lead (a failed lock check, a fence) stops the work and exits 1, so systemd
// restarts the process as a standby; no page is sent after the loss.
func TestRunLostLeadershipExits(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	ts := testnats.Start(t)
	ts.CreateStream(t)
	store := newFakeStore()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, configFile(t, Config{NATS: natsConfig(ts)}), opener(store), os.Stdout) }()
	ts.WaitConsumer(t, natsauth.ConsumerAlerterHB)
	store.mu.Lock()
	l := store.lease
	store.mu.Unlock()
	l.lose(leader.ErrLost)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "lost leadership") || !errors.Is(err, leader.ErrLost) || exitCode(err) != 1 {
			t.Fatalf("after the loss: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run kept working after losing the lead")
	}
	if !store.closed || store.afterClose != 0 || !l.isReleased() {
		t.Fatalf("closed %v, %d calls after close, released %v", store.closed, store.afterClose, l.isReleased())
	}
}

// deliver sends nothing once the lead is lost: the new leader delivers what is due.
func TestDeliverStopsWhenLost(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { posts.Add(1) }))
	defer srv.Close()
	store := newFakeStore()
	queued(store, "p1", 0)
	a := newApp(t, store, alerter.NewWebhook(srv.URL, []byte(webhookSecret), time.Second, 1))
	lost := make(chan struct{})
	close(lost)
	a.lost = lost
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	a.deliver(ctx)
	if time.Since(start) > 3*time.Second || posts.Load() != 0 || store.pages()[0].delivered {
		t.Fatalf("after %s: %d posts, delivered %v", time.Since(start), posts.Load(), store.pages()[0].delivered)
	}
}

// A busy health address is an error at start, not a silent instance without health.
func TestRunHealthAddressBusy(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	store := newFakeStore()
	err = run(context.Background(), configFile(t, Config{HealthListen: &addr}), opener(store), os.Stdout)
	if err == nil || !strings.Contains(err.Error(), "health_listen") || !store.closed {
		t.Fatalf("%v (closed %v)", err, store.closed)
	}
}

func consumerNames(t *testing.T, ts *testnats.Server) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := ts.AdminJS.Stream(ctx, natsauth.StreamName)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	l := s.ConsumerNames(ctx)
	for n := range l.Name() {
		names = append(names, n)
	}
	return names
}

// The leader block and health_listen are checked at load: an out-of-range interval or a
// malformed address is refused; health_listen unset is the default, "" turns it off.
func TestLoadLeaderAndHealth(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	for name, c := range map[string]struct{ cfg, want string }{
		"poll too short": {`{"leader": {"poll": "10ms"}}`, "leader.poll"},
		"check too long": {`{"leader": {"check": "5m"}}`, "leader.check"},
		"bad address":    {`{"health_listen": "8741"}`, "health_listen"},
	} {
		if _, err := load(configFile(t, c.cfg)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	st, err := load(configFile(t, `{}`))
	if err != nil || st.health != defaultHealthListen {
		t.Fatalf("default: %q %v", st.health, err)
	}
	st, err = load(configFile(t, `{"health_listen": "", "leader": {"poll": "500ms", "check": "2s"}}`))
	if err != nil || st.health != "" {
		t.Fatalf("off: %q %v", st.health, err)
	}
}
