package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/backend/testnats"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// request sends method to url with token and returns the status, the role header and
// the body.
func request(t *testing.T, method, url, token string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, resp.Header.Get("X-Portwarden-Role"), string(b)
}

func streamConsumers(t *testing.T, ts *testnats.Server) []string {
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

// A standby inventory serves reads with the token checks and its role, refuses to forget
// (503 after the admin check), and consumes nothing; once it leads it creates its
// consumer and forgets.
func TestRunStandbyServesReadsUntilItLeads(t *testing.T) {
	clearEnv(t)
	ts := testnats.Start(t)
	ts.CreateStream(t)
	addr := freeAddr(t)
	cfg := goodConfig(t, ts, addr)
	cfg.API.AdminTokenFile = writeFile(t, "admin", adminTok)
	store := newFakeStore()
	store.standby = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, configFile(t, cfg), opener(store)) }()
	base := "http://" + addr
	waitFor(t, "the standby's API", func() bool { code, _, _ := request(t, "GET", base+"/healthz", ""); return code == 200 })

	if code, role, body := request(t, "GET", base+"/healthz", ""); code != 200 || role != "standby" || !strings.Contains(body, `"role":"standby"`) {
		t.Fatalf("healthz: %d %q %s", code, role, body)
	}
	if code, role, _ := request(t, "GET", base+"/v1/hosts", readToken); code != 200 || role != "standby" {
		t.Fatalf("read: %d %q", code, role)
	}
	if code, _, _ := request(t, "GET", base+"/v1/hosts", "wrong-token-0123456789"); code != 401 {
		t.Fatalf("read with a wrong token: %d", code)
	}
	if code, _, _ := request(t, "DELETE", base+"/v1/hosts/gone?force=1", ""); code != 401 {
		t.Fatalf("forget without a token: %d", code)
	}
	if code, _, body := request(t, "DELETE", base+"/v1/hosts/gone?force=1", adminTok); code != 503 || !strings.Contains(body, "standby") {
		t.Fatalf("forget on a standby: %d %s", code, body)
	}
	time.Sleep(500 * time.Millisecond)
	if names := streamConsumers(t, ts); len(names) != 0 {
		t.Fatalf("a standby created consumers: %v", names)
	}

	close(store.standby)
	ts.WaitConsumer(t, natsauth.ConsumerInventory)
	waitFor(t, "the leader's role", func() bool { _, role, _ := request(t, "GET", base+"/healthz", ""); return role == "leader" })
	waitFor(t, "a forget on the leader", func() bool {
		code, _, _ := request(t, "DELETE", base+"/v1/hosts/gone?force=1", adminTok)
		return code == 200
	})
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown: %v", err)
	}
	if !store.currentLease().isReleased() {
		t.Fatal("a clean stop did not release the lock")
	}
}

// Losing the lead stops the work and exits 1 (systemd restarts it as a standby).
func TestRunLostLeadershipExits(t *testing.T) {
	clearEnv(t)
	ts := testnats.Start(t)
	ts.CreateStream(t)
	store := newFakeStore()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, configFile(t, goodConfig(t, ts, freeAddr(t))), opener(store)) }()
	ts.WaitConsumer(t, natsauth.ConsumerInventory)
	l := store.currentLease()
	l.lose(leader.ErrFenced)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "lost leadership") || !errors.Is(err, leader.ErrFenced) || exitCode(err) != 1 {
			t.Fatalf("after the loss: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run kept working after losing the lead")
	}
	_, _, _, closed, after := store.snapshot()
	if !closed || after != 0 || !l.isReleased() {
		t.Fatalf("closed %v, %d calls after close, released %v", closed, after, l.isReleased())
	}
}

func TestLoadLeader(t *testing.T) {
	clearEnv(t)
	cfg := goodConfig(t, nil, "127.0.0.1:0")
	cfg.Leader.Poll = 1 // 1ns
	if _, err := load(configFile(t, cfg)); err == nil || !strings.Contains(err.Error(), "leader.poll") {
		t.Fatalf("%v", err)
	}
}
