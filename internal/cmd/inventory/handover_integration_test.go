//go:build integration

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/leader"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/backend/testnats"
	"github.com/thapr0digy/portwarden/internal/inventory"
	"github.com/thapr0digy/portwarden/internal/inventory/pg"
)

func roleOf(t *testing.T, addr string) string {
	t.Helper()
	_, role, _ := request(t, "GET", "http://"+addr+"/healthz", "")
	return role
}

// lastHeartbeat is the host's last heartbeat as instance addr serves it (zero if none).
func lastHeartbeat(t *testing.T, addr string) time.Time {
	t.Helper()
	code, _, body := request(t, "GET", "http://"+addr+"/v1/hosts/"+testnats.Host, readToken)
	if code != 200 {
		return time.Time{}
	}
	var h inventory.HostView
	if err := json.Unmarshal([]byte(body), &h); err != nil || h.LastHeartbeat == nil {
		return time.Time{}
	}
	return *h.LastHeartbeat
}

// TestTwoInventoriesHandover is the two-instance test of the design: inventory A (a child
// process) leads and B stands by, serving A's data with the read token; A is killed with
// SIGKILL and B leads within seconds, stores the next heartbeat and forgets a host, which
// a standby C refuses; then B's lock session is terminated (a dropped database
// connection): B stops with "lost leadership" and C leads and stores heartbeats.
func TestTwoInventoriesHandover(t *testing.T) {
	clearEnv(t)
	dsn := os.Getenv("PORTWARDEN_TEST_PG")
	if dsn == "" {
		t.Fatal("PORTWARDEN_TEST_PG is not set; run the integration tests through dev/itest.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if s, err := pg.Open(ctx, dsn); err != nil { // migrate before the truncate
		t.Fatal(err)
	} else {
		s.Close()
	}
	adm, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close(ctx)
	if _, err := adm.Exec(ctx, "TRUNCATE hosts, listeners, exposure_history, proxies, quarantine, forgotten_hosts"); err != nil {
		t.Fatal(err)
	}

	ts := testnats.Start(t)
	ts.CreateStream(t)
	dsnFile, adminFile := writeFile(t, "dsn", dsn+"\n"), writeFile(t, "admin", adminTok)
	config := func(addr string) string {
		cfg := goodConfig(t, ts, addr)
		cfg.PostgresDSNFile, cfg.API.AdminTokenFile = dsnFile, adminFile
		cfg.Leader = svc.Leader{Poll: svc.Duration(200 * time.Millisecond), Check: svc.Duration(200 * time.Millisecond)}
		return configFile(t, cfg)
	}
	addrA, addrB, addrC := freeAddr(t), freeAddr(t), freeAddr(t)

	childA := exec.Command(os.Args[0])
	childA.Env = append(os.Environ(), "PW_TEST_HELPER=1", "PW_TEST_REAL_PG=1", "PW_TEST_ARGS=--config\n"+config(addrA))
	childA.Stdout, childA.Stderr = io.Discard, io.Discard
	if err := childA.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = childA.Process.Kill(); _ = childA.Wait() }()
	waitFor(t, "A to lead", func() bool { return roleOf(t, addrA) == "leader" })
	ctxB, cancelB := context.WithCancel(ctx)
	defer cancelB()
	doneB := make(chan error, 1)
	go func() { doneB <- run(ctxB, config(addrB), openPG) }()
	waitFor(t, "B to stand by", func() bool { return roleOf(t, addrB) == "standby" })

	seq := uint64(0)
	heartbeat := func() {
		t.Helper()
		seq++
		hb, _ := proto.Marshal(&asmv1.Heartbeat{EventId: bus.NewEventID(), HostId: testnats.Host, RunId: "run-1", Seq: seq, At: timestamppb.Now()})
		if _, err := ts.HostJS.Publish(ctx, bus.Subject(testnats.Host, bus.KindHeartbeat), hb); err != nil {
			t.Fatal(err)
		}
	}
	heartbeat()
	waitFor(t, "A's heartbeat, read through standby B", func() bool { return !lastHeartbeat(t, addrB).IsZero() })
	first := lastHeartbeat(t, addrB)

	killed := time.Now()
	if err := childA.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B to lead after A's SIGKILL", func() bool { return roleOf(t, addrB) == "leader" })
	t.Logf("handover after SIGKILL: %s", time.Since(killed).Round(time.Millisecond))
	time.Sleep(10 * time.Millisecond)
	heartbeat()
	waitFor(t, "B to store the next heartbeat", func() bool { return lastHeartbeat(t, addrB).After(first) })

	ctxC, cancelC := context.WithCancel(ctx)
	defer cancelC()
	doneC := make(chan error, 1)
	go func() { doneC <- run(ctxC, config(addrC), openPG) }()
	waitFor(t, "C to stand by", func() bool { return roleOf(t, addrC) == "standby" })
	if code, _, body := request(t, "DELETE", "http://"+addrC+"/v1/hosts/gone?force=1", adminTok); code != http.StatusServiceUnavailable {
		t.Fatalf("forget on standby C: %d %s", code, body)
	}
	if code, _, body := request(t, "DELETE", "http://"+addrB+"/v1/hosts/gone?force=1", adminTok); code != http.StatusOK {
		t.Fatalf("forget on leader B: %d %s", code, body)
	}

	var pid int32
	if err := adm.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 1
		AND ((classid::bigint << 32) | objid::bigint) = $1`, int64(pg.LeaderLock)).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	dropped := time.Now()
	if _, err := adm.Exec(ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
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
	waitFor(t, "C to lead after B's lock session dropped", func() bool { return roleOf(t, addrC) == "leader" })
	t.Logf("handover after the lock session dropped: %s", time.Since(dropped).Round(time.Millisecond))
	second := lastHeartbeat(t, addrC)
	time.Sleep(10 * time.Millisecond)
	heartbeat()
	waitFor(t, "C to store the next heartbeat", func() bool { return lastHeartbeat(t, addrC).After(second) })
	cancelC()
	if err := <-doneC; !errors.Is(err, context.Canceled) {
		t.Fatalf("C's stop: %v", err)
	}
}
