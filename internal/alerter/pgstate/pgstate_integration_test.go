//go:build integration

package pgstate

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/alerter"
)

func open(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("PORTWARDEN_TEST_PG")
	if dsn == "" {
		t.Fatal("PORTWARDEN_TEST_PG is not set; run the integration tests through dev/itest.sh")
	}
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.pool.Exec(context.Background(), "TRUNCATE alerter_pages, alerter_dedupe, alerter_probe, alerter_forgotten"); err != nil {
		t.Fatal(err)
	}
	return s
}

// Marks and pages are written in one transaction (a failed decision leaves nothing),
// survive a reopen, and pages are retried until delivered.
func TestOutboxAndState(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	boom := errors.New("boom")
	if err := s.InTx(ctx, func(st alerter.State) error {
		_ = st.SetPaged(ctx, "listener:h/k", now)
		_ = st.Enqueue(ctx, &alerter.Alert{ID: "lost", Kind: "x"})
		return boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := s.InTx(ctx, func(st alerter.State) error {
		if _, ok, _ := st.LastPaged(ctx, "listener:h/k"); ok {
			t.Error("rolled-back mark persisted")
		}
		if err := st.SetProbeResult(ctx, "h/k", "confirmed", now); err != nil {
			return err
		}
		return st.Enqueue(ctx, &alerter.Alert{ID: "a1", Kind: alerter.KindNewlyReachable, Host: "h\x00", Summary: "s"})
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open2(t)
	due, err := s.Due(ctx, now.Add(time.Second), 10)
	if err != nil || len(due) != 1 || due[0].ID != "a1" {
		t.Fatalf("due %+v %v", due, err)
	}
	if err := s.Failed(ctx, "a1", now.Add(time.Hour), false, "HTTP 503"); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.Due(ctx, now.Add(time.Second), 10); len(due) != 0 {
		t.Fatal("retried before its backoff")
	}
	due, _ = s.Due(ctx, now.Add(2*time.Hour), 10)
	if len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("due after backoff %+v", due)
	}
	if err := s.Delivered(ctx, "a1", now); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.Due(ctx, now.Add(3*time.Hour), 10); len(due) != 0 {
		t.Fatal("delivered page still due")
	}
	_ = s.InTx(ctx, func(st alerter.State) error {
		if r, _ := st.ProbeResult(ctx, "h/k"); r != "confirmed" {
			t.Errorf("probe result %q", r)
		}
		return nil
	})
}

func open2(t *testing.T) *Store {
	s, err := Open(context.Background(), os.Getenv("PORTWARDEN_TEST_PG"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// PagedKeys matches a literal prefix: a host id with LIKE wildcards matches nothing else.
func TestPagedKeysPrefix(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.InTx(ctx, func(st alerter.State) error {
		for _, k := range []string{"tamper:h1/ptraced/self", "tamper:h1/unit_changed/x", "tamper:h10/ptraced/self", "tamper:h_/a/b", "listener:h1/k"} {
			if err := st.SetPaged(ctx, k, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTx(ctx, func(st alerter.State) error {
		got, err := st.PagedKeys(ctx, "tamper:h1/")
		if err != nil {
			return err
		}
		if len(got) != 2 || got[0] != "tamper:h1/ptraced/self" || got[1] != "tamper:h1/unit_changed/x" {
			t.Errorf("tamper:h1/ = %v", got)
		}
		if got, _ := st.PagedKeys(ctx, "tamper:h%"); len(got) != 0 {
			t.Errorf("a wildcard prefix matched %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLikePrefixEscapes(t *testing.T) {
	if got := likePrefix(`tamper:h_%\/`); got != `tamper:h\_\%\\/%` {
		t.Fatalf("got %q", got)
	}
}

// A forget drops the host's marks and probe results (and no other host's, even one whose
// id has LIKE wildcards or shares a prefix), and its watermark survives a reopen.
func TestForgetHost(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	e := alerter.NewEngine(alerter.Rules{}, func() string { return "x" })
	hosts := []string{"web", "web-2", "w_b", "we%"}
	if err := s.InTx(ctx, func(st alerter.State) error {
		for _, h := range hosts {
			for _, k := range []string{"silent:" + h, alerter.TamperPrefix(h) + "ptraced/self/1", "listener:" + h + "/k"} {
				if err := st.SetPaged(ctx, k, now); err != nil {
					return err
				}
			}
			if err := st.SetProbeResult(ctx, h+"/k", "confirmed", now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"w_b", "web"} {
		if err := s.InTx(ctx, func(st alerter.State) error { return e.Forget(ctx, st, h, 77) }); err != nil {
			t.Fatal(err)
		}
	}
	var marks, probes int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM alerter_dedupe").Scan(&marks)
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM alerter_probe").Scan(&probes)
	if marks != 6 || probes != 2 {
		t.Fatalf("left %d marks and %d probes, want 6 and 2 (web-2 and we%% untouched)", marks, probes)
	}
	if err := s.InTx(ctx, func(st alerter.State) error { return st.SetForgotten(ctx, "web", 5) }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open2(t)
	got, err := s.Forgotten(ctx)
	if err != nil || len(got) != 2 || got["web"] != 77 || got["w_b"] != 77 {
		t.Fatalf("forgotten %v %v", got, err)
	}
}
