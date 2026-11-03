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
	if _, err := s.pool.Exec(context.Background(), "TRUNCATE alerter_pages, alerter_dedupe, alerter_probe"); err != nil {
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
