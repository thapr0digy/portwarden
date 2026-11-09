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
	if _, err := s.pool.Exec(context.Background(), "TRUNCATE alerter_pages, alerter_dedupe, alerter_probe, alerter_forgotten, alerter_runs"); err != nil {
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
		if err := s.InTx(ctx, func(st alerter.State) error {
			return e.Forget(ctx, st, h, alerter.ForgetMark{Seq: 77, Stream: pgStream1})
		}); err != nil {
			t.Fatal(err)
		}
	}
	var marks, probes int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM alerter_dedupe").Scan(&marks)
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM alerter_probe").Scan(&probes)
	if marks != 6 || probes != 2 {
		t.Fatalf("left %d marks and %d probes, want 6 and 2 (web-2 and we%% untouched)", marks, probes)
	}
	// An older announcement of the same stream changes nothing; SetBack sticks.
	if err := s.InTx(ctx, func(st alerter.State) error {
		if err := st.SetForgotten(ctx, "web", alerter.ForgetMark{Seq: 5, Stream: pgStream1}); err != nil {
			return err
		}
		return st.SetBack(ctx, "web")
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open2(t)
	got, err := s.Forgotten(ctx)
	if err != nil || len(got) != 2 || !sameMark(got["web"], alerter.ForgetMark{Seq: 77, Stream: pgStream1, Back: true}) ||
		!sameMark(got["w_b"], alerter.ForgetMark{Seq: 77, Stream: pgStream1}) {
		t.Fatalf("forgotten %v %v", got, err)
	}
	var m alerter.ForgetMark
	var ok bool
	_ = s.InTx(ctx, func(st alerter.State) error { m, ok, err = st.ForgetMark(ctx, "web"); return err })
	if !ok || !m.Back || m.Seq != 77 {
		t.Fatalf("ForgetMark %+v %v", m, ok)
	}
}

var (
	pgStream1 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	pgStream2 = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
)

// The stream was recreated (sequences start over) and a host id is reused: the old mark
// goes at start, as does one past the new stream's last sequence; a new stream's
// announcement replaces an old mark whatever its sequence.
func TestForgottenAcrossAStreamReset(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.InTx(ctx, func(st alerter.State) error {
		for h, m := range map[string]alerter.ForgetMark{"reused": {Seq: 5000, Stream: pgStream1}, "past-end": {Seq: 900, Stream: pgStream2},
			"kept": {Seq: 7, Stream: pgStream2}, "replaced": {Seq: 4000, Stream: pgStream1}} {
			if err := st.SetForgotten(ctx, h, m); err != nil {
				return err
			}
		}
		return st.SetForgotten(ctx, "replaced", alerter.ForgetMark{Seq: 3, Stream: pgStream2})
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneForgotten(ctx, pgStream2, 100)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d (%v), want 2", n, err)
	}
	got, _ := s.Forgotten(ctx)
	if len(got) != 2 || got["kept"].Seq != 7 || !sameMark(got["replaced"], alerter.ForgetMark{Seq: 3, Stream: pgStream2}) {
		t.Fatalf("left %v", got)
	}
}

// sameMark compares marks with time.Time.Equal (PostgreSQL returns the local zone).
func sameMark(a, b alerter.ForgetMark) bool {
	return a.Seq == b.Seq && a.Back == b.Back && a.Stream.Equal(b.Stream)
}

// Migration 0004: a host's agent run round-trips (NUL bytes cleaned), is replaced, and is
// dropped by ClearRun.
func TestRunState(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	want := alerter.Run{ID: "01A", BootID: "b1", Number: 7, Version: "1.4.0", Identity: true}
	if err := s.InTx(ctx, func(st alerter.State) error {
		if _, ok, err := st.Run(ctx, "h"); err != nil || ok {
			t.Errorf("no run yet: %v %v", ok, err)
		}
		if err := st.SetRun(ctx, "h", alerter.Run{ID: "old\x00"}); err != nil {
			return err
		}
		return st.SetRun(ctx, "h", want)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTx(ctx, func(st alerter.State) error {
		got, ok, err := st.Run(ctx, "h")
		if err != nil || !ok || got != want {
			t.Errorf("run = %+v %v %v, want %+v", got, ok, err, want)
		}
		if err := st.ClearRun(ctx, "h"); err != nil {
			return err
		}
		if _, ok, err := st.Run(ctx, "h"); err != nil || ok {
			t.Errorf("after ClearRun: %v %v", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
