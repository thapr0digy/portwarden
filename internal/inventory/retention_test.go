package inventory

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakePruner holds row times per table; each call deletes up to batch rows older than
// before and records the batch size.
type fakePruner struct {
	rows    map[string][]time.Time
	batches map[string][]int
	fail    error
}

func (f *fakePruner) prune(table string, before time.Time, batch int) (int64, error) {
	if f.fail != nil {
		return 0, f.fail
	}
	f.batches[table] = append(f.batches[table], batch)
	var keep []time.Time
	var n int64
	for _, at := range f.rows[table] {
		if at.Before(before) && n < int64(batch) {
			n++
			continue
		}
		keep = append(keep, at)
	}
	f.rows[table] = keep
	return n, nil
}

func (f *fakePruner) PruneHistory(_ context.Context, before time.Time, batch int) (int64, error) {
	return f.prune("history", before, batch)
}

func (f *fakePruner) PruneQuarantine(_ context.Context, before time.Time, batch int) (int64, error) {
	return f.prune("quarantine", before, batch)
}

func rowsAged(now time.Time, ages ...time.Duration) []time.Time {
	var out []time.Time
	for _, a := range ages {
		out = append(out, now.Add(-a))
	}
	return out
}

func TestRetentionPassDeletesOnlyOldRowsInBatches(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	f := &fakePruner{batches: map[string][]int{}, rows: map[string][]time.Time{
		"history":    rowsAged(now, 100*day, 95*day, 91*day, 89*day, time.Hour),
		"quarantine": rowsAged(now, 40*day, 31*day, 29*day),
	}}
	r := Retention{History: 90 * day, Quarantine: 30 * day, Batch: 2, Now: func() time.Time { return now }}
	h, q, err := r.Pass(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if h != 3 || q != 2 || len(f.rows["history"]) != 2 || len(f.rows["quarantine"]) != 1 {
		t.Fatalf("deleted %d/%d, left %v", h, q, f.rows)
	}
	// Two full batches and a short one: each statement is bounded.
	if got := f.batches["history"]; len(got) != 2 || got[0] != 2 {
		t.Fatalf("history batches %v", got)
	}
}

func TestRetentionZeroKeepsForever(t *testing.T) {
	now := time.Now()
	f := &fakePruner{batches: map[string][]int{}, rows: map[string][]time.Time{
		"history": rowsAged(now, 1000*24*time.Hour), "quarantine": rowsAged(now, 1000*24*time.Hour)}}
	r := Retention{History: 0, Quarantine: time.Hour, Batch: 10, Now: func() time.Time { return now }}
	if _, _, err := r.Pass(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if len(f.batches["history"]) != 0 || len(f.rows["history"]) != 1 {
		t.Fatal("history with retention 0 was pruned")
	}
	if len(f.rows["quarantine"]) != 0 {
		t.Fatal("quarantine was not pruned")
	}
}

func TestRetentionPassIsBounded(t *testing.T) {
	now := time.Now()
	var old []time.Duration
	for range 50 {
		old = append(old, 48*time.Hour)
	}
	f := &fakePruner{batches: map[string][]int{}, rows: map[string][]time.Time{"history": rowsAged(now, old...)}}
	r := Retention{History: time.Hour, Batch: 5, MaxBatches: 3, Now: func() time.Time { return now }}
	h, _, err := r.Pass(context.Background(), f)
	if err != nil || h != 15 || len(f.batches["history"]) != 3 {
		t.Fatalf("deleted %d in %d batches (%v); want 15 in 3 (the next pass continues)", h, len(f.batches["history"]), err)
	}
}

func TestRetentionPassReportsErrors(t *testing.T) {
	f := &fakePruner{batches: map[string][]int{}, fail: errors.New("db down")}
	r := Retention{History: time.Hour, Quarantine: time.Hour, Batch: 5}
	if _, _, err := r.Pass(context.Background(), f); err == nil {
		t.Fatal("a failed delete was not reported")
	}
}

func TestRetentionDefaults(t *testing.T) {
	r := Retention{}.WithDefaults()
	if r.Batch != 1000 || r.Interval != time.Hour || r.MaxBatches != 1000 {
		t.Fatalf("defaults %+v", r)
	}
}
