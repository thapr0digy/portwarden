package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Default retention (M8): exposure history 90 days, quarantined messages 30 days.
const (
	DefaultHistoryRetention    = 90 * 24 * time.Hour
	DefaultQuarantineRetention = 30 * 24 * time.Hour
)

// Pruner deletes one bounded batch of old rows per call and reports how many it deleted.
type Pruner interface {
	PruneHistory(ctx context.Context, before time.Time, batch int) (int64, error)
	PruneQuarantine(ctx context.Context, before time.Time, batch int) (int64, error)
}

// Retention prunes exposure_history and quarantine by age, in batches on a timer, so no
// statement holds its locks for long. A zero History or Quarantine keeps that table
// forever.
type Retention struct {
	History, Quarantine time.Duration
	// Interval between passes (default 1 h); the first pass runs a minute after start.
	Interval time.Duration
	// Batch is the rows per DELETE (default 1000); MaxBatches bounds one pass per table
	// (default 1000; the next pass continues).
	Batch, MaxBatches int
	// Pause between batches (default 50 ms), so other writers get the table.
	Pause time.Duration
	Now   func() time.Time
}

// WithDefaults fills the zero tuning fields (not the ages: zero keeps forever).
func (r Retention) WithDefaults() Retention {
	if r.Interval <= 0 {
		r.Interval = time.Hour
	}
	if r.Batch <= 0 {
		r.Batch = 1000
	}
	if r.MaxBatches <= 0 {
		r.MaxBatches = 1000
	}
	return r
}

// Run prunes until ctx ends.
func (r Retention) Run(ctx context.Context, p Pruner) {
	r = r.WithDefaults()
	if r.History == 0 && r.Quarantine == 0 {
		slog.Info("retention: off (history and quarantine kept forever)")
		return
	}
	if r.Pause <= 0 {
		r.Pause = 50 * time.Millisecond
	}
	wait := time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = r.Interval
		h, q, err := r.Pass(ctx, p)
		if err != nil && ctx.Err() == nil {
			slog.Warn("retention pass failed; retried at the next interval", "err", err, "history_deleted", h, "quarantine_deleted", q)
			continue
		}
		if h > 0 || q > 0 {
			slog.Info("retention pass", "history_deleted", h, "quarantine_deleted", q)
		}
	}
}

// Pass runs one pass over both tables.
func (r Retention) Pass(ctx context.Context, p Pruner) (history, quarantine int64, err error) {
	r = r.WithDefaults()
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	var errs []error
	if r.History > 0 {
		history, err = r.table(ctx, now.Add(-r.History), p.PruneHistory)
		if err != nil {
			errs = append(errs, fmt.Errorf("exposure_history: %w", err))
		}
	}
	if r.Quarantine > 0 {
		quarantine, err = r.table(ctx, now.Add(-r.Quarantine), p.PruneQuarantine)
		if err != nil {
			errs = append(errs, fmt.Errorf("quarantine: %w", err))
		}
	}
	return history, quarantine, errors.Join(errs...)
}

func (r Retention) table(ctx context.Context, before time.Time, prune func(context.Context, time.Time, int) (int64, error)) (int64, error) {
	var total int64
	for range r.MaxBatches {
		n, err := prune(ctx, before, r.Batch)
		total += n
		if err != nil || n < int64(r.Batch) {
			return total, err
		}
		if r.Pause > 0 {
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			case <-time.After(r.Pause):
			}
		}
	}
	return total, nil
}
