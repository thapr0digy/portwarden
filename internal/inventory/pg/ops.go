package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Forget removes a host (its listeners and proxies by cascade, and its exposure history)
// and records its forget watermark, in one transaction (M8).
func (s *Store) Forget(ctx context.Context, host string, streamSeq uint64) (bool, error) {
	host = clean(host)
	var existed bool
	err := s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM hosts WHERE host_id = $1", host)
		if err != nil {
			return err
		}
		existed = tag.RowsAffected() == 1
		if _, err := tx.Exec(ctx, "DELETE FROM exposure_history WHERE host_id = $1", host); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO forgotten_hosts (host_id, stream_seq) VALUES ($1, $2)
			ON CONFLICT (host_id) DO UPDATE SET stream_seq = GREATEST(forgotten_hosts.stream_seq, EXCLUDED.stream_seq),
				forgotten_at = now()`, host, int64(streamSeq))
		return err
	})
	return existed, err
}

// ForgottenSeq returns a host's forget watermark (0 when it was never forgotten).
func (s *Store) ForgottenSeq(ctx context.Context, host string) (uint64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, "SELECT stream_seq FROM forgotten_hosts WHERE host_id = $1", clean(host)).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return uint64(seq), err
}

// PruneHistory deletes at most batch exposure_history rows older than before, oldest
// first, in one short statement, and returns how many it deleted.
func (s *Store) PruneHistory(ctx context.Context, before time.Time, batch int) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM exposure_history WHERE id IN (
		SELECT id FROM exposure_history WHERE at < $1 ORDER BY at LIMIT $2)`, before, batch)
	return tag.RowsAffected(), err
}

// PruneQuarantine deletes at most batch quarantined messages older than before.
func (s *Store) PruneQuarantine(ctx context.Context, before time.Time, batch int) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM quarantine WHERE id IN (
		SELECT id FROM quarantine WHERE at < $1 ORDER BY at LIMIT $2)`, before, batch)
	return tag.RowsAffected(), err
}
