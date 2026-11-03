package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thapr0digy/portwarden/internal/inventory"
)

// Forget removes a host (its listeners and proxies by cascade, and its exposure history)
// and records its forget mark, in one transaction (M8). A mark of the same stream with a
// higher sequence is kept; one of another stream is replaced.
func (s *Store) Forget(ctx context.Context, host string, mark inventory.Mark) (bool, error) {
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
		_, err = tx.Exec(ctx, `INSERT INTO forgotten_hosts (host_id, stream_seq, stream_created) VALUES ($1, $2, $3)
			ON CONFLICT (host_id) DO UPDATE SET
				stream_seq = CASE WHEN forgotten_hosts.stream_created = EXCLUDED.stream_created
					THEN GREATEST(forgotten_hosts.stream_seq, EXCLUDED.stream_seq) ELSE EXCLUDED.stream_seq END,
				stream_created = EXCLUDED.stream_created, forgotten_at = now()`, host, int64(mark.Seq), mark.Stream)
		return err
	})
	return existed, err
}

// ForgottenMark returns a host's forget mark (ok false when it was never forgotten).
func (s *Store) ForgottenMark(ctx context.Context, host string) (inventory.Mark, bool, error) {
	var seq int64
	var m inventory.Mark
	err := s.pool.QueryRow(ctx, "SELECT stream_seq, stream_created FROM forgotten_hosts WHERE host_id = $1", clean(host)).Scan(&seq, &m.Stream)
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.Mark{}, false, nil
	}
	m.Seq = uint64(seq)
	return m, err == nil, err
}

// PruneMarks drops the forget marks of another stream and those past lastSeq.
func (s *Store) PruneMarks(ctx context.Context, stream time.Time, lastSeq uint64) (int64, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM forgotten_hosts WHERE stream_created <> $1 OR stream_seq > $2", stream, int64(lastSeq))
	return tag.RowsAffected(), err
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
