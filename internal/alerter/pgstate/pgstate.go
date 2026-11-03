// Package pgstate keeps the alerter's state in PostgreSQL: an outbox of pages (delivered
// with retries across restarts), dedupe marks and the last probe result per listener.
package pgstate

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/thapr0digy/portwarden/internal/alerter"
)

//go:embed migrations/*.sql
var migrations embed.FS

const migrationLock = 0x7077616c72 // "pwalr"

// Store is the alerter's PostgreSQL state.
type Store struct{ pool *pgxpool.Pool }

// Open connects and migrates.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstate: dsn: %w", err)
	}
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	}
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the pool.
func (s *Store) Close() { s.pool.Close() }

func (s *Store) migrate(ctx context.Context) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(migrationLock)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS alerter_schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("pgstate: migration %s: bad version", base)
		}
		var done bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM alerter_schema_migrations WHERE version = $1)", version).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("pgstate: migration %s: %w", base, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO alerter_schema_migrations (version, name) VALUES ($1, $2)", version, base); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// InTx runs f with a State bound to one transaction, committed when f succeeds.
func (s *Store) InTx(ctx context.Context, f func(alerter.State) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := f(txState{tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type txState struct{ tx pgx.Tx }

func clean(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

func (t txState) LastPaged(ctx context.Context, key string) (time.Time, bool, error) {
	var at time.Time
	err := t.tx.QueryRow(ctx, "SELECT paged_at FROM alerter_dedupe WHERE key = $1", clean(key)).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return at, false, nil
	}
	return at, err == nil, err
}

func (t txState) SetPaged(ctx context.Context, key string, at time.Time) error {
	_, err := t.tx.Exec(ctx, `INSERT INTO alerter_dedupe (key, paged_at) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET paged_at = EXCLUDED.paged_at`, clean(key), at)
	return err
}

func (t txState) ClearPaged(ctx context.Context, key string) error {
	_, err := t.tx.Exec(ctx, "DELETE FROM alerter_dedupe WHERE key = $1", clean(key))
	return err
}

func (t txState) ProbeResult(ctx context.Context, key string) (string, error) {
	var r string
	err := t.tx.QueryRow(ctx, "SELECT result FROM alerter_probe WHERE key = $1", clean(key)).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return r, err
}

func (t txState) SetProbeResult(ctx context.Context, key, result string, at time.Time) error {
	_, err := t.tx.Exec(ctx, `INSERT INTO alerter_probe (key, result, at) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET result = EXCLUDED.result, at = EXCLUDED.at`, clean(key), clean(result), at)
	return err
}

func (t txState) Enqueue(ctx context.Context, a *alerter.Alert) error {
	b, err := cleanJSON(a)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(ctx, `INSERT INTO alerter_pages (id, kind, host, payload) VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO NOTHING`, a.ID, a.Kind, clean(a.Host), json.RawMessage(b))
	return err
}

// Page is an outbox entry.
type Page struct {
	ID       string
	Alert    alerter.Alert
	Attempts int
}

// Due returns undelivered pages whose next attempt is due, oldest first.
func (s *Store) Due(ctx context.Context, now time.Time, limit int) ([]Page, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, payload, attempts FROM alerter_pages
		WHERE delivered_at IS NULL AND gave_up_at IS NULL AND next_attempt <= $1 ORDER BY created_at, id LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Page
	for rows.Next() {
		var p Page
		var b []byte
		if err := rows.Scan(&p.ID, &b, &p.Attempts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &p.Alert); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Delivered marks a page delivered.
func (s *Store) Delivered(ctx context.Context, id string, at time.Time) error {
	_, err := s.pool.Exec(ctx, "UPDATE alerter_pages SET delivered_at = $2, attempts = attempts + 1 WHERE id = $1", id, at)
	return err
}

// Failed records a failed attempt: retried at next, or given up when giveUp.
func (s *Store) Failed(ctx context.Context, id string, next time.Time, giveUp bool, why string) error {
	if giveUp {
		_, err := s.pool.Exec(ctx, "UPDATE alerter_pages SET gave_up_at = now(), attempts = attempts + 1, last_error = $2 WHERE id = $1", id, clean(why))
		return err
	}
	_, err := s.pool.Exec(ctx, "UPDATE alerter_pages SET next_attempt = $2, attempts = attempts + 1, last_error = $3 WHERE id = $1",
		id, next, clean(why))
	return err
}

// Prune drops listener dedupe marks older than window and finished pages older than a
// week (silence and feed marks stay until cleared).
func (s *Store) Prune(ctx context.Context, now time.Time, window time.Duration) error {
	if _, err := s.pool.Exec(ctx, "DELETE FROM alerter_dedupe WHERE key LIKE 'listener:%' AND paged_at < $1", now.Add(-window)); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM alerter_pages WHERE (delivered_at IS NOT NULL OR gave_up_at IS NOT NULL)
		AND created_at < $1`, now.Add(-7*24*time.Hour))
	return err
}

// cleanJSON encodes v with every string cleaned (jsonb rejects \u0000).
func cleanJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(cleanValue(generic))
}

func cleanValue(v any) any {
	switch x := v.(type) {
	case string:
		return clean(x)
	case []any:
		for i := range x {
			x[i] = cleanValue(x[i])
		}
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[clean(k)] = cleanValue(e)
		}
		return out
	}
	return v
}
