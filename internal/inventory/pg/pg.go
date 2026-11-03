// Package pg is the inventory's PostgreSQL store. Every statement is parameterized;
// migrations are embedded and applied idempotently under an advisory lock.
package pg

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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/inventory"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLock is the advisory lock key held while migrating ("pwinv" in ASCII).
const migrationLock = 0x7077696e76

// Store implements inventory.Store, inventory.Reader and inventory.CloudState.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects and migrates. The DSN is a libpq URL or key=value string; keep the
// password in a file the service reads (PGPASSFILE) or the DSN file, not the command line.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pg: dsn: %w", err)
	}
	if cfg.ConnConfig.ConnectTimeout == 0 {
		cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	}
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
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
		return fmt.Errorf("pg: migrate: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(migrationLock)); err != nil {
		return fmt.Errorf("pg: migrate lock: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("pg: migrate: %w", err)
	}
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("pg: migration %s: bad version", base)
		}
		var done bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		// Migration files are static and embedded: they are the only SQL not built from
		// fixed strings with parameters, and take no input.
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("pg: migration %s: %w", base, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", version, base); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Cursor returns a host's run and seq.
func (s *Store) Cursor(ctx context.Context, host string) (inventory.Cursor, bool, error) {
	var c inventory.Cursor
	var last, num int64
	err := s.pool.QueryRow(ctx, "SELECT run_id, last_seq, needs_resync, boot_id, run_number, retired_runs FROM hosts WHERE host_id = $1", clean(host)).
		Scan(&c.RunID, &last, &c.NeedsResync, &c.BootID, &num, &c.Retired)
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.Cursor{}, false, nil
	}
	c.LastSeq, c.RunNumber = uint64(last), uint64(num)
	return c, err == nil && c.RunID != "", err
}

// SetCursor writes a host's cursor only.
func (s *Store) SetCursor(ctx context.Context, host string, c inventory.Cursor) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if err := ensureHost(ctx, tx, host); err != nil {
			return err
		}
		return setCursor(ctx, tx, host, c)
	})
}

// SetSilent records silence (since set) or recovery (zero).
func (s *Store) SetSilent(ctx context.Context, host string, since time.Time) error {
	var arg any
	if !since.IsZero() {
		arg = since
	}
	_, err := s.pool.Exec(ctx, "UPDATE hosts SET silent_since = $2, updated_at = now() WHERE host_id = $1", host, arg)
	return err
}

// LastHeartbeats returns every host's last heartbeat.
func (s *Store) LastHeartbeats(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, "SELECT host_id, last_heartbeat FROM hosts WHERE last_heartbeat IS NOT NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var h string
		var at time.Time
		if err := rows.Scan(&h, &at); err != nil {
			return nil, err
		}
		out[h] = at
	}
	return out, rows.Err()
}

func (s *Store) tx(ctx context.Context, f func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := f(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func ensureHost(ctx context.Context, tx pgx.Tx, host string) error {
	_, err := tx.Exec(ctx, "INSERT INTO hosts (host_id) VALUES ($1) ON CONFLICT (host_id) DO NOTHING", host)
	return err
}

func setCursor(ctx context.Context, tx pgx.Tx, host string, c inventory.Cursor) error {
	retired := c.Retired
	if retired == nil {
		retired = []string{}
	}
	for i := range retired {
		retired[i] = clean(retired[i])
	}
	_, err := tx.Exec(ctx, `UPDATE hosts SET run_id = $2, last_seq = $3, needs_resync = $4, boot_id = $5, run_number = $6,
		retired_runs = $7, updated_at = now() WHERE host_id = $1`,
		host, clean(c.RunID), int64(c.LastSeq), c.NeedsResync, clean(c.BootID), int64(c.RunNumber), retired)
	return err
}

// Apply applies one event and its cursor in one transaction. Every string in the message
// is cleaned first (NUL bytes removed, invalid UTF-8 replaced), since PostgreSQL rejects
// both; a data error the database still raises (SQLSTATE classes 22, 23) is permanent.
func (s *Store) Apply(ctx context.Context, e inventory.Event) error {
	cleanMessage(e.Msg)
	e.Meta.Host, e.Meta.Kind = clean(e.Meta.Host), clean(e.Meta.Kind)
	return classify(s.apply(ctx, e))
}

func (s *Store) apply(ctx context.Context, e inventory.Event) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		host := e.Meta.Host
		if err := ensureHost(ctx, tx, host); err != nil {
			return err
		}
		at := e.Meta.StreamTime
		if at.IsZero() {
			at = time.Now()
		}
		var err error
		switch m := e.Msg.(type) {
		case *asmv1.Snapshot:
			err = applySnapshot(ctx, tx, e.Meta, m, at)
		case *asmv1.ListenerEvent:
			err = applyListener(ctx, tx, host, m, at)
		case *asmv1.ExposureEvent:
			err = applyExposure(ctx, tx, e.Meta, m, at)
		case *asmv1.ExposureConfirmation:
			err = applyConfirmation(ctx, tx, e.Meta, m, at)
		case *asmv1.ProxyRoutes:
			err = applyProxyRoutes(ctx, tx, host, m, at)
		case *asmv1.HostEvent:
			err = setHostInfo(ctx, tx, host, m.GetHost())
		case *asmv1.Heartbeat:
			_, err = tx.Exec(ctx, "UPDATE hosts SET last_heartbeat = GREATEST(last_heartbeat, $2), ringbuf_drops = $3, queue_drops = $4 WHERE host_id = $1",
				host, at, int64(m.GetRingbufDrops()), int64(m.GetQueueDrops()))
		default:
			err = fmt.Errorf("pg: unexpected message %T", e.Msg)
		}
		if err != nil {
			return err
		}
		if e.Cursor == nil {
			return nil // a backend event: never the host's firewall
		}
		if fp, ok := inventory.FirewallFingerprint(e.Msg); ok {
			if err := setFirewall(ctx, tx, host, fp, at); err != nil {
				return err
			}
		}
		return setCursor(ctx, tx, host, *e.Cursor)
	})
}

// setFirewall records the fingerprint an agent message carried (inventory.Firewall.Observe
// decides). The consumer applies a host's messages in (boot_id, run_number, seq) order and
// skips stale ones, so a late message cannot roll it back.
func setFirewall(ctx context.Context, tx pgx.Tx, host, fp string, at time.Time) error {
	var cur inventory.Firewall
	var stored *string
	var changedAt *time.Time
	if err := tx.QueryRow(ctx, "SELECT firewall_fingerprint, firewall_changed_at FROM hosts WHERE host_id = $1 FOR UPDATE", host).
		Scan(&stored, &changedAt); err != nil {
		return err
	}
	if stored != nil {
		cur = inventory.Firewall{Known: true, Fingerprint: *stored}
		if changedAt != nil {
			cur.ChangedAt = *changedAt
		}
	}
	next, write, _ := cur.Observe(fp, at)
	if !write {
		return nil
	}
	_, err := tx.Exec(ctx, "UPDATE hosts SET firewall_fingerprint = $2, firewall_changed_at = $3, updated_at = now() WHERE host_id = $1",
		host, clean(next.Fingerprint), next.ChangedAt)
	return err
}

func setHostInfo(ctx context.Context, tx pgx.Tx, host string, h *asmv1.HostInfo) error {
	if h == nil {
		return nil
	}
	ips, err := jsonList(h.GetPublicIps())
	if err != nil {
		return err
	}
	conds, err := json.Marshal(nonNil(h.GetConditions()))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE hosts SET cloud = $2, instance_id = $3, region = $4, public_ips = $5, conditions = $6,
		updated_at = now() WHERE host_id = $1`,
		host, h.GetCloud(), h.GetInstanceId(), h.GetRegion(), ips, json.RawMessage(conds))
	return err
}

const effectiveLevel = "GREATEST(agent_level, cloud_level, CASE WHEN probe_result = 'confirmed' THEN 5 ELSE 0 END)"

func upsertListener(ctx context.Context, tx pgx.Tx, host string, l *asmv1.Listener, procs []*asmv1.Process,
	behind []*asmv1.ProxyRef, exp *asmv1.Exposure, at time.Time) error {
	pj, err := jsonList(procs)
	if err != nil {
		return err
	}
	bj, err := jsonList(behind)
	if err != nil {
		return err
	}
	ev, err := json.Marshal(nonNil(exp.GetEvidence()))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO listeners (host_id, key, netns, proto, addr, port, processes, behind_proxy,
			agent_level, agent_evidence, level, opened_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $9, $11, $11)
		ON CONFLICT (host_id, key) DO UPDATE SET processes = EXCLUDED.processes, behind_proxy = EXCLUDED.behind_proxy,
			agent_level = EXCLUDED.agent_level, agent_evidence = EXCLUDED.agent_evidence, updated_at = EXCLUDED.updated_at`,
		host, listenerKey(l), int64(l.GetNetns()), l.GetProto(), l.GetAddr(), int(l.GetPort()), pj, bj,
		int16(exp.GetLevel()), json.RawMessage(ev), at)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE listeners SET level = "+effectiveLevel+" WHERE host_id = $1 AND key = $2", host, listenerKey(l))
	return err
}

func listenerKey(l *asmv1.Listener) string {
	if l.GetKey() != "" {
		return l.GetKey()
	}
	// The agent always sets key; this is the same format for messages that do not.
	return fmt.Sprintf("%d/%s/%s", l.GetNetns(), l.GetProto(), joinHostPort(l.GetAddr(), l.GetPort()))
}

func joinHostPort(addr string, port uint32) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]:" + strconv.Itoa(int(port))
	}
	return addr + ":" + strconv.Itoa(int(port))
}

func applySnapshot(ctx context.Context, tx pgx.Tx, m inventory.Meta, s *asmv1.Snapshot, at time.Time) error {
	host := m.Host
	if err := setHostInfo(ctx, tx, host, s.GetHost()); err != nil {
		return err
	}
	keys := make([]string, 0, len(s.GetListeners()))
	for _, ls := range s.GetListeners() {
		key := listenerKey(ls.GetListener())
		keys = append(keys, key)
		var prev int16
		err := tx.QueryRow(ctx, "SELECT agent_level FROM listeners WHERE host_id = $1 AND key = $2", host, key).Scan(&prev)
		known := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := upsertListener(ctx, tx, host, ls.GetListener(), ls.GetProcesses(), ls.GetBehindProxy(), ls.GetExposure(), at); err != nil {
			return err
		}
		if lvl := int16(ls.GetExposure().GetLevel()); !known || prev != lvl {
			var p *int16
			if known {
				p = &prev
			}
			if err := history(ctx, tx, m, key, at, "agent", lvl, p, ls.GetExposure().GetEvidence(), "snapshot", nil); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(ctx, "DELETE FROM listeners WHERE host_id = $1 AND NOT (key = ANY($2))", host, keys); err != nil {
		return err
	}
	ids := make([]string, 0, len(s.GetProxies()))
	for _, ps := range s.GetProxies() {
		p := ps.GetProxy()
		ids = append(ids, p.GetId())
		pj, err := protoJSON(p)
		if err != nil {
			return err
		}
		// Route sets follow the snapshot as proxy.routes events; keep the stored routes.
		if _, err := tx.Exec(ctx, `INSERT INTO proxies (host_id, proxy_id, kind, proxy, route_count, routes_digest, truncated, trigger, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'snapshot', $8)
			ON CONFLICT (host_id, proxy_id) DO UPDATE SET kind = EXCLUDED.kind, proxy = EXCLUDED.proxy,
				route_count = EXCLUDED.route_count, routes_digest = EXCLUDED.routes_digest, truncated = EXCLUDED.truncated,
				updated_at = EXCLUDED.updated_at`,
			host, p.GetId(), p.GetKind(), json.RawMessage(pj), int(ps.GetRouteCount()), ps.GetRoutesDigest(), ps.GetTruncated(), at); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "DELETE FROM proxies WHERE host_id = $1 AND NOT (proxy_id = ANY($2))", host, ids); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE hosts SET last_snapshot_at = $2 WHERE host_id = $1", host, at)
	return err
}

func applyListener(ctx context.Context, tx pgx.Tx, host string, ev *asmv1.ListenerEvent, at time.Time) error {
	if err := setHostInfo(ctx, tx, host, ev.GetHost()); err != nil {
		return err
	}
	if ev.GetKind() == asmv1.Kind_CLOSED {
		_, err := tx.Exec(ctx, "DELETE FROM listeners WHERE host_id = $1 AND key = $2", host, listenerKey(ev.GetListener()))
		return err
	}
	return upsertListener(ctx, tx, host, ev.GetListener(), ev.GetProcesses(), ev.GetBehindProxy(), ev.GetExposure(), at)
}

func applyExposure(ctx context.Context, tx pgx.Tx, m inventory.Meta, ev *asmv1.ExposureEvent, at time.Time) error {
	host, key := m.Host, listenerKey(ev.GetListener())
	lvl := int16(ev.GetExposure().GetLevel())
	var prev *int16
	if ev.GetPrevious() != nil {
		p := int16(ev.GetPrevious().GetLevel())
		prev = &p
	}
	origin := m.Origin
	if origin == "" {
		origin = "agent"
	}
	inserted, err := historyNew(ctx, tx, m, key, at, origin, lvl, prev, ev.GetExposure().GetEvidence(), ev.GetTrigger(), nil)
	if err != nil || !inserted {
		return err // a redelivered backend event was applied already
	}
	evd, err := json.Marshal(nonNil(ev.GetExposure().GetEvidence()))
	if err != nil {
		return err
	}
	if origin == "agent" {
		if err := setHostInfo(ctx, tx, host, ev.GetHost()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE listeners SET agent_level = $3, agent_evidence = $4, updated_at = $5 WHERE host_id = $1 AND key = $2",
			host, key, lvl, json.RawMessage(evd), at)
	} else {
		// A cloud verdict: level 4 when open, otherwise it adds nothing (0) but its
		// evidence says why.
		cl := int16(0)
		if lvl >= int16(asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN) {
			cl = int16(asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN)
		}
		_, err = tx.Exec(ctx, "UPDATE listeners SET cloud_level = $3, cloud_evidence = $4, cloud_at = $5, updated_at = $5 WHERE host_id = $1 AND key = $2",
			host, key, cl, json.RawMessage(evd), at)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE listeners SET level = "+effectiveLevel+" WHERE host_id = $1 AND key = $2", host, key)
	return err
}

func applyConfirmation(ctx context.Context, tx pgx.Tx, m inventory.Meta, ev *asmv1.ExposureConfirmation, at time.Time) error {
	host, key := m.Host, listenerKey(ev.GetListener())
	detail, err := json.Marshal(map[string]any{
		"result": ev.GetResult(), "target": ev.GetTarget(), "probe": ev.GetProbe(), "banner": ev.GetBanner(),
		"detail": ev.GetDetail(), "rtt_ms": ev.GetRttMs(), "checker": ev.GetChecker(),
	})
	if err != nil {
		return err
	}
	lvl := int16(0)
	if ev.GetResult() == "confirmed" {
		lvl = int16(asmv1.ExposureLevel_EXPOSURE_CONFIRMED)
	}
	evidence := ev.GetExposure().GetEvidence()
	if len(evidence) == 0 {
		evidence = []string{"probe: " + ev.GetResult() + " " + ev.GetTarget()}
	}
	inserted, err := historyNew(ctx, tx, m, key, at, "verifier", lvl, nil, evidence, ev.GetResult(), detail)
	if err != nil || !inserted {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE listeners SET probe_result = $3, probe = $4, probe_at = $5, updated_at = $5 WHERE host_id = $1 AND key = $2`,
		host, key, ev.GetResult(), json.RawMessage(detail), at)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE listeners SET level = "+effectiveLevel+" WHERE host_id = $1 AND key = $2", host, key)
	return err
}

func applyProxyRoutes(ctx context.Context, tx pgx.Tx, host string, ev *asmv1.ProxyRoutes, at time.Time) error {
	p := ev.GetProxy()
	if ev.GetRemoved() {
		_, err := tx.Exec(ctx, "DELETE FROM proxies WHERE host_id = $1 AND proxy_id = $2", host, p.GetId())
		return err
	}
	pj, err := protoJSON(p)
	if err != nil {
		return err
	}
	rj, err := jsonList(ev.GetRoutes())
	if err != nil {
		return err
	}
	count := int(ev.GetTotalRoutes())
	if count == 0 {
		count = len(ev.GetRoutes())
	}
	_, err = tx.Exec(ctx, `INSERT INTO proxies (host_id, proxy_id, kind, proxy, routes, route_count, truncated, trigger, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (host_id, proxy_id) DO UPDATE SET kind = EXCLUDED.kind, proxy = EXCLUDED.proxy, routes = EXCLUDED.routes,
			route_count = EXCLUDED.route_count, truncated = EXCLUDED.truncated, trigger = EXCLUDED.trigger, updated_at = EXCLUDED.updated_at`,
		host, p.GetId(), p.GetKind(), json.RawMessage(pj), rj, count, ev.GetTruncated(), ev.GetTrigger(), at)
	return err
}

func history(ctx context.Context, tx pgx.Tx, m inventory.Meta, key string, at time.Time, origin string, lvl int16,
	prev *int16, evidence []string, trigger string, detail []byte) error {
	_, err := historyNew(ctx, tx, m, key, at, origin, lvl, prev, evidence, trigger, detail)
	return err
}

// historyNew inserts a history row and reports whether it is new (false: this stream
// message was applied before).
func historyNew(ctx context.Context, tx pgx.Tx, m inventory.Meta, key string, at time.Time, origin string, lvl int16,
	prev *int16, evidence []string, trigger string, detail []byte) (bool, error) {
	evd, err := json.Marshal(nonNil(evidence))
	if err != nil {
		return false, err
	}
	var d any
	if detail != nil {
		d = json.RawMessage(detail)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO exposure_history (host_id, key, at, origin, level, previous_level, evidence, trigger, detail, stream_seq)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (stream_seq, host_id, key) DO NOTHING`,
		m.Host, key, at, origin, lvl, prev, json.RawMessage(evd), trigger, d, int64(m.StreamSeq))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// jsonList encodes protos as a JSON array (protojson, proto field names).
func jsonList[T proto.Message](xs []T) (json.RawMessage, error) {
	var b strings.Builder
	b.WriteByte('[')
	for i, x := range xs {
		if i > 0 {
			b.WriteByte(',')
		}
		j, err := protoJSON(x)
		if err != nil {
			return nil, err
		}
		b.Write(j)
	}
	b.WriteByte(']')
	return json.RawMessage(b.String()), nil
}

func protoJSON(m proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
}
