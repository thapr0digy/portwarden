package pg

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thapr0digy/portwarden/internal/inventory"
)

const (
	defaultLimit = 1000
	maxLimit     = 10000
)

// clampLimit bounds a list's rows: the default for 0, at most maxLimit plus the one row
// the API asks for beyond a page.
func clampLimit(n int) int {
	if n <= 0 {
		return defaultLimit
	}
	return min(n, maxLimit+1)
}

const hostColumns = `h.host_id, h.cloud, h.instance_id, h.region, h.public_ips, h.conditions, h.run_id, h.last_seq,
	h.needs_resync, h.last_snapshot_at, h.last_heartbeat, h.ringbuf_drops, h.queue_drops, h.silent_since, h.cloud_status,
	h.cloud_checked_at, h.first_seen, h.updated_at, h.firewall_fingerprint, h.firewall_changed_at, h.tamper, h.tamper_at,
	(SELECT count(*) FROM listeners l WHERE l.host_id = h.host_id)`

func scanHost(row pgx.Row) (inventory.HostView, error) {
	var v inventory.HostView
	var ips, conds, tamper []byte
	var last, rb, qd int64
	var n int64
	err := row.Scan(&v.ID, &v.Cloud, &v.InstanceID, &v.Region, &ips, &conds, &v.RunID, &last, &v.NeedsResync,
		&v.LastSnapshotAt, &v.LastHeartbeat, &rb, &qd, &v.SilentSince, &v.CloudStatus, &v.CloudCheckedAt,
		&v.FirstSeen, &v.UpdatedAt, &v.FirewallFingerprint, &v.FirewallChangedAt, &tamper, &v.TamperAt, &n)
	v.PublicIPs, v.Conditions = json.RawMessage(ips), json.RawMessage(conds)
	if tamper != nil {
		v.Tamper = json.RawMessage(tamper)
	}
	v.LastSeq, v.RingbufDrops, v.QueueDrops, v.Listeners = uint64(last), uint64(rb), uint64(qd), int(n)
	v.Silent = v.SilentSince != nil
	return v, err
}

// Hosts lists hosts by id, after q.After.
func (s *Store) Hosts(ctx context.Context, q inventory.HostQuery) ([]inventory.HostView, error) {
	after, from := "", false
	if q.After != nil {
		after, from = q.After.ID, true
	}
	rows, err := s.pool.Query(ctx, "SELECT "+hostColumns+" FROM hosts h WHERE (NOT $1 OR h.host_id > $2) ORDER BY h.host_id LIMIT $3",
		from, after, clampLimit(q.Limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []inventory.HostView{}
	for rows.Next() {
		v, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Host returns one host.
func (s *Store) Host(ctx context.Context, id string) (inventory.HostView, bool, error) {
	v, err := scanHost(s.pool.QueryRow(ctx, "SELECT "+hostColumns+" FROM hosts h WHERE h.host_id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.HostView{}, false, nil
	}
	return v, err == nil, err
}

// Listeners lists listeners matching f. Every filter is a bind parameter; the WHERE
// clause is assembled only from fixed fragments.
func (s *Store) Listeners(ctx context.Context, f inventory.ListenerFilter) ([]inventory.ListenerView, error) {
	var where []string
	var args []any
	add := func(fragment string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(fragment, "$?", "$"+strconv.Itoa(len(args))))
	}
	if f.Host != "" {
		add("host_id = $?", f.Host)
	}
	if f.Proto != "" {
		add("proto = $?", f.Proto)
	}
	if f.Addr != "" {
		add("addr = $?", f.Addr)
	}
	if f.Port != 0 {
		add("port = $?", f.Port)
	}
	if f.MinLevel != 0 {
		add("level >= $?", f.MinLevel)
	}
	if f.Unit != "" {
		add("processes @> jsonb_build_array(jsonb_build_object('unit', $?::text))", f.Unit)
	}
	if f.Exe != "" {
		add("processes @> jsonb_build_array(jsonb_build_object('exe', $?::text))", f.Exe)
	}
	if a := f.After; a != nil {
		args = append(args, a.Host, a.Proto, a.Port, a.Key)
		n := len(args)
		where = append(where, "(host_id, proto, port, key) > ($"+strconv.Itoa(n-3)+", $"+strconv.Itoa(n-2)+
			", $"+strconv.Itoa(n-1)+", $"+strconv.Itoa(n)+")")
	}
	q := `SELECT host_id, key, netns, proto, addr, port, level, agent_level, agent_evidence, cloud_level, cloud_evidence,
		cloud_at, probe_result, probe, probe_at, processes, behind_proxy, opened_at, updated_at FROM listeners`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, clampLimit(f.Limit))
	q += " ORDER BY host_id, proto, port, key LIMIT $" + strconv.Itoa(len(args))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []inventory.ListenerView{}
	for rows.Next() {
		var v inventory.ListenerView
		var netns int64
		var lvl, agent, cloud int16
		var aev, cev, probe, procs, behind []byte
		if err := rows.Scan(&v.Host, &v.Key, &netns, &v.Proto, &v.Addr, &v.Port, &lvl, &agent, &aev, &cloud, &cev,
			&v.CloudAt, &v.ProbeResult, &probe, &v.ProbeAt, &procs, &behind, &v.OpenedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		v.Netns = uint32(netns)
		v.Level, v.AgentLevel, v.CloudLevel = inventory.LevelName(int(lvl)), inventory.LevelName(int(agent)), inventory.LevelName(int(cloud))
		v.AgentEvidence, v.CloudEvidence, v.Processes, v.BehindProxy = aev, cev, procs, behind
		if probe != nil {
			v.Probe = probe
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// History returns a listener's exposure changes, newest first, after q.After.
func (s *Store) History(ctx context.Context, q inventory.HistoryQuery) ([]inventory.HistoryView, error) {
	var at time.Time
	var id int64
	from := q.After != nil
	if from {
		at, id = q.After.At, q.After.ID
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, origin, level, previous_level, evidence, trigger, detail FROM exposure_history
		WHERE host_id = $1 AND key = $2 AND (NOT $4 OR (at, id) < ($5, $6)) ORDER BY at DESC, id DESC LIMIT $3`,
		q.Host, q.Key, clampLimit(q.Limit), from, at, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []inventory.HistoryView{}
	for rows.Next() {
		var v inventory.HistoryView
		var lvl int16
		var prev *int16
		var evd, detail []byte
		if err := rows.Scan(&v.ID, &v.At, &v.Origin, &lvl, &prev, &evd, &v.Trigger, &detail); err != nil {
			return nil, err
		}
		v.Level = inventory.LevelName(int(lvl))
		if prev != nil {
			v.PreviousLevel = inventory.LevelName(int(*prev))
		}
		v.Evidence = evd
		if detail != nil {
			v.Detail = detail
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Proxies returns proxies with their routes; empty host or proxyID match all.
func (s *Store) Proxies(ctx context.Context, host, proxyID string) ([]inventory.ProxyView, error) {
	rows, err := s.pool.Query(ctx, `SELECT host_id, proxy_id, kind, proxy, routes, route_count, routes_digest, truncated, trigger, updated_at
		FROM proxies WHERE ($1 = '' OR host_id = $1) AND ($2 = '' OR proxy_id = $2) ORDER BY host_id, proxy_id LIMIT $3`,
		host, proxyID, maxLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []inventory.ProxyView{}
	for rows.Next() {
		var v inventory.ProxyView
		var p, r []byte
		if err := rows.Scan(&v.Host, &v.ProxyID, &v.Kind, &p, &r, &v.RouteCount, &v.RoutesDigest, &v.Truncated, &v.Trigger, &v.UpdatedAt); err != nil {
			return nil, err
		}
		v.Proxy, v.Routes = p, r
		out = append(out, v)
	}
	return out, rows.Err()
}

// CloudHosts lists hosts with a cloud identity.
func (s *Store) CloudHosts(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, "SELECT host_id FROM hosts WHERE cloud <> '' ORDER BY host_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CloudHost returns a host's identity and listeners for the cloud look-up.
func (s *Store) CloudHost(ctx context.Context, host string) (inventory.CloudHost, bool, error) {
	var h inventory.CloudHost
	err := s.pool.QueryRow(ctx, "SELECT host_id, cloud, instance_id, region FROM hosts WHERE host_id = $1", host).
		Scan(&h.ID, &h.Cloud, &h.InstanceID, &h.Region)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, false, nil
	}
	if err != nil {
		return h, false, err
	}
	rows, err := s.pool.Query(ctx, `SELECT key, proto, addr, port, netns, agent_level, agent_evidence, cloud_level, cloud_evidence
		FROM listeners WHERE host_id = $1 ORDER BY key`, host)
	if err != nil {
		return h, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var l inventory.CloudListener
		var netns int64
		var agent, cloud int16
		var aev, cev []byte
		if err := rows.Scan(&l.Key, &l.Proto, &l.Addr, &l.Port, &netns, &agent, &aev, &cloud, &cev); err != nil {
			return h, false, err
		}
		l.Netns, l.AgentLevel, l.CloudLevel = uint32(netns), int(agent), int(cloud)
		if err := json.Unmarshal(aev, &l.AgentEvidence); err != nil {
			return h, false, err
		}
		if err := json.Unmarshal(cev, &l.CloudEvidence); err != nil {
			return h, false, err
		}
		h.Listeners = append(h.Listeners, l)
	}
	return h, true, rows.Err()
}

// SetCloudStatus records the cloud look-up's outcome for a host.
func (s *Store) SetCloudStatus(ctx context.Context, host, status string, at time.Time) error {
	_, err := s.pool.Exec(ctx, "UPDATE hosts SET cloud_status = $2, cloud_checked_at = $3 WHERE host_id = $1", host, status, at)
	return err
}

var (
	_ inventory.Store      = (*Store)(nil)
	_ inventory.Reader     = (*Store)(nil)
	_ inventory.CloudState = (*Store)(nil)
)

// ProbeInput returns a listener's stored state for a probe request.
func (s *Store) ProbeInput(ctx context.Context, host, key string) (inventory.ProbeInput, bool, error) {
	var in inventory.ProbeInput
	var netns int64
	var lvl int16
	var evd, ips []byte
	err := s.pool.QueryRow(ctx, `SELECT l.netns, l.key, l.proto, l.addr, l.port, l.level, l.agent_evidence, h.public_ips
		FROM listeners l JOIN hosts h ON h.host_id = l.host_id WHERE l.host_id = $1 AND l.key = $2`, clean(host), clean(key)).
		Scan(&netns, &in.Key, &in.Proto, &in.Addr, &in.Port, &lvl, &evd, &ips)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, false, nil
	}
	if err != nil {
		return in, false, err
	}
	in.Netns, in.Level = uint32(netns), int(lvl)
	if err := json.Unmarshal(evd, &in.AgentEvidence); err != nil {
		return in, false, err
	}
	var cands []struct {
		IP  string `json:"ip"`
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(ips, &cands); err != nil {
		return in, false, err
	}
	for _, c := range cands {
		if c.Dir == "in" {
			in.InboundIPs = append(in.InboundIPs, c.IP)
		}
	}
	return in, true, nil
}

// StaleProbes lists listeners due for a reprobe.
func (s *Store) StaleProbes(ctx context.Context, before time.Time, limit int) ([]inventory.HostKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT host_id, key FROM listeners WHERE level >= 2 AND (probe_at IS NULL OR probe_at < $1)
		ORDER BY probe_at NULLS FIRST, host_id, key LIMIT $2`, before, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []inventory.HostKey
	for rows.Next() {
		var hk inventory.HostKey
		if err := rows.Scan(&hk.Host, &hk.Key); err != nil {
			return nil, err
		}
		out = append(out, hk)
	}
	return out, rows.Err()
}

var _ inventory.ProbeState = (*Store)(nil)
