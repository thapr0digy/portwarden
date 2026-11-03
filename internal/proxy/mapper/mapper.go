// Package mapper keeps the proxy mapping current: it finds the proxies among the
// listener holders, reads their configurations (again when a config file changes and
// holds still, when a proxy restarts, and on the recheck), tracks the proxies in the
// connect-counting probes and folds the observed connections in. Every change goes out as
// one proxy.Update with the full set of proxies.
package mapper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy"
	"github.com/thapr0digy/portwarden/internal/proxy/apache"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/discover"
	"github.com/thapr0digy/portwarden/internal/proxy/haproxy"
	"github.com/thapr0digy/portwarden/internal/proxy/nginx"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
	"github.com/thapr0digy/portwarden/internal/state"
)

// Conn is one counted destination (probes.ProxyConn).
type Conn struct {
	Proxy uint32
	Addr  netip.AddrPort
	Count uint64
	Last  time.Time
}

// Conns is the connect-counting probe (probes.ProxyConns behind an adapter).
type Conns interface {
	SetCgroups(paths []string) error
	SetPIDs(pids []uint32) error
	Read() ([]Conn, error)
}

// Config wires the mapper to the host.
type Config struct {
	Procs       discover.Procs
	SelfMountNS uint64
	// Enrich fills a master process that holds no listener itself.
	Enrich func(model.Process) model.Process
	// OpenRoot opens a proxy's root ("/" or /proc/<pid>/root); rootfs.Open.
	OpenRoot func(root string) (rootfs.FS, error)
	// NetnsAddrs lists the local addresses of a network namespace, read through one of
	// its processes.
	NetnsAddrs func(netns uint32, pid uint32) ([]netip.Addr, error)
	// Conns counts the proxies' connects; nil: no observed connections.
	Conns Conns
	// Poll is how often config fingerprints and connection counts are read (2 s);
	// Settle how long a changed config must hold still before it is read (2 s).
	Poll, Settle time.Duration
	// Recheck re-reads every config and namespace address; 0 disables.
	Recheck time.Duration
}

type tracked struct {
	inst    discover.Instance
	res     conf.Result
	fp      string // fingerprint of res.Watch when res was read
	pending string // a newer fingerprint waiting to settle
	since   time.Time
	// observed accumulates the counted destinations; raw is the last kernel count per
	// destination, so a count that drops (entries evicted or reset) is not lost.
	observed map[netip.AddrPort]proxy.Observed
	raw      map[netip.AddrPort]uint64
	trigger  string
	at       time.Time
}

// Mapper runs the proxy mapping; create it with New, feed it Listeners, start Run.
type Mapper struct {
	cfg       Config
	listeners chan []state.Listener
	proxies   map[string]*tracked
	addrs     map[uint32][]netip.Addr
	current   []state.Listener
	attached  string // the last cgroup and pid sets given to Conns, to skip no-op updates
}

// New returns a mapper; Poll and Settle default to 2 s.
func New(cfg Config) *Mapper {
	if cfg.Poll <= 0 {
		cfg.Poll = 2 * time.Second
	}
	if cfg.Settle <= 0 {
		cfg.Settle = 2 * time.Second
	}
	return &Mapper{
		cfg: cfg, listeners: make(chan []state.Listener, 1),
		proxies: make(map[string]*tracked), addrs: make(map[uint32][]netip.Addr),
	}
}

// Listeners hands the mapper the current listener set; it never blocks, and only the
// newest set matters.
func (m *Mapper) Listeners(ls []state.Listener) {
	for {
		select {
		case m.listeners <- ls:
			return
		default:
		}
		select {
		case <-m.listeners:
		default:
		}
	}
}

// Run maps until ctx ends, calling out (from this goroutine) after every change.
func (m *Mapper) Run(ctx context.Context, out func(proxy.Update)) {
	poll := time.NewTicker(m.cfg.Poll)
	defer poll.Stop()
	var recheckC <-chan time.Time
	if m.cfg.Recheck > 0 {
		t := time.NewTicker(m.cfg.Recheck)
		defer t.Stop()
		recheckC = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ls := <-m.listeners:
			m.current = ls
			if m.sync(time.Now()) {
				out(m.update())
			}
		case now := <-poll.C:
			changed := m.checkConfigs(now)
			if m.readConns(now) {
				changed = true
			}
			if changed {
				out(m.update())
			}
		case now := <-recheckC:
			clear(m.addrs)
			for _, t := range m.proxies {
				m.read(t, model.ProxyTriggerRecheck, now)
			}
			m.sync(now)
			out(m.update())
		}
	}
}

// sync matches the tracked proxies to the instances in the current listener set and
// reports whether anything changed.
func (m *Mapper) sync(now time.Time) bool {
	changed := false
	found := discover.Find(m.current, m.cfg.Procs, m.cfg.SelfMountNS, m.cfg.Enrich)
	seen := make(map[string]bool, len(found))
	for _, inst := range found {
		seen[inst.ID] = true
		t, ok := m.proxies[inst.ID]
		switch {
		case !ok:
			t = &tracked{observed: make(map[netip.AddrPort]proxy.Observed), raw: make(map[netip.AddrPort]uint64)}
			t.inst = inst
			m.proxies[inst.ID] = t
			m.read(t, model.ProxyTriggerStarted, now)
			changed = true
		case t.inst.Master().PID != inst.Master().PID || t.inst.Root != inst.Root:
			// A restart: the new master may run a different config.
			t.inst = inst
			m.read(t, model.ProxyTriggerListener, now)
			changed = true
		case !sameInstance(t.inst, inst):
			t.inst = inst
			t.trigger, t.at = model.ProxyTriggerListener, now
			changed = true
		}
	}
	for id := range m.proxies {
		if !seen[id] {
			delete(m.proxies, id)
			changed = true
		}
	}
	if m.refreshAddrs() {
		changed = true
	}
	m.track()
	return changed
}

func sameInstance(a, b discover.Instance) bool {
	return slices.Equal(a.PIDs, b.PIDs) && slices.Equal(a.Listeners, b.Listeners) &&
		slices.EqualFunc(a.Procs, b.Procs, model.Process.SameIdentity) && a.Cgroup == b.Cgroup
}

// track gives the connect probe the proxies' cgroups and pids.
func (m *Mapper) track() {
	if m.cfg.Conns == nil {
		return
	}
	var cgroups []string
	var pids []uint32
	for _, t := range m.proxies {
		if t.inst.Cgroup != "" && !slices.Contains(cgroups, t.inst.Cgroup) {
			cgroups = append(cgroups, t.inst.Cgroup)
		}
		pids = append(pids, t.inst.PIDs...)
	}
	slices.Sort(cgroups)
	slices.Sort(pids)
	key := fmt.Sprint(cgroups, pids)
	if key == m.attached {
		return
	}
	m.attached = key
	if err := m.cfg.Conns.SetPIDs(pids); err != nil {
		slog.Warn("proxy connection tracking: pids", "error", err.Error())
	}
	if err := m.cfg.Conns.SetCgroups(cgroups); err != nil {
		slog.Warn("proxy connection tracking: cgroups", "error", err.Error())
	}
}

// refreshAddrs reads the addresses of every netns that holds a listener and is not
// cached yet.
func (m *Mapper) refreshAddrs() bool {
	if m.cfg.NetnsAddrs == nil {
		return false
	}
	changed := false
	present := make(map[uint32]bool)
	for _, l := range m.current {
		ns := l.Key.NetNS
		present[ns] = true
		if _, ok := m.addrs[ns]; ok {
			continue
		}
		var pid uint32
		for _, p := range l.Procs {
			if p.PID != 0 {
				pid = p.PID
				break
			}
		}
		as, err := m.cfg.NetnsAddrs(ns, pid)
		if err != nil {
			continue // tried again with the next listener set
		}
		m.addrs[ns] = as
		changed = true
	}
	for ns := range m.addrs {
		if !present[ns] {
			delete(m.addrs, ns)
		}
	}
	return changed
}

// read loads a proxy's configuration and remembers its fingerprint.
func (m *Mapper) read(t *tracked, trigger string, now time.Time) {
	t.trigger, t.at = trigger, now
	t.pending = ""
	if !discover.ConfigReadable(t.inst.Kind) {
		t.res = conf.Result{}
		return
	}
	fsys, err := m.cfg.OpenRoot(t.inst.Root)
	if err != nil {
		t.res = conf.Result{Notes: []string{"unreadable root " + t.inst.Root + ": " + err.Error()}}
		t.fp = ""
		return
	}
	defer fsys.Close()
	switch t.inst.Kind {
	case discover.KindNginx:
		t.res = nginx.Load(fsys, t.inst.NginxConf)
	case discover.KindApache:
		t.res = apache.Load(fsys, t.inst.Apache)
	case discover.KindHAProxy:
		t.res = haproxy.Load(fsys, t.inst.HAProxyFile)
	}
	t.fp = fingerprint(fsys, t.res.Watch)
}

// fingerprint identifies the state of every watched path: identity, size and mtime of
// what exists, and which paths are missing.
func fingerprint(fsys conf.FS, paths []string) string {
	h := sha256.New()
	for _, p := range paths {
		in, err := fsys.Stat(p)
		if err != nil {
			fmt.Fprintf(h, "%s|missing\n", p)
			continue
		}
		fmt.Fprintf(h, "%s|%d|%d|%d|%d|%t\n", p, in.Dev, in.Ino, in.Size, in.ModTime.UnixNano(), in.Dir)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// checkConfigs re-reads a proxy whose files changed and then held still for Settle.
func (m *Mapper) checkConfigs(now time.Time) bool {
	changed := false
	for _, t := range m.proxies {
		if !discover.ConfigReadable(t.inst.Kind) || len(t.res.Watch) == 0 {
			continue
		}
		fsys, err := m.cfg.OpenRoot(t.inst.Root)
		if err != nil {
			continue
		}
		cur := fingerprint(fsys, t.res.Watch)
		_ = fsys.Close()
		switch {
		case cur == t.fp:
			t.pending = ""
		case cur != t.pending:
			t.pending, t.since = cur, now
		case now.Sub(t.since) >= m.cfg.Settle:
			m.read(t, model.ProxyTriggerConfig, now)
			changed = true
		}
	}
	return changed
}

// readConns folds the kernel's counts into each proxy's observed destinations.
func (m *Mapper) readConns(now time.Time) bool {
	if m.cfg.Conns == nil || len(m.proxies) == 0 {
		return false
	}
	conns, err := m.cfg.Conns.Read()
	if err != nil {
		slog.Warn("proxy connections", "error", err.Error())
	}
	owner := make(map[uint32]*tracked)
	for _, t := range m.proxies {
		for _, pid := range t.inst.PIDs {
			owner[pid] = t
		}
	}
	type sum struct {
		count uint64
		last  time.Time
	}
	sums := make(map[*tracked]map[netip.AddrPort]sum)
	for _, c := range conns {
		t := owner[c.Proxy]
		if t == nil {
			continue
		}
		if sums[t] == nil {
			sums[t] = make(map[netip.AddrPort]sum)
		}
		s := sums[t][c.Addr]
		s.count += c.Count
		if c.Last.After(s.last) {
			s.last = c.Last
		}
		sums[t][c.Addr] = s
	}
	changed := false
	for t, byAddr := range sums {
		newDest := false
		for a, s := range byAddr {
			delta := s.count
			if prev := t.raw[a]; s.count >= prev {
				delta = s.count - prev
			}
			t.raw[a] = s.count
			if delta == 0 {
				continue
			}
			o, had := t.observed[a]
			o.Addr, o.Count = a, o.Count+delta
			if s.last.After(o.Last) {
				o.Last = s.last
			}
			t.observed[a] = o
			changed = true
			if !had {
				newDest = true
			}
		}
		if newDest {
			t.trigger, t.at = model.ProxyTriggerTraffic, now
		}
	}
	return changed
}

// update renders the full view.
func (m *Mapper) update() proxy.Update {
	ids := make([]string, 0, len(m.proxies))
	for id := range m.proxies {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	u := proxy.Update{NetnsAddrs: make(map[uint32][]netip.Addr, len(m.addrs))}
	for ns, as := range m.addrs {
		u.NetnsAddrs[ns] = slices.Clone(as)
	}
	for _, id := range ids {
		t := m.proxies[id]
		inst := t.inst.ProxyInstance
		inst.Procs = slices.Clone(inst.Procs)
		inst.Listeners = slices.Clone(inst.Listeners)
		inst.Files = slices.Clone(t.res.Files)
		inst.Notes = slices.Clone(t.res.Notes)
		if m.cfg.Conns == nil {
			inst.Notes = append(inst.Notes, "observed connections unavailable")
		}
		if !discover.ConfigReadable(inst.Kind) {
			inst.Notes = append(inst.Notes, "config not read for "+inst.Kind+": routes are inferred from observed connections")
		}
		s := proxy.State{Instance: inst, Routes: t.res.Routes, Trigger: t.trigger, At: t.at}
		for _, o := range t.observed {
			s.Observed = append(s.Observed, o)
		}
		slices.SortFunc(s.Observed, func(a, b proxy.Observed) int { return a.Addr.Compare(b.Addr) })
		u.States = append(u.States, s)
	}
	return u
}
