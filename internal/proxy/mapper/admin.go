package mapper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/admin"
	"github.com/thapr0digy/portwarden/internal/proxy/caddy"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/discover"
	"github.com/thapr0digy/portwarden/internal/proxy/haproxy"
)

// AdminConfig turns on reading proxies' admin interfaces (internal/proxy/admin).
type AdminConfig struct {
	// Kinds are the proxy kinds whose admin interface is read (discover.KindCaddy,
	// discover.KindHAProxy).
	Kinds map[string]bool
	// Poll re-reads every proxy's admin interface; 0: only on start, restart and recheck.
	Poll time.Duration
	// Read is admin.Read with the production Host bound.
	Read func(ctx context.Context, p admin.Proxy, ep admin.Endpoint, q admin.Query) (admin.Answer, error)
	// SelfNetNS is the agent's network namespace.
	SelfNetNS uint32
	// HostContainerNet reports whether an address is reached over a host container
	// network (netif); nil: container proxies are not dialled.
	HostContainerNet func(netip.Addr) bool
}

// AdminKinds are the kinds the admin reader supports.
var AdminKinds = []string{discover.KindCaddy, discover.KindHAProxy}

// adminState is what the last admin read of a proxy gave.
type adminState struct {
	endpoints []admin.Endpoint
	names     *conf.Names
	// skip is the note for a proxy whose admin interface is not read (off, none
	// configured); no read is started then.
	skip     string
	inflight bool
	again    bool // another read was asked for while one ran
	gen      uint64
	// have: a verified answer is in hand (routes or servers below); note is the failure
	// of the last read otherwise.
	have    bool
	note    string
	hash    string
	via     string
	routes  []conf.Route
	servers []haproxy.RuntimeServer
	notes   []string
}

// reset forgets the endpoints and the answer; a read still running stays counted (so
// only one runs per proxy) and its result, of an older generation, is dropped.
func (a adminState) reset() adminState {
	return adminState{gen: a.gen + 1, inflight: a.inflight}
}

// adminResult is one finished read, handed back to the mapper goroutine.
type adminResult struct {
	id  string
	gen uint64
	// err is why no answer was read, or why it did not parse.
	err     error
	via     string
	hash    string
	routes  []conf.Route
	servers []haproxy.RuntimeServer
	notes   []string
}

func (m *Mapper) adminOn(kind string) bool {
	return m.cfg.Admin != nil && m.cfg.Admin.Kinds[kind]
}

// readable reports whether the mapper has routes to read for this kind: from its config
// files, or from its admin interface.
func (m *Mapper) readable(kind string) bool {
	return discover.ConfigReadable(kind) || (kind == discover.KindCaddy && m.adminOn(kind))
}

// planAdmin works out a trusted proxy's admin endpoints after its config was read (the
// HAProxy loader lists the stats sockets; Caddy's come from its command line, environment
// and config file) and keeps the previous answer only if the endpoints are unchanged.
func (m *Mapper) planAdmin(t *tracked, fsys conf.FS) {
	if !m.adminOn(t.inst.Kind) || !t.inst.Trusted {
		t.adm = t.adm.reset()
		return
	}
	var eps []admin.Endpoint
	skip := ""
	switch t.inst.Kind {
	case discover.KindCaddy:
		master := t.inst.Master()
		args := master.Cmdline
		if len(args) == 0 {
			args = m.cfg.Procs.Cmdline(master.PID)
		}
		a := caddy.AdminAddress(fsys, args, m.cfg.Procs.Environ(master.PID))
		if a.Off {
			skip = "admin:off (" + a.Origin + "); routes are inferred from observed connections"
		} else {
			eps = []admin.Endpoint{{Network: a.Network, Addr: a.Addr, Origin: a.Origin}}
		}
	case discover.KindHAProxy:
		for _, s := range t.res.AdminSockets {
			eps = append(eps, admin.Endpoint{Network: s.Network, Addr: s.Addr, Origin: s.Source})
		}
		if len(eps) == 0 {
			skip = "admin:no stats socket in the config; runtime changes not read"
		}
	}
	if !slices.Equal(eps, t.adm.endpoints) || skip != t.adm.skip {
		t.adm = t.adm.reset()
	}
	t.adm.endpoints, t.adm.skip = eps, skip
	t.adm.names = conf.LoadNames(fsys)
}

// startAdmin starts a read of t's admin interface unless one is running (then it runs
// again when that one ends). The read and the parse happen off the mapper goroutine.
func (m *Mapper) startAdmin(ctx context.Context, t *tracked) {
	if len(t.adm.endpoints) == 0 || m.cfg.Admin == nil || m.cfg.Admin.Read == nil {
		return
	}
	if t.adm.inflight {
		t.adm.again = true
		return
	}
	t.adm.inflight, t.adm.again = true, false
	t.adm.gen++
	id, gen, kind := t.inst.ID, t.adm.gen, t.inst.Kind
	p := m.adminProxy(t)
	eps, names := slices.Clone(t.adm.endpoints), t.adm.names
	read := m.cfg.Admin.Read
	go func() {
		r := adminResult{id: id, gen: gen}
		q := admin.Query{HTTPPath: caddy.ConfigPath}
		if kind == discover.KindHAProxy {
			q = admin.Query{Command: "show servers state"}
		}
		// The endpoints are tried in order; the first failure is kept when none answers
		// (it is the one the proxy declares first).
		var firstErr error
		for _, ep := range eps {
			ans, err := read(ctx, p, ep, q)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			sum := sha256.Sum256(ans.Body)
			r.via, r.hash, firstErr = ans.Via, hex.EncodeToString(sum[:]), nil
			var perr error
			if kind == discover.KindCaddy {
				var res conf.Result
				res, perr = caddy.Parse(ans.Body, ans.Via, names)
				r.routes, r.notes = res.Routes, res.Notes
			} else {
				r.servers, perr = haproxy.ParseServersState(ans.Body)
			}
			if perr != nil {
				r.err = errors.New("admin:undetermined " + ans.Via + ": " + perr.Error())
			}
			break
		}
		if firstErr != nil {
			r.err = firstErr
		}
		select {
		case m.adminDone <- r:
		case <-ctx.Done():
		}
	}()
}

func (m *Mapper) adminProxy(t *tracked) admin.Proxy {
	p := admin.Proxy{
		PIDs: slices.Clone(t.inst.PIDs), Exe: t.inst.Master().Exe, Root: t.inst.Root,
		NetNS: t.inst.NetNS, SameNetNS: t.inst.NetNS == m.cfg.Admin.SelfNetNS,
		Listeners: slices.Clone(t.inst.Listeners), LocalAddrs: slices.Clone(m.addrs[t.inst.NetNS]),
		HostContainerNet: m.cfg.Admin.HostContainerNet,
	}
	return p
}

// applyAdmin folds a finished read into its proxy; it reports whether what the proxy
// publishes changed. A result for a proxy that is gone, or older than the endpoints
// (they changed while it ran), is dropped.
func (m *Mapper) applyAdmin(ctx context.Context, r adminResult, now time.Time) bool {
	t, ok := m.proxies[r.id]
	if !ok {
		return false
	}
	t.adm.inflight = false
	defer func() {
		if t.adm.again {
			m.startAdmin(ctx, t)
		}
	}()
	if r.gen != t.adm.gen {
		t.adm.again = true // the endpoints changed during the read: read them now
		return false
	}
	before := t.adm.have
	prevNote := t.adm.note
	if r.err == nil && t.adm.have && r.hash == t.adm.hash {
		return false
	}
	routes, servers, notes, err := r.routes, r.servers, r.notes, r.err
	if err != nil {
		note := err.Error()
		var ae *admin.Error
		if errors.As(err, &ae) {
			note = ae.Note()
		}
		note = conf.Redact(note)
		if ae != nil && ae.Mismatch && note != prevNote {
			slog.Warn("proxy admin answer refused", "proxy", t.inst.ID, "reason", ae.Reason)
		}
		t.adm.have, t.adm.note, t.adm.hash, t.adm.routes, t.adm.servers, t.adm.notes = false, note, "", nil, nil, nil
		if before || note != prevNote {
			t.trigger, t.at = model.ProxyTriggerConfig, now
			return true
		}
		return false
	}
	for i, rt := range routes {
		routes[i] = conf.RedactRoute(rt)
	}
	for i, n := range notes {
		notes[i] = conf.Redact(n)
	}
	t.adm.have, t.adm.note, t.adm.hash, t.adm.via = true, "", r.hash, r.via
	t.adm.routes, t.adm.servers, t.adm.notes = routes, servers, notes
	t.trigger, t.at = model.ProxyTriggerConfig, now
	return true
}

// effective is what t publishes: its config routes with the admin answer folded in.
func (t *tracked) effective() (routes []conf.Route, notes []string) {
	notes = slices.Clone(t.res.Notes)
	routes = t.res.Routes
	switch {
	case t.adm.skip != "":
		notes = append(notes, t.adm.skip)
	case t.adm.have && t.inst.Kind == discover.KindCaddy:
		routes = t.adm.routes
		notes = append(notes, "routes from the admin API at "+t.adm.via)
		notes = append(notes, t.adm.notes...)
	case t.adm.have && t.inst.Kind == discover.KindHAProxy:
		routes = haproxy.Overlay(t.res.Routes, t.adm.servers)
		for i, rt := range routes {
			routes[i] = conf.RedactRoute(rt)
		}
		notes = append(notes, "runtime state from "+t.adm.via)
	case t.adm.note != "":
		notes = append(notes, t.adm.note)
		if t.inst.Kind == discover.KindCaddy {
			notes = append(notes, "routes are inferred from observed connections")
		}
	case len(t.adm.endpoints) > 0:
		notes = append(notes, "admin:pending first read")
	}
	return routes, notes
}
