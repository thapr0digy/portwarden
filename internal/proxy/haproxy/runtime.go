package haproxy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// RuntimeServer is one server as HAProxy's runtime API reports it ("show servers
// state"): where it sends traffic now, which may differ from the config file after a
// "set server addr", an "add server" or a DNS resolution.
type RuntimeServer struct {
	Backend string
	Name    string
	// Addr is the server's current address and port; invalid when the runtime has none
	// (an unresolved name) or reports port 0 (the client's destination port).
	Addr netip.AddrPort
	// RawAddr and Port are what the runtime printed, for the notes.
	RawAddr string
	Port    string
	// Maint and Drain come from srv_admin_state; Down from srv_op_state.
	Maint, Drain, Down bool
}

// MaxRuntimeServers bounds the servers one answer may list.
const MaxRuntimeServers = 16384

// ErrServersState is returned for an answer that is not a "show servers state" dump.
var ErrServersState = errors.New("not a version 1 servers state dump")

// columns ParseServersState needs, looked up by name in the header line.
var stateColumns = []string{"be_name", "srv_name", "srv_addr", "srv_op_state", "srv_admin_state", "srv_port"}

// srv_admin_state bits (SRV_ADMF_* in HAProxy's server-t.h).
const (
	admForcedMaint  = 0x01
	admInheritMaint = 0x02
	admConfigMaint  = 0x04
	admForcedDrain  = 0x08
	admInheritDrain = 0x10
	admResolvMaint  = 0x20
	admHealthMaint  = 0x40
	maintBits       = admForcedMaint | admInheritMaint | admConfigMaint | admResolvMaint | admHealthMaint
	drainBits       = admForcedDrain | admInheritDrain
)

// ParseServersState reads the answer to "show servers state": a version line ("1"), a
// "# " header naming the columns, then one line per server. Columns are found by their
// header name, not their position, so columns added by later versions do not matter.
func ParseServersState(b []byte) ([]RuntimeServer, error) {
	lines := strings.Split(string(b), "\n")
	i := 0
	next := func() (string, bool) {
		for i < len(lines) {
			l := strings.TrimRight(lines[i], "\r")
			i++
			if strings.TrimSpace(l) != "" {
				return l, true
			}
		}
		return "", false
	}
	version, ok := next()
	if !ok || strings.TrimSpace(version) != "1" {
		return nil, ErrServersState
	}
	header, ok := next()
	if !ok || !strings.HasPrefix(header, "#") {
		return nil, fmt.Errorf("%w: no header", ErrServersState)
	}
	names := strings.Fields(strings.TrimPrefix(header, "#"))
	col := make(map[string]int, len(stateColumns))
	for _, want := range stateColumns {
		for k, n := range names {
			if n == want {
				col[want] = k
				break
			}
		}
		if _, ok := col[want]; !ok {
			return nil, fmt.Errorf("%w: no %s column", ErrServersState, want)
		}
	}
	var out []RuntimeServer
	for {
		l, ok := next()
		if !ok {
			return out, nil
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		if len(out) >= MaxRuntimeServers {
			return out, fmt.Errorf("more than %d servers", MaxRuntimeServers)
		}
		f := strings.Fields(l)
		if len(f) < len(names) {
			return out, fmt.Errorf("short servers state line %d (%d of %d columns)", i, len(f), len(names))
		}
		s := RuntimeServer{Backend: f[col["be_name"]], Name: f[col["srv_name"]], RawAddr: f[col["srv_addr"]], Port: f[col["srv_port"]]}
		op, err1 := strconv.ParseUint(f[col["srv_op_state"]], 10, 8)
		adm, err2 := strconv.ParseUint(f[col["srv_admin_state"]], 10, 16)
		if err1 != nil || err2 != nil {
			return out, fmt.Errorf("bad state on servers state line %d", i)
		}
		s.Down = op == 0
		s.Maint = adm&maintBits != 0
		s.Drain = adm&drainBits != 0
		if a, err := netip.ParseAddr(s.RawAddr); err == nil {
			if p, err := strconv.ParseUint(s.Port, 10, 16); err == nil && p != 0 {
				s.Addr = netip.AddrPortFrom(a.Unmap(), uint16(p))
			}
		}
		out = append(out, s)
	}
}

// Overlay folds the runtime servers into the routes read from the config: a server whose
// runtime address differs from the file's gets the runtime one (noted), a server only the
// runtime knows (added with "add server") is added (noted), and a server's maintenance or
// drain state is noted. Nothing is removed: a file server the runtime does not list is
// kept, with a note, so the overlay can never hide a backend. Routes are matched by
// backend name (Upstream).
func Overlay(routes []conf.Route, servers []RuntimeServer) []conf.Route {
	byBackend := make(map[string][]RuntimeServer)
	for _, s := range servers {
		byBackend[s.Backend] = append(byBackend[s.Backend], s)
	}
	out := make([]conf.Route, len(routes))
	for i, rt := range routes {
		out[i] = rt
		rs, ok := byBackend[rt.Upstream]
		if rt.Upstream == "" || !ok {
			continue
		}
		out[i].Backends = overlayBackends(rt.Backends, rs)
	}
	return out
}

// overlayBackends matches file backends to runtime servers by server name. A
// server-template backend stands for the runtime's <prefix><n> servers: they are listed
// after it (noted), and the template line itself is kept as the config states it.
func overlayBackends(file []conf.Backend, rs []RuntimeServer) []conf.Backend {
	var out []conf.Backend
	used := make([]bool, len(rs))
	for _, b := range file {
		if strings.Contains(b.Note, "server-template") {
			out = append(out, b)
			for k, s := range rs {
				if !used[k] && templated(s.Name, b.Server) {
					used[k] = true
					rb := runtimeBackend(s)
					rb.Note = joinNote(rb.Note, "server-template "+b.Server+" (runtime)")
					out = append(out, rb)
				}
			}
			continue
		}
		k := -1
		for j, s := range rs {
			if !used[j] && b.Server != "" && s.Name == b.Server {
				k = j
				break
			}
		}
		if k < 0 {
			b.Note = joinNote(b.Note, "not in runtime state")
			out = append(out, b)
			continue
		}
		used[k] = true
		out = append(out, applyRuntime(b, rs[k]))
	}
	for k, s := range rs {
		if used[k] {
			continue
		}
		b := runtimeBackend(s)
		b.Note = joinNote(b.Note, "added at runtime")
		out = append(out, b)
	}
	return out
}

// templated reports whether a runtime server name is one a server-template with this
// prefix creates (the prefix and a number).
func templated(name, prefix string) bool {
	n, ok := strings.CutPrefix(name, prefix)
	if !ok || n == "" || prefix == "" {
		return false
	}
	_, err := strconv.ParseUint(n, 10, 32)
	return err == nil
}

// applyRuntime gives a file backend the runtime's address when they differ. A Unix
// socket server keeps its path (the runtime prints the path as its address).
func applyRuntime(b conf.Backend, s RuntimeServer) conf.Backend {
	if b.Unix == "" && s.Addr.IsValid() && !(len(b.Addrs) == 1 && b.Addrs[0] == s.Addr) {
		b.Note = joinNote(dropUnresolved(b.Note), "runtime address (file: "+b.Address+")")
		b.Address, b.Addrs = s.Addr.String(), []netip.AddrPort{s.Addr}
	}
	return withState(b, s)
}

// dropUnresolved removes the "unresolved: …" part of a note: the runtime resolved it.
func dropUnresolved(note string) string {
	var keep []string
	for _, p := range strings.Split(note, "; ") {
		if p != "" && !strings.HasPrefix(p, "unresolved:") {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, "; ")
}

func runtimeBackend(s RuntimeServer) conf.Backend {
	b := conf.Backend{Address: s.RawAddr + ":" + s.Port}
	switch {
	case s.Addr.IsValid():
		b.Address, b.Addrs = s.Addr.String(), []netip.AddrPort{s.Addr}
	case strings.HasPrefix(s.RawAddr, "/"):
		b.Address, b.Unix = s.RawAddr, s.RawAddr
	default:
		b.Note = "unresolved: runtime address " + b.Address
	}
	return withState(b, s)
}

func withState(b conf.Backend, s RuntimeServer) conf.Backend {
	switch {
	case s.Maint:
		b.Note = joinNote(b.Note, "maint (runtime)")
	case s.Drain:
		b.Note = joinNote(b.Note, "drain (runtime)")
	}
	if s.Down && !s.Maint {
		b.Note = joinNote(b.Note, "down (runtime)")
	}
	return b
}
