// Package caddy reads the routes of a running Caddy from its admin API's answer to
// GET /config/ (the JSON config Caddy runs, whatever it was loaded from: a Caddyfile, a
// JSON file, or API calls). Only the HTTP app is read: each server's listen addresses
// and its routes, through subroutes, down to the handlers that send traffic somewhere
// (reverse_proxy, file_server, static_response). Fetching the answer, and proving Caddy
// gave it, is internal/proxy/admin's job; this package only parses bytes.
package caddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// ConfigPath is the admin API path whose answer Parse reads.
const ConfigPath = "/config/"

// MaxDepth bounds nested subroutes.
const MaxDepth = conf.MaxDepth

// MaxRoutes bounds the routes one answer yields (proxy.MaxRoutes publishes 500).
const MaxRoutes = 4096

type config struct {
	Apps map[string]json.RawMessage `json:"apps"`
}

type httpApp struct {
	Servers map[string]server `json:"servers"`
}

type server struct {
	Listen []string `json:"listen"`
	Routes []route  `json:"routes"`
}

type route struct {
	Match  []map[string]json.RawMessage `json:"match"`
	Handle []json.RawMessage            `json:"handle"`
}

type handler struct {
	Handler string `json:"handler"`
	// reverse_proxy
	Upstreams        []upstream      `json:"upstreams"`
	DynamicUpstreams json.RawMessage `json:"dynamic_upstreams"`
	Transport        *struct {
		Protocol string `json:"protocol"`
	} `json:"transport"`
	// file_server and vars
	Root string `json:"root"`
	// static_response
	StatusCode json.RawMessage `json:"status_code"`
	// subroute
	Routes []route `json:"routes"`
}

type upstream struct {
	Dial string `json:"dial"`
}

// Parse reads a /config/ answer. source names where it came from ("127.0.0.1:2019");
// each route's Source is the admin URL of the route itself (Caddy's config paths), so a
// route can be looked up on the proxy. names resolves upstream hosts without DNS.
func Parse(b []byte, source string, names *conf.Names) (conf.Result, error) {
	var res conf.Result
	if len(bytes.TrimSpace(b)) == 0 || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		res.Notes = append(res.Notes, "caddy runs no config")
		return res, nil
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return res, fmt.Errorf("caddy config: %w", err)
	}
	p := &parser{names: names, src: source + ConfigPath}
	appNames := make([]string, 0, len(cfg.Apps))
	for name := range cfg.Apps {
		appNames = append(appNames, name)
	}
	slices.Sort(appNames)
	for _, name := range appNames {
		switch name {
		case "http":
			var app httpApp
			if err := json.Unmarshal(cfg.Apps[name], &app); err != nil {
				return res, fmt.Errorf("caddy http app: %w", err)
			}
			p.http(app)
		case "tls", "pki":
		default:
			p.note("app %s not read", name)
		}
	}
	res.Routes, res.Notes = p.routes, append(res.Notes, p.notes...)
	return res, nil
}

type parser struct {
	names  *conf.Names
	src    string
	routes []conf.Route
	notes  []string
	cut    bool
}

func (p *parser) note(format string, args ...any) {
	n := fmt.Sprintf(format, args...)
	if !slices.Contains(p.notes, n) && len(p.notes) < conf.MaxNotes {
		p.notes = append(p.notes, n)
	}
}

// scope is what the enclosing routes matched and set.
type scope struct {
	hosts, paths, other []string
	root                string
}

func (p *parser) http(app httpApp) {
	ids := make([]string, 0, len(app.Servers))
	for id := range app.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := app.Servers[id]
		listen := make([]string, 0, len(s.Listen))
		for _, a := range s.Listen {
			listen = append(listen, normListen(a))
		}
		base := conf.Route{Listen: listen}
		p.walk(s.Routes, base, scope{}, "apps/http/servers/"+id+"/routes", 0)
	}
}

// walk reads routes in order; at is the config path of the list.
func (p *parser) walk(routes []route, base conf.Route, sc scope, at string, depth int) {
	if depth > MaxDepth {
		p.note("subroutes nested over %d at %s", MaxDepth, at)
		return
	}
	for i, r := range routes {
		here := at + "/" + strconv.Itoa(i)
		rs := p.match(r.Match, sc)
		for j, raw := range r.Handle {
			var h handler
			if err := json.Unmarshal(raw, &h); err != nil {
				p.note("handler at %s/handle/%d unreadable", here, j)
				continue
			}
			hat := here + "/handle/" + strconv.Itoa(j)
			switch h.Handler {
			case "subroute":
				p.walk(h.Routes, base, rs, hat+"/routes", depth+1)
			case "vars":
				if h.Root != "" {
					rs.root = h.Root
				}
			case "reverse_proxy":
				p.add(p.proxy(base, rs, h, hat))
			case "file_server":
				root := h.Root
				if root == "" {
					root = rs.root
				}
				if root == "" {
					root = "(working directory)"
				}
				rt := p.route(base, rs, hat)
				rt.Kind, rt.Target, rt.Root = model.RouteStatic, root, root
				p.add(rt)
			case "static_response":
				rt := p.route(base, rs, hat)
				rt.Kind, rt.Target = model.RouteReturn, statusText(h.StatusCode)
				p.add(rt)
			}
		}
	}
}

func (p *parser) add(rt conf.Route) {
	if len(p.routes) >= MaxRoutes {
		if !p.cut {
			p.cut = true
			p.note("more than %d routes; the rest not read", MaxRoutes)
		}
		return
	}
	p.routes = append(p.routes, rt)
}

func (p *parser) route(base conf.Route, sc scope, at string) conf.Route {
	rt := base
	rt.Listen = slices.Clone(base.Listen)
	rt.ServerNames = slices.Clone(sc.hosts)
	rt.Path = strings.Join(sc.paths, ",")
	rt.Source = p.src + at
	for _, o := range sc.other {
		rt.Notes = append(rt.Notes, "matcher "+o)
	}
	return rt
}

// match narrows the enclosing scope by a route's matcher sets (any set may match):
// hosts and paths are collected, other matchers named in a note. An inner host or path
// list replaces the outer one, as the inner route only runs for requests both match.
func (p *parser) match(sets []map[string]json.RawMessage, sc scope) scope {
	out := scope{hosts: sc.hosts, paths: sc.paths, other: sc.other, root: sc.root}
	var hosts, paths, other []string
	for _, set := range sets {
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			switch k {
			case "host":
				hosts = appendStrings(hosts, set[k])
			case "path":
				paths = appendStrings(paths, set[k])
			default:
				if !slices.Contains(other, k) {
					other = append(other, k)
				}
			}
		}
	}
	if len(hosts) > 0 {
		out.hosts = hosts
	}
	if len(paths) > 0 {
		out.paths = paths
	}
	if len(other) > 0 {
		out.other = append(slices.Clone(sc.other), other...)
	}
	return out
}

func appendStrings(dst []string, raw json.RawMessage) []string {
	var vs []string
	if json.Unmarshal(raw, &vs) != nil {
		return dst
	}
	for _, v := range vs {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

func (p *parser) proxy(base conf.Route, sc scope, h handler, at string) conf.Route {
	rt := p.route(base, sc, at)
	rt.Kind = model.RouteProxy
	if h.Transport != nil && h.Transport.Protocol == "fastcgi" {
		rt.Kind = model.RouteFastCGI
	}
	var dials []string
	for _, u := range h.Upstreams {
		dials = append(dials, u.Dial)
		rt.Backends = append(rt.Backends, p.backend(u.Dial))
	}
	rt.Target = strings.Join(dials, " ")
	if len(h.DynamicUpstreams) > 0 && string(h.DynamicUpstreams) != "null" {
		note := "unresolved: dynamic upstreams"
		rt.Notes = append(rt.Notes, note)
		rt.Backends = append(rt.Backends, conf.Backend{Address: "(dynamic)", Note: note})
		if rt.Target == "" {
			rt.Target = "(dynamic upstreams)"
		}
	}
	return rt
}

// backend resolves an upstream's dial address: "host:port", "[v6]:port", a network
// prefix ("tcp/", "unix/"), or a placeholder.
func (p *parser) backend(dial string) conf.Backend {
	network, addr := "", dial
	if n, a, ok := strings.Cut(dial, "/"); ok && !strings.Contains(n, ":") && !strings.Contains(n, "{") {
		network, addr = n, a
	}
	switch {
	case strings.HasPrefix(network, "unix"):
		return conf.Backend{Address: dial, Unix: addr}
	case network != "" && network != "tcp" && network != "tcp4" && network != "tcp6":
		return conf.Backend{Address: dial, Note: "unresolved: network " + network}
	case strings.Contains(addr, "{"):
		return conf.Backend{Address: dial, Note: "unresolved: placeholder in " + dial}
	}
	b := p.names.Endpoint(dial, addr, 0, "")
	if len(b.Addrs) == 0 && b.Note == "" {
		b.Note = "unresolved: no port"
	}
	for _, a := range b.Addrs {
		if a.Port() == 0 {
			return conf.Backend{Address: dial, Note: "unresolved: no port"}
		}
	}
	return b
}

// normListen renders a Caddy listen address the way the other parsers do: "*:443" for
// ":443", "unix:/path" for a socket, a port range as written.
func normListen(a string) string {
	network, addr := "", a
	if n, rest, ok := strings.Cut(a, "/"); ok && !strings.Contains(n, ":") {
		network, addr = n, rest
	}
	if strings.HasPrefix(network, "unix") {
		return "unix:" + addr
	}
	prefix := ""
	if network == "udp" || network == "udp4" || network == "udp6" {
		prefix = "udp/"
	}
	if strings.HasPrefix(addr, ":") {
		return prefix + "*" + addr
	}
	return prefix + addr
}

func statusText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "200"
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return strconv.Itoa(n)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return "200"
}
