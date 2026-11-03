// Package nginx reads an nginx configuration (the main file and every include, as
// nginx itself expands them) and lists its routes: each server's listen addresses and
// names, each location, and where it sends requests (proxy_pass, fastcgi_pass,
// uwsgi_pass, scgi_pass, grpc_pass, memcached_pass, an upstream's servers, a static
// root or a return), plus stream servers. Targets built from variables are expanded
// when every variable comes from a map or a set; otherwise they stay unresolved.
package nginx

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// DefaultConfPath is nginx's usual --conf-path (Debian, Ubuntu, RHEL, upstream packages).
const DefaultConfPath = "/etc/nginx/nginx.conf"

// Load reads main and its includes through fsys and returns the routes. Names resolve
// against fsys's /etc/hosts only.
func Load(fsys conf.FS, main string) conf.Result {
	r := conf.NewReader()
	l := &loader{fsys: fsys, r: r, prefix: path.Dir(main)}
	top := l.file(main, 0)
	p := &parser{names: conf.LoadNames(fsys), r: r}
	var routes []conf.Route
	for _, d := range top {
		switch {
		case d.name == "http" && d.block != nil:
			routes = append(routes, p.http(d.block)...)
		case d.name == "stream" && d.block != nil:
			routes = append(routes, p.stream(d.block)...)
		}
	}
	return r.Finish(routes)
}

type upstreamServer struct {
	addr string
	note string
}

type parser struct {
	names *conf.Names
	r     *conf.Reader
}

// scope is what a block's routes resolve against.
type scope struct {
	upstreams map[string][]upstreamServer
	vars      map[string][]string
}

func (p *parser) collect(block []*directive) scope {
	s := scope{upstreams: make(map[string][]upstreamServer), vars: make(map[string][]string)}
	for _, d := range block {
		switch {
		case d.name == "upstream" && len(d.args) == 1 && d.block != nil:
			var servers []upstreamServer
			for _, sd := range d.block {
				if sd.name != "server" || len(sd.args) == 0 {
					continue
				}
				var flags []string
				for _, a := range sd.args[1:] {
					if a == "backup" || a == "down" {
						flags = append(flags, a)
					}
				}
				servers = append(servers, upstreamServer{addr: sd.args[0], note: strings.Join(flags, " ")})
			}
			s.upstreams[d.args[0]] = servers
		case d.name == "map" && len(d.args) == 2 && d.block != nil:
			var values []string
			for _, e := range d.block {
				if len(e.args) == 1 && !slices.Contains(values, e.args[0]) {
					values = append(values, e.args[0])
				}
			}
			s.vars[strings.TrimPrefix(d.args[1], "$")] = values
		}
	}
	return s
}

func (p *parser) http(block []*directive) []conf.Route {
	s := p.collect(block)
	root := lastArg(block, "root")
	var out []conf.Route
	for _, d := range block {
		if d.name == "server" && d.block != nil {
			out = append(out, p.server(d, s, root)...)
		}
	}
	return out
}

func (p *parser) stream(block []*directive) []conf.Route {
	s := p.collect(block)
	var out []conf.Route
	for _, d := range block {
		if d.name != "server" || d.block == nil {
			continue
		}
		listen := listens(d.block)
		for _, h := range d.block {
			if h.name != "proxy_pass" || len(h.args) != 1 {
				continue
			}
			rt := conf.Route{Listen: listen, Kind: model.RouteProxy, Target: h.args[0], Source: h.source()}
			p.resolve(&rt, h.args[0], "", s)
			out = append(out, rt)
		}
	}
	return out
}

func (p *parser) server(d *directive, outer scope, root string) []conf.Route {
	s := scope{upstreams: outer.upstreams, vars: make(map[string][]string)}
	for k, v := range outer.vars {
		s.vars[k] = v
	}
	// set $x value; anywhere in the server gives $x a possible value.
	walk(d.block, func(sd *directive) {
		if sd.name == "set" && len(sd.args) == 2 {
			name := strings.TrimPrefix(sd.args[0], "$")
			if !slices.Contains(s.vars[name], sd.args[1]) {
				s.vars[name] = append(s.vars[name], sd.args[1])
			}
		}
	})
	if r := lastArg(d.block, "root"); r != "" {
		root = r
	}
	if root == "" {
		root = "html"
	}
	base := conf.Route{Listen: listens(d.block), ServerNames: serverNames(d.block)}
	var out []conf.Route
	hasLocation := false
	for _, c := range d.block {
		switch {
		case c.name == "return" && len(c.args) > 0:
			rt := base
			rt.Kind, rt.Target, rt.Source = model.RouteReturn, returnCode(c.args), c.source()
			out = append(out, rt)
		case c.name == "location" && c.block != nil:
			hasLocation = true
			out = append(out, p.location(c, base, s, root)...)
		}
	}
	if !hasLocation && len(out) == 0 {
		rt := base
		rt.Path, rt.Kind, rt.Target, rt.Root, rt.Source = "/", model.RouteStatic, root, root, d.source()
		out = append(out, rt)
	}
	return out
}

var handlers = map[string]string{
	"proxy_pass":     model.RouteProxy,
	"fastcgi_pass":   model.RouteFastCGI,
	"uwsgi_pass":     model.RouteUWSGI,
	"scgi_pass":      model.RouteSCGI,
	"grpc_pass":      model.RouteGRPC,
	"memcached_pass": model.RouteMemcached,
}

func (p *parser) location(d *directive, base conf.Route, s scope, root string) []conf.Route {
	base.Path = strings.Join(d.args, " ")
	if r := lastArg(d.block, "root"); r != "" {
		root = r
	}
	staticRoot := root
	if a := lastArg(d.block, "alias"); a != "" {
		staticRoot = a
	}
	var out []conf.Route
	handled := false
	add := func(h *directive, cond string) {
		kind, ok := handlers[h.name]
		if !ok || len(h.args) != 1 {
			return
		}
		handled = true
		rt := base
		rt.Kind, rt.Target, rt.Source = kind, h.args[0], h.source()
		if cond != "" {
			rt.Notes = append(rt.Notes, "conditional: "+cond)
		}
		p.resolve(&rt, h.args[0], kind, s)
		out = append(out, rt)
	}
	var ret *directive
	for _, c := range d.block {
		switch {
		case c.name == "if" || c.name == "limit_except":
			cond := c.name + " " + strings.Join(c.args, " ")
			for _, h := range c.block {
				add(h, cond)
			}
		case c.name == "return" && len(c.args) > 0:
			ret = c
		default:
			add(c, "")
		}
	}
	if !handled {
		rt := base
		if ret != nil {
			rt.Kind, rt.Target, rt.Source = model.RouteReturn, returnCode(ret.args), ret.source()
		} else {
			rt.Kind, rt.Target, rt.Root, rt.Source = model.RouteStatic, staticRoot, staticRoot, d.source()
		}
		out = append([]conf.Route{rt}, out...)
	}
	for _, c := range d.block {
		if c.name == "location" && c.block != nil {
			out = append(out, p.location(c, base, s, root)...)
		}
	}
	return out
}

var varRef = regexp.MustCompile(`\$(\{[A-Za-z0-9_]+\}|[A-Za-z0-9_]+)`)

// expand substitutes every variable in s with each of its known values; unresolved
// names the first variable without known values.
func expand(s string, vars map[string][]string) (out []string, unresolved string) {
	out = []string{s}
	for {
		loc := varRef.FindStringIndex(out[0])
		if loc == nil {
			return out, ""
		}
		ref := out[0][loc[0]:loc[1]]
		name := strings.Trim(ref[1:], "{}")
		values, ok := vars[name]
		if !ok || len(values) == 0 {
			return nil, "$" + name
		}
		var next []string
		for _, o := range out {
			for _, v := range values {
				if strings.Contains(v, "$") {
					return nil, "$" + name
				}
				if len(next) >= conf.MaxExpansions {
					return nil, "$" + name + " (too many values)"
				}
				next = append(next, strings.Replace(o, ref, v, 1))
			}
		}
		out = next
	}
}

// resolve fills rt's backends from target. kind "" is a stream proxy_pass (no scheme).
func (p *parser) resolve(rt *conf.Route, target, kind string, s scope) {
	schemes, hostPort, unix := splitTarget(target, kind)
	if unix != "" {
		rt.Backends = append(rt.Backends, conf.Backend{Address: "unix:" + unix, Unix: unix})
		return
	}
	// Only the host[:port] has to resolve; variables in the URI do not matter.
	hosts, unresolved := expand(hostPort, s.vars)
	if unresolved != "" {
		note := "unresolved: variable " + unresolved
		rt.Notes = append(rt.Notes, note)
		rt.Backends = append(rt.Backends, conf.Backend{Address: hostPort, Note: note})
		return
	}
	var ups []string
	for _, hp := range hosts {
		if u, ok := strings.CutPrefix(hp, "unix:"); ok {
			rt.Backends = append(rt.Backends, conf.Backend{Address: hp, Unix: u})
			continue
		}
		if servers, ok := s.upstreams[hp]; ok {
			if !slices.Contains(ups, hp) {
				ups = append(ups, hp)
			}
			for _, sv := range servers {
				if u, ok := strings.CutPrefix(sv.addr, "unix:"); ok {
					rt.Backends = append(rt.Backends, conf.Backend{Address: sv.addr, Unix: u, Note: sv.note})
					continue
				}
				rt.Backends = append(rt.Backends, p.names.Endpoint(sv.addr, sv.addr, 80, sv.note))
			}
			continue
		}
		b := p.names.Endpoint(hp, hp, defaultPort(schemes[0]), "")
		for _, sc := range schemes[1:] { // $scheme: either default port may be the one
			if extra := p.names.Endpoint(hp, hp, defaultPort(sc), ""); len(extra.Addrs) > 0 {
				for _, a := range extra.Addrs {
					if !slices.Contains(b.Addrs, a) {
						b.Addrs = append(b.Addrs, a)
					}
				}
			}
		}
		rt.Backends = append(rt.Backends, b)
	}
	rt.Upstream = strings.Join(ups, ",")
}

// returnCode keeps only a return's status code: its text or URL may carry secrets.
func returnCode(args []string) string {
	if len(args) > 0 && isDigits(args[0]) {
		return args[0]
	}
	return "302" // "return URL;" is a temporary redirect
}

func defaultPort(scheme string) uint16 {
	switch scheme {
	case "https", "grpcs", "suwsgi":
		return 443
	}
	return 80
}

// uriVars are variables that only ever form the URI part of a target.
var uriVars = regexp.MustCompile(`^\$\{?(request_uri|uri|document_uri|is_args|args|query_string|request|arg_[A-Za-z0-9_]+|[0-9]+)\b`)

// splitTarget splits a *_pass argument into its possible schemes ($scheme is http or
// https), the host[:port] (or upstream name), with userinfo dropped and the URI cut off
// at the first "/", "?" or URI variable, or a Unix socket path.
func splitTarget(t, kind string) (schemes []string, hostPort, unix string) {
	scheme, rest, hasScheme := strings.Cut(t, "://")
	switch {
	case !hasScheme:
		rest, schemes = t, []string{"http"}
	case scheme == "$scheme" || scheme == "${scheme}":
		schemes = []string{"http", "https"}
	default:
		schemes = []string{scheme}
	}
	if u, ok := strings.CutPrefix(rest, "unix:"); ok {
		// proxy_pass http://unix:/path:/uri — the socket path ends at the next colon.
		if kind == model.RouteProxy && hasScheme {
			u, _, _ = strings.Cut(u, ":")
		}
		return schemes, "", u
	}
	if hasScheme {
		end := len(rest)
		for i := 0; i < len(rest); i++ {
			if rest[i] == '/' || rest[i] == '?' || (rest[i] == '$' && i > 0 && uriVars.MatchString(rest[i:])) {
				end = i
				break
			}
		}
		rest = rest[:end]
		if at := strings.LastIndexByte(rest, '@'); at >= 0 {
			rest = rest[at+1:]
		}
	}
	return schemes, rest, ""
}

func listens(block []*directive) []string {
	var out []string
	for _, d := range block {
		if d.name == "listen" && len(d.args) > 0 {
			out = append(out, normListen(d.args))
		}
	}
	if len(out) == 0 {
		out = []string{"*:80"}
	}
	return out
}

// normListen renders a listen directive as "addr:port" ("*:80", "[::]:443",
// "127.0.0.1:8080", "unix:/path"), with "/udp" for a UDP (or QUIC) listener.
func normListen(args []string) string {
	a := args[0]
	if strings.HasPrefix(a, "unix:") {
		return a
	}
	suffix := ""
	for _, f := range args[1:] {
		if f == "udp" || f == "quic" {
			suffix = "/udp"
		}
	}
	if isDigits(a) {
		return "*:" + a + suffix
	}
	host, port, ok := conf.SplitHostPort(a, 80)
	if !ok {
		return a + suffix
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(port)) + suffix
}

func serverNames(block []*directive) []string {
	var out []string
	for _, d := range block {
		if d.name == "server_name" {
			out = append(out, d.args...)
		}
	}
	return out
}

func lastArg(block []*directive, name string) string {
	v := ""
	for _, d := range block {
		if d.name == name && len(d.args) > 0 {
			v = d.args[0]
		}
	}
	return v
}

func walk(block []*directive, f func(*directive)) {
	for _, d := range block {
		f(d)
		walk(d.block, f)
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
