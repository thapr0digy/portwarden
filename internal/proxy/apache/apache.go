// Package apache reads an Apache httpd configuration (the main file and every Include, as
// httpd expands them) and lists its routes: per virtual host (and the main server) the
// ProxyPass and ProxyPassMatch rules (also inside <Location>), RewriteRule with the P
// flag, SetHandler "proxy:…" (PHP-FPM), balancer members, and the DocumentRoot.
package apache

import (
	"path"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// Options says how the running httpd was started.
type Options struct {
	// ServerRoot is -d (or the compiled HTTPD_ROOT); ConfigFile is -f (or the compiled
	// SERVER_CONFIG_FILE), relative to ServerRoot unless absolute.
	ServerRoot, ConfigFile string
	// Defines are the -D names.
	Defines []string
	// Env is the master process's environment, for ${NAME} (Debian's APACHE_* vars).
	Env map[string]string
}

// Debian/Ubuntu and RHEL compiled defaults.
const (
	DebianRoot   = "/etc/apache2"
	DebianConfig = "apache2.conf"
	RHELRoot     = "/etc/httpd"
	RHELConfig   = "conf/httpd.conf"
)

// MainFile is the absolute path of the main configuration file.
func (o Options) MainFile() string {
	if path.IsAbs(o.ConfigFile) {
		return path.Clean(o.ConfigFile)
	}
	return path.Join(o.ServerRoot, o.ConfigFile)
}

// Load reads the configuration and returns its routes.
func Load(fsys conf.FS, o Options) conf.Result {
	res, _ := load(fsys, o)
	return res
}

// vhost is a <VirtualHost> as `apache2 -S` lists it.
type vhost struct {
	addrs  []string
	names  []string
	source string
}

func load(fsys conf.FS, o Options) (conf.Result, []vhost) {
	r := conf.NewReader()
	l := &loader{
		fsys: fsys, r: r, serverRoot: o.ServerRoot,
		defines: make(map[string]string), env: o.Env, modules: make(map[string]bool),
	}
	for _, d := range o.Defines {
		l.defines[d] = ""
	}
	top := l.file(o.MainFile(), 0)
	p := &parser{names: conf.LoadNames(fsys), balancers: balancers(top)}

	var listens []string
	mainName, docRoot := "", ""
	for _, d := range top {
		switch {
		case d.name == "listen" && len(d.args) > 0:
			listens = append(listens, normListen(d.args[0]))
		case d.name == "servername" && len(d.args) > 0:
			mainName = d.args[0]
		case d.name == "documentroot" && len(d.args) > 0:
			docRoot = d.args[0]
		}
	}
	main := conf.Route{Listen: listens}
	if mainName != "" {
		main.ServerNames = []string{mainName}
	}
	var routes []conf.Route
	for _, rt := range p.routes(top, main, "") {
		rt.Notes = append(rt.Notes, "main server: inherited by every virtual host")
		routes = append(routes, rt)
	}
	var vhosts []vhost
	for _, d := range top {
		if d.name != "virtualhost" || !d.container {
			continue
		}
		v := vhost{source: d.source()}
		for _, a := range d.args {
			v.addrs = append(v.addrs, normVhostAddr(a))
		}
		root := ""
		for _, c := range d.block {
			switch {
			case (c.name == "servername" || c.name == "serveralias") && len(c.args) > 0:
				v.names = append(v.names, c.args...)
			case c.name == "documentroot" && len(c.args) > 0:
				root = c.args[0]
			}
		}
		vhosts = append(vhosts, v)
		base := conf.Route{Listen: v.addrs, ServerNames: v.names}
		vr := p.routes(d.block, base, "")
		if root != "" && !proxiesRoot(vr) {
			st := base
			st.Path, st.Kind, st.Target, st.Root, st.Source = "/", model.RouteStatic, root, root, d.source()
			if d.via != "" {
				st.Notes = append(st.Notes, "from "+d.via)
			}
			vr = append([]conf.Route{st}, vr...)
		}
		routes = append(routes, vr...)
	}
	if len(vhosts) == 0 && docRoot != "" && !proxiesRoot(routes) {
		st := main
		st.Path, st.Kind, st.Target, st.Root = "/", model.RouteStatic, docRoot, docRoot
		routes = append(routes, st)
	}
	return r.Finish(routes), vhosts
}

func proxiesRoot(routes []conf.Route) bool {
	for _, rt := range routes {
		if rt.Path == "/" && rt.Kind != model.RouteStatic {
			return true
		}
	}
	return false
}

// balancers maps balancer://name to its member URLs (inside <Proxy balancer://name> or
// as "BalancerMember balancer://name url").
func balancers(top []*directive) map[string][]string {
	out := make(map[string][]string)
	var walk func(block []*directive, current string)
	walk = func(block []*directive, current string) {
		for _, d := range block {
			if d.container {
				next := current
				if d.name == "proxy" && len(d.args) > 0 && strings.HasPrefix(strings.ToLower(d.args[0]), "balancer://") {
					next = balancerName(d.args[0])
				}
				walk(d.block, next)
				continue
			}
			if d.name != "balancermember" || len(d.args) == 0 {
				continue
			}
			name, url := current, d.args[0]
			if strings.HasPrefix(strings.ToLower(d.args[0]), "balancer://") && len(d.args) > 1 {
				name, url = balancerName(d.args[0]), d.args[1]
			}
			if name != "" {
				out[name] = append(out[name], url)
			}
		}
	}
	walk(top, "")
	return out
}

func balancerName(u string) string {
	rest := u[len("balancer://"):]
	name, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(name)
}

type parser struct {
	names     *conf.Names
	balancers map[string][]string
}

// routes lists the proxy rules of a block (not descending into virtual hosts); where is
// the enclosing <Location>/<Files…> path, "" at server level.
func (p *parser) routes(block []*directive, base conf.Route, where string) []conf.Route {
	var out []conf.Route
	// add resolves the substituted target but publishes the raw one (args[i]).
	add := func(d *directive, path string, i int, trim string) {
		target := strings.TrimPrefix(d.args[i], trim)
		rt := base
		rt.Path, rt.Target, rt.Source = path, target, d.source()
		if i < len(d.raw) {
			rt.Target = strings.TrimPrefix(d.raw[i], trim)
		}
		p.resolve(&rt, target)
		if d.via != "" {
			rt.Notes = append(rt.Notes, "from "+d.via)
		}
		out = append(out, rt)
	}
	for _, d := range block {
		if d.container {
			arg := strings.Join(d.args, " ")
			switch d.name {
			case "location":
				out = append(out, p.routes(d.block, base, arg)...)
			case "locationmatch":
				out = append(out, p.routes(d.block, base, "~ "+arg)...)
			case "files", "filesmatch", "directory", "directorymatch":
				out = append(out, p.routes(d.block, base, sectionNames[d.name]+" "+arg)...)
			case "if", "elseif", "else":
				for _, rt := range p.routes(d.block, base, where) {
					rt.Notes = append(rt.Notes, "conditional: <"+d.name+" "+arg+">")
					out = append(out, rt)
				}
			}
			continue
		}
		switch d.name {
		case "proxypass", "proxypassmatch":
			pth, ti := where, 0
			switch {
			case where != "" && len(d.args) >= 1:
			case len(d.args) >= 2:
				pth, ti = d.args[0], 1
			default:
				continue
			}
			target := d.args[ti]
			if target == "!" || pth == "!" {
				continue
			}
			if d.name == "proxypassmatch" && where == "" {
				pth = "~ " + pth
			}
			add(d, pth, ti, "")
		case "rewriterule":
			if len(d.args) >= 3 && proxyFlag(d.args[2]) {
				pth := "~ " + d.args[0]
				if where != "" {
					pth = where + " " + pth
				}
				add(d, pth, 1, "")
			}
		case "sethandler":
			if len(d.args) == 1 && strings.HasPrefix(strings.ToLower(d.args[0]), "proxy:") {
				add(d, where, 0, d.args[0][:len("proxy:")])
			}
		}
	}
	return out
}

var sectionNames = map[string]string{
	"files": "Files", "filesmatch": "FilesMatch", "directory": "Directory", "directorymatch": "DirectoryMatch",
}

func proxyFlag(flags string) bool {
	for _, f := range strings.Split(strings.Trim(flags, "[]"), ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "p" || f == "proxy" {
			return true
		}
	}
	return false
}

// schemePorts are mod_proxy's default ports (ap_proxy_port_of_scheme).
var schemePorts = map[string]uint16{
	"http": 80, "ws": 80, "h2c": 80, "https": 443, "wss": 443, "h2": 443,
	"ajp": 8009, "fcgi": 8000, "scgi": 4000, "uwsgi": 3031, "ftp": 21,
}

func kindOf(scheme string) string {
	switch scheme {
	case "fcgi":
		return model.RouteFastCGI
	case "scgi":
		return model.RouteSCGI
	case "uwsgi":
		return model.RouteUWSGI
	}
	return model.RouteProxy
}

// resolve fills rt's kind and backends from a mod_proxy URL: "scheme://host[:port]/…",
// "unix:/path|scheme://…" or "balancer://name/…".
func (p *parser) resolve(rt *conf.Route, target string) {
	rt.Kind = model.RouteProxy
	backends, kind, upstream, note := p.endpoints(target, 0)
	if kind != "" {
		rt.Kind = kind
	}
	rt.Upstream = upstream
	rt.Backends = backends
	if note != "" {
		rt.Notes = append(rt.Notes, note)
	}
}

func (p *parser) endpoints(target string, depth int) (bs []conf.Backend, kind, upstream, note string) {
	if u, ok := strings.CutPrefix(target, "unix:"); ok {
		sock, after, _ := strings.Cut(u, "|")
		scheme, _, _ := strings.Cut(after, "://")
		return []conf.Backend{{Address: "unix:" + sock, Unix: sock}}, kindOf(strings.ToLower(scheme)), "", ""
	}
	scheme, rest, ok := strings.Cut(target, "://")
	if !ok {
		n := "unresolved: not a URL " + target
		return []conf.Backend{{Address: target, Note: n}}, "", "", n
	}
	scheme = strings.ToLower(scheme)
	hostPort, _, _ := strings.Cut(rest, "/")
	hostPort, _, _ = strings.Cut(hostPort, "?")
	if at := strings.LastIndexByte(hostPort, '@'); at >= 0 {
		hostPort = hostPort[at+1:] // userinfo is not part of the destination
	}
	if scheme == "balancer" {
		name := strings.ToLower(hostPort)
		members, found := p.balancers[name]
		if !found || depth > 0 {
			n := "unresolved: balancer://" + hostPort + " has no members"
			return []conf.Backend{{Address: target, Note: n}}, "", name, n
		}
		for _, m := range members {
			mb, mk, _, _ := p.endpoints(m, depth+1)
			bs = append(bs, mb...)
			if kind == "" {
				kind = mk
			}
		}
		return bs, kind, name, ""
	}
	if strings.ContainsAny(hostPort, "$%") {
		n := "unresolved: variable in " + hostPort
		return []conf.Backend{{Address: hostPort, Note: n}}, kindOf(scheme), "", n
	}
	def := schemePorts[scheme]
	if def == 0 {
		def = 80
	}
	return []conf.Backend{p.names.Endpoint(hostPort, hostPort, def, "")}, kindOf(scheme), "", ""
}

// normListen renders "Listen [addr:]port [proto]" as "addr:port" ("*:80" for a port).
func normListen(a string) string {
	if _, err := strconv.ParseUint(a, 10, 16); err == nil {
		return "*:" + a
	}
	return a
}

// normVhostAddr renders a <VirtualHost> address: "_default_" is "*", and a missing port
// is "*" (every port).
func normVhostAddr(a string) string {
	host, port := a, "*"
	if strings.HasPrefix(a, "[") {
		if end := strings.Index(a, "]"); end >= 0 {
			host = a[:end+1]
			if p, ok := strings.CutPrefix(a[end+1:], ":"); ok {
				port = p
			}
		}
	} else if h, p, ok := strings.Cut(a, ":"); ok && !strings.Contains(p, ":") {
		host, port = h, p
	}
	if host == "_default_" {
		host = "*"
	}
	return host + ":" + port
}
