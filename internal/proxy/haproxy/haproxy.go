// Package haproxy reads an HAProxy configuration (each -f file, or every *.cfg in a -f
// directory, in order) and lists its routes: for each frontend and listen section, its
// bind addresses and the backends its use_backend rules and default_backend name, with
// their servers. The runtime API is not used.
package haproxy

import (
	"path"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// DefaultConfig is the packaged configuration file.
const DefaultConfig = "/etc/haproxy/haproxy.cfg"

// sectionKeywords start a section.
var sectionKeywords = map[string]bool{
	"global": true, "defaults": true, "frontend": true, "backend": true, "listen": true,
	"resolvers": true, "peers": true, "userlist": true, "mailers": true, "program": true,
	"http-errors": true, "ring": true, "cache": true, "log-forward": true, "fcgi-app": true,
	"crt-store": true, "traces": true,
}

type line struct {
	words []string
	num   int
	file  string
}

type section struct {
	kind, name string
	head       line
	lines      []line
}

// Load reads the -f paths (files, or directories whose *.cfg files are read in lexical
// order) and returns the routes.
func Load(fsys conf.FS, paths []string) conf.Result {
	r := conf.NewReader()
	var sections []*section
	for _, p := range paths {
		files := []string{p}
		if in, err := fsys.Stat(p); err == nil && in.Dir {
			files = conf.Glob(fsys, r, path.Join(p, "*.cfg"))
		}
		for _, f := range files {
			data, ok := r.Read(fsys, f)
			if !ok {
				continue
			}
			sections = appendSections(sections, f, string(data))
		}
	}
	return r.Finish(routes(sections, conf.LoadNames(fsys)))
}

func appendSections(sections []*section, file, src string) []*section {
	var cur *section
	for i, raw := range strings.Split(src, "\n") {
		words := split(raw)
		if len(words) == 0 {
			continue
		}
		ln := line{words: words, num: i + 1, file: file}
		if sectionKeywords[words[0]] {
			cur = &section{kind: words[0], head: ln}
			if len(words) > 1 {
				cur.name = words[1]
			}
			sections = append(sections, cur)
			continue
		}
		if cur != nil {
			cur.lines = append(cur.lines, ln)
		}
	}
	return sections
}

// split breaks a line into words as HAProxy does: whitespace separates them, '#' starts a
// comment, double and single quotes group, a backslash escapes the next character.
func split(s string) []string {
	var out []string
	var b strings.Builder
	in := false
	quote := byte(0)
	flush := func() {
		if in {
			out = append(out, b.String())
			b.Reset()
			in = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else {
				b.WriteByte(c)
			}
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
			in = true
		case c == '"' || c == '\'':
			quote = c
			in = true
		case c == '#':
			flush()
			return out
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		default:
			b.WriteByte(c)
			in = true
		}
	}
	flush()
	return out
}

type server struct {
	src   line
	addr  string
	flags string
	tmpl  bool
}

func routes(sections []*section, names *conf.Names) []conf.Route {
	backends := make(map[string][]server)
	for _, s := range sections {
		if s.kind == "backend" || s.kind == "listen" {
			backends[s.name] = servers(s)
		}
	}
	var out []conf.Route
	defaultBackend := ""
	for _, s := range sections {
		switch s.kind {
		case "defaults":
			defaultBackend = ""
			for _, l := range s.lines {
				if l.words[0] == "default_backend" && len(l.words) > 1 {
					defaultBackend = l.words[1]
				}
			}
		case "frontend", "listen":
			out = append(out, frontendRoutes(s, defaultBackend, backends, names)...)
		}
	}
	return out
}

func frontendRoutes(s *section, inherited string, backends map[string][]server, names *conf.Names) []conf.Route {
	var binds []string
	acls := make(map[string][]string)
	def := inherited
	for _, l := range s.lines {
		w := l.words
		switch {
		case w[0] == "bind" && len(w) > 1:
			for _, a := range strings.Split(w[1], ",") {
				binds = append(binds, normBind(a))
			}
		case w[0] == "acl" && len(w) > 2:
			acls[w[1]] = append(acls[w[1]], strings.Join(w[2:], " "))
		case w[0] == "default_backend" && len(w) > 1:
			def = w[1]
		}
	}
	base := conf.Route{Listen: binds, Kind: model.RouteProxy}
	var out []conf.Route
	for _, l := range s.lines {
		w := l.words
		if w[0] != "use_backend" || len(w) < 2 {
			continue
		}
		rt := base
		rt.Target, rt.Source = w[1], source(l)
		rt.Path = strings.Join(w[2:], " ")
		for _, name := range condACLs(w[2:]) {
			for _, def := range acls[name] {
				rt.Notes = append(rt.Notes, "acl "+name+" "+def)
			}
		}
		fill(&rt, w[1], backends, names)
		out = append(out, rt)
	}
	switch {
	case def != "":
		rt := base
		rt.Path, rt.Target, rt.Source = "default", def, source(s.head)
		fill(&rt, def, backends, names)
		if s.kind == "listen" && len(backends[s.name]) > 0 {
			rt.Notes = append(rt.Notes, "default_backend takes precedence over this section's servers")
		}
		out = append(out, rt)
	case s.kind == "listen" && len(backends[s.name]) > 0:
		rt := base
		rt.Path, rt.Target, rt.Source = "default", s.name, source(s.head)
		fill(&rt, s.name, backends, names)
		out = append(out, rt)
	}
	return out
}

// condACLs lists the ACL names an "if/unless" condition refers to.
func condACLs(cond []string) []string {
	var out []string
	for _, w := range cond {
		w = strings.TrimPrefix(w, "!")
		if w == "if" || w == "unless" || w == "or" || w == "||" || w == "{" || w == "}" || w == "" {
			continue
		}
		out = append(out, w)
	}
	return out
}

func fill(rt *conf.Route, name string, backends map[string][]server, names *conf.Names) {
	if strings.Contains(name, "%[") {
		note := "unresolved: dynamic backend " + name
		rt.Notes = append(rt.Notes, note)
		rt.Backends = []conf.Backend{{Address: name, Note: note}}
		return
	}
	rt.Upstream = name
	srvs, ok := backends[name]
	if !ok {
		note := "unresolved: no backend " + name
		rt.Notes = append(rt.Notes, note)
		rt.Backends = []conf.Backend{{Address: name, Note: note}}
		return
	}
	for _, sv := range srvs {
		rt.Backends = append(rt.Backends, endpoint(sv, names))
	}
}

func servers(s *section) []server {
	var out []server
	for _, l := range s.lines {
		w := l.words
		switch {
		case w[0] == "server" && len(w) > 2:
			out = append(out, server{src: l, addr: w[2], flags: flags(w[3:])})
		case w[0] == "server-template" && len(w) > 3:
			out = append(out, server{src: l, addr: w[3], flags: flags(w[4:]), tmpl: true})
		}
	}
	return out
}

func flags(params []string) string {
	var out []string
	for _, p := range params {
		if p == "backup" || p == "disabled" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

// endpoint resolves a server address: [ipv4@|ipv6@]host[:port], unix@/path or /path.
func endpoint(sv server, names *conf.Names) conf.Backend {
	a := sv.addr
	if u, ok := strings.CutPrefix(a, "unix@"); ok {
		return conf.Backend{Address: a, Unix: u, Note: sv.flags}
	}
	if strings.HasPrefix(a, "/") {
		return conf.Backend{Address: a, Unix: a, Note: sv.flags}
	}
	if strings.HasPrefix(a, "abns@") || strings.HasPrefix(a, "fd@") || strings.HasPrefix(a, "sockpair@") {
		return conf.Backend{Address: a, Note: joinNote(sv.flags, "unresolved: "+a)}
	}
	hostPort := a
	for _, p := range []string{"ipv4@", "ipv6@", "tcp@", "tcp4@", "tcp6@"} {
		hostPort = strings.TrimPrefix(hostPort, p)
	}
	host, port, ok := splitServer(hostPort)
	if !ok {
		return conf.Backend{Address: a, Note: joinNote(sv.flags, "unresolved: bad address "+a)}
	}
	if port == "" {
		return conf.Backend{Address: a, Note: joinNote(sv.flags, "unresolved: no port (the client's destination port is used)")}
	}
	b := names.Endpoint(a, joinHostPort(host, port), 0, sv.flags)
	if sv.tmpl {
		b.Note = joinNote(b.Note, "server-template")
	}
	return b
}

// splitServer splits "host:port", "[v6]:port", a bare IPv6 "::1:9000" (last colon is the
// port, as HAProxy reads it) or "host".
func splitServer(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", false
		}
		return s[1:end], strings.TrimPrefix(s[end+1:], ":"), true
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", true
	}
	return s[:i], s[i+1:], true
}

func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// normBind renders a bind address: "*:80" for ":80", "[::]:8443" for ":::8443",
// "unix:/path" for a socket.
func normBind(a string) string {
	if u, ok := strings.CutPrefix(a, "unix@"); ok {
		return "unix:" + u
	}
	if strings.HasPrefix(a, "/") {
		return "unix:" + a
	}
	for _, p := range []string{"ipv4@", "ipv6@", "tcp@", "tcp4@", "tcp6@"} {
		a = strings.TrimPrefix(a, p)
	}
	host, port, ok := splitServer(a)
	if !ok || port == "" {
		return a
	}
	switch host {
	case "", "*":
		host = "*"
	default:
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return host + ":" + port
}

func source(l line) string { return l.file + ":" + strconv.Itoa(l.num) }

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
