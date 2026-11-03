package apache

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// directive is one parsed directive; a container (<VirtualHost …>) has a block.
type directive struct {
	name string // lower case, without "<" for a container
	args []string
	// raw are the arguments before ${VAR} substitution: what is published, so an
	// environment value (a password) never is.
	raw       []string
	file      string
	line      int
	container bool
	block     []*directive
}

func (d *directive) source() string { return fmt.Sprintf("%s:%d", d.file, d.line) }

// staticModules are compiled into Debian/Ubuntu's apache2 (`apache2 -l`); <IfModule>
// on them is always true.
var staticModules = []string{"core.c", "mod_so.c", "mod_watchdog.c", "http_core.c",
	"mod_log_config.c", "mod_logio.c", "mod_version.c", "mod_unixd.c"}

// loader reads Apache's configuration as the server does while it starts: one directive
// per line (a trailing backslash continues it), "#" only at the start of a line,
// ${NAME} replaced from Define and the environment, Include/IncludeOptional spliced in
// place (relative to ServerRoot, wildcards with fnmatch semantics, a directory read
// recursively in sorted order), <IfModule> decided from the LoadModule lines seen so far
// and the static modules, <IfDefine> from -D and Define. Sections whose condition is
// false are skipped unread, as Apache skips them.
type loader struct {
	fsys       conf.FS
	r          *conf.Reader
	serverRoot string
	defines    map[string]string
	env        map[string]string
	modules    map[string]bool
}

type line struct {
	text string
	num  int
}

func (l *loader) file(p string, depth int) []*directive {
	if depth > conf.MaxDepth {
		l.r.Note("include depth over %d at %s", conf.MaxDepth, p)
		return nil
	}
	data, ok, leave := l.r.Enter(l.fsys, p)
	defer leave()
	if !ok {
		return nil
	}
	lines := splitLines(string(data))
	pos := 0
	return l.block(p, lines, &pos, depth, "")
}

// splitLines joins continuation lines and drops blank and comment lines.
func splitLines(src string) []line {
	var out []line
	raw := strings.Split(src, "\n")
	for i := 0; i < len(raw); i++ {
		num := i + 1
		text := strings.TrimRight(raw[i], " \t\r")
		for strings.HasSuffix(text, "\\") && i+1 < len(raw) {
			i++
			text = strings.TrimSuffix(text, "\\") + " " + strings.TrimSpace(strings.TrimRight(raw[i], "\r"))
		}
		text = strings.TrimSpace(text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		out = append(out, line{text, num})
	}
	return out
}

// block parses lines until the end tag of the container named end ("" for a file).
func (l *loader) block(file string, lines []line, pos *int, depth int, end string) []*directive {
	var out []*directive
	for *pos < len(lines) {
		ln := lines[*pos]
		*pos++
		if strings.HasPrefix(ln.text, "</") {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(ln.text, "</"), ">"))
			if end == "" {
				l.r.Note("unexpected </%s> at %s:%d", name, file, ln.num)
				continue
			}
			if name != end {
				l.r.Note("expected </%s> but saw </%s> at %s:%d", end, name, file, ln.num)
			}
			return out
		}
		words := l.words(ln.text)
		if len(words) == 0 {
			continue
		}
		if strings.HasPrefix(words[0], "<") {
			name := strings.ToLower(strings.TrimPrefix(words[0], "<"))
			args := words[1:]
			if n := len(args); n > 0 {
				args[n-1] = strings.TrimSuffix(args[n-1], ">")
				if args[n-1] == "" {
					args = args[:n-1]
				}
			} else {
				name = strings.TrimSuffix(name, ">")
			}
			switch name {
			case "ifmodule", "ifdefine", "ifdirective", "ifsection", "iffile":
				if l.condition(name, args) {
					out = append(out, l.block(file, lines, pos, depth, name)...)
				} else {
					skip(lines, pos)
				}
				continue
			case "macro":
				l.r.Note("<Macro> at %s:%d not expanded", file, ln.num)
				skip(lines, pos)
				continue
			}
			d := &directive{name: name, args: args, file: file, line: ln.num, container: true}
			d.block = l.block(file, lines, pos, depth, name)
			out = append(out, d)
			continue
		}
		d := &directive{name: strings.ToLower(words[0]), args: words[1:], file: file, line: ln.num}
		if raw := l.split(ln.text); len(raw) == len(words) {
			d.raw = raw[1:]
		}
		switch d.name {
		case "include", "includeoptional":
			if len(d.args) == 1 {
				out = append(out, l.include(d, depth)...)
			}
			continue
		case "define":
			if len(d.args) >= 1 {
				v := ""
				if len(d.args) > 1 {
					v = d.args[1]
				}
				l.defines[d.args[0]] = v
			}
		case "undefine":
			if len(d.args) == 1 {
				delete(l.defines, d.args[0])
			}
		case "serverroot":
			if len(d.args) == 1 {
				l.serverRoot = d.args[0]
			}
		case "loadmodule":
			if len(d.args) == 2 {
				l.modules[d.args[0]] = true
				base := path.Base(d.args[1])
				l.modules[strings.TrimSuffix(base, path.Ext(base))+".c"] = true
			}
		}
		out = append(out, d)
	}
	if end != "" {
		l.r.Note("missing </%s> in %s", end, file)
	}
	return out
}

// skip moves pos past the end tag of the section just opened, counting nested sections.
func skip(lines []line, pos *int) {
	depth := 1
	for *pos < len(lines) && depth > 0 {
		t := lines[*pos].text
		*pos++
		switch {
		case strings.HasPrefix(t, "</"):
			depth--
		case strings.HasPrefix(t, "<"):
			depth++
		}
	}
}

func (l *loader) condition(name string, args []string) bool {
	if len(args) == 0 {
		return false
	}
	arg, negate := strings.CutPrefix(args[0], "!")
	var v bool
	switch name {
	case "ifmodule":
		v = l.modules[arg]
		for _, m := range staticModules {
			v = v || m == arg
		}
	case "ifdefine":
		_, v = l.defines[arg]
	default: // IfDirective, IfSection, IfFile: not modelled; read the contents
		return true
	}
	return v != negate
}

func (l *loader) include(d *directive, depth int) []*directive {
	p := d.args[0]
	if !path.IsAbs(p) {
		p = path.Join(l.serverRoot, p)
	}
	optional := d.name == "includeoptional"
	var files []string
	if conf.HasMeta(p) {
		files = conf.Glob(l.fsys, l.r, p)
		if len(files) == 0 && !optional {
			l.r.Note("Include %s matches no file", p)
		}
	} else {
		p = path.Clean(p)
		in, err := l.fsys.Stat(p)
		switch {
		case err != nil && optional:
			l.r.Watch(p)
			return nil
		case err == nil && in.Dir:
			l.r.Watch(p)
			files = l.dirFiles(p)
		default:
			files = []string{p}
		}
	}
	var out []*directive
	for _, f := range files {
		if !l.r.Op() {
			break
		}
		if in, err := l.fsys.Stat(f); err == nil && in.Dir {
			for _, g := range l.dirFiles(f) {
				out = append(out, l.file(g, depth+1)...)
			}
			continue
		}
		out = append(out, l.file(f, depth+1)...)
	}
	return out
}

// dirFiles lists every file under dir (recursively), sorted per directory, as Apache
// reads an Include of a directory.
func (l *loader) dirFiles(dir string) []string {
	l.r.Watch(dir)
	names, err := l.fsys.ReadDir(dir)
	if err != nil {
		l.r.Note("unreadable %s", conf.ErrText(err))
		return nil
	}
	var out []string
	for _, n := range names {
		if !l.r.Op() {
			break
		}
		p := path.Join(dir, n)
		if in, err := l.fsys.Stat(p); err == nil && in.Dir {
			out = append(out, l.dirFiles(p)...)
			continue
		}
		out = append(out, p)
	}
	return out
}

var varRef = regexp.MustCompile(`\$\{([A-Za-z0-9_:.-]+)\}`)

// words splits a line into arguments as ap_getword_conf does (double or single quotes,
// a backslash escaping a quote inside them) after substituting ${NAME}.
func (l *loader) words(text string) []string {
	return l.split(l.substitute(text))
}

func (l *loader) substitute(text string) string {
	return varRef.ReplaceAllStringFunc(text, func(ref string) string {
		name := ref[2 : len(ref)-1]
		if v, ok := l.defines[name]; ok {
			return v
		}
		if v, ok := l.env[name]; ok {
			return v
		}
		return ref
	})
}

// split breaks a line into words (no substitution).
func (l *loader) split(text string) []string {
	var out []string
	i := 0
	for i < len(text) {
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i >= len(text) {
			break
		}
		var b strings.Builder
		if q := text[i]; q == '"' || q == '\'' {
			i++
			for i < len(text) && text[i] != q {
				if text[i] == '\\' && i+1 < len(text) && (text[i+1] == q || text[i+1] == '\\') {
					i++
				}
				b.WriteByte(text[i])
				i++
			}
			i++
		} else {
			for i < len(text) && text[i] != ' ' && text[i] != '\t' {
				b.WriteByte(text[i])
				i++
			}
		}
		out = append(out, b.String())
	}
	return out
}
