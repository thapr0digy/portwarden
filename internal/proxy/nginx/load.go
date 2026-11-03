package nginx

import (
	"fmt"
	"path"
	"strings"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// directive is one parsed directive; block is non-nil for a block directive.
type directive struct {
	name  string
	args  []string
	file  string
	line  int
	block []*directive
}

func (d *directive) source() string { return fmt.Sprintf("%s:%d", d.file, d.line) }

// loader reads files and splices includes the way nginx's conf parser does: an include
// is parsed in place, in the block it appears in; a relative path is relative to the
// directory of the main file (nginx's conf prefix); a pattern with wildcards is expanded
// with glob(3) and may match nothing, a plain path must exist.
type loader struct {
	fsys   conf.FS
	r      *conf.Reader
	prefix string
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
	toks, unterminated := lex(string(data))
	if unterminated {
		l.r.Note("unexpected end of file, expecting a closing quote in %s", p)
	}
	pos := 0
	ds := l.block(p, toks, &pos, depth, false)
	return ds
}

// block parses directives up to a closing brace (nested) or the end of the tokens.
func (l *loader) block(file string, toks []token, pos *int, depth int, nested bool) []*directive {
	var out []*directive
	var words []token
	for *pos < len(toks) {
		t := toks[*pos]
		*pos++
		switch t.kind {
		case tokWord:
			words = append(words, t)
		case tokSemi:
			if len(words) == 0 {
				continue
			}
			d := newDirective(file, words)
			words = nil
			if d.name == "include" && len(d.args) == 1 {
				out = append(out, l.include(d, depth)...)
				continue
			}
			out = append(out, d)
		case tokOpen:
			if len(words) == 0 {
				l.r.Note("unexpected { at %s:%d", file, t.line)
				words = []token{{tokWord, "", t.line}}
			}
			d := newDirective(file, words)
			words = nil
			d.block = l.block(file, toks, pos, depth, true)
			if d.block == nil {
				d.block = []*directive{}
			}
			out = append(out, d)
		case tokClose:
			if !nested {
				l.r.Note("unexpected } at %s:%d", file, t.line)
				continue
			}
			return out
		}
	}
	if nested {
		l.r.Note("unexpected end of file, expecting } in %s", file)
	}
	if len(words) > 0 {
		l.r.Note("unexpected end of file, expecting ; or } in %s", file)
	}
	return out
}

func newDirective(file string, words []token) *directive {
	d := &directive{name: words[0].text, file: file, line: words[0].line}
	for _, w := range words[1:] {
		d.args = append(d.args, w.text)
	}
	return d
}

func (l *loader) include(d *directive, depth int) []*directive {
	p := d.args[0]
	if !path.IsAbs(p) {
		p = path.Join(l.prefix, p)
	}
	var files []string
	if conf.HasMeta(p) {
		files = conf.Glob(l.fsys, l.r, p)
	} else {
		files = []string{path.Clean(p)}
	}
	var out []*directive
	for _, f := range files {
		out = append(out, l.file(f, depth+1)...)
	}
	return out
}

// ParseDump splits `nginx -T` output into its files: each starts with a line
// "# configuration file <path>:" and is followed by one extra newline. The first file is
// the main one.
func ParseDump(out []byte) (main string, files conf.MemFS, order []string, err error) {
	const header = "# configuration file "
	files = conf.MemFS{}
	s := string(out)
	var cur string
	var body strings.Builder
	flush := func() {
		if cur != "" {
			files[cur] = []byte(strings.TrimSuffix(body.String(), "\n"))
		}
		body.Reset()
	}
	for len(s) > 0 {
		line, rest, _ := strings.Cut(s, "\n")
		s = rest
		if name, ok := strings.CutPrefix(line, header); ok && strings.HasSuffix(name, ":") {
			if _, dup := files[strings.TrimSuffix(name, ":")]; !dup {
				flush()
				cur = strings.TrimSuffix(name, ":")
				order = append(order, cur)
				if main == "" {
					main = cur
				}
				continue
			}
		}
		if cur != "" {
			body.WriteString(line)
			body.WriteByte('\n')
		}
	}
	flush()
	if main == "" {
		return "", nil, nil, fmt.Errorf("no %q header", header)
	}
	return main, files, order, nil
}
