package apache

import (
	"fmt"
	"slices"
	"strings"
)

// Limits on mod_macro expansion. The expanded text also counts against the load's byte
// budget (conf.MaxTotalBytes) and each Use spends one operation (conf.MaxOps), so a
// macro used inside a macro cannot multiply past what a load may read.
const (
	// MaxMacroDepth bounds Use nested inside the expansion of another Use.
	MaxMacroDepth = 8
	// MaxMacros bounds the macros defined in one load.
	MaxMacros = 256
)

// macro is one <Macro name $param…> definition: its body lines as written.
type macro struct {
	name   string
	params []string // in definition order
	order  []int    // indexes into params, longest parameter first
	body   []line
	file   string
	line   int
}

// macros is the load's macro table and the expansion in progress.
type macros struct {
	defs map[string]*macro // by lower-case name, as mod_macro matches them
	// active are the macros being expanded (outermost first), to refuse recursion.
	active []string
	// via describes the innermost expansion, for the directives it produces.
	via string
}

// defineMacro reads a <Macro> section (its lines up to the matching </Macro>, nested
// <Macro> sections counted) into the table, as mod_macro does when it reads the config.
func (l *loader) defineMacro(file string, num int, args []string, lines []line, pos *int) {
	body := macroBody(lines, pos)
	where := fmt.Sprintf("%s:%d", file, num)
	switch {
	case len(args) == 0:
		l.r.Note("<Macro> without a name at %s", where)
		return
	case len(l.macros.defs) >= MaxMacros:
		l.r.Note("more than %d macros; <Macro %s> at %s ignored", MaxMacros, args[0], where)
		return
	}
	params := args[1:]
	for i, p := range params {
		if slices.Contains(params[:i], p) {
			l.r.Note("<Macro %s> at %s: duplicate parameter %s; ignored", args[0], where, p)
			return
		}
	}
	if l.macros.defs == nil {
		l.macros.defs = make(map[string]*macro)
	}
	// Longest parameter first, so "$host" is not replaced inside "$hostname".
	order := make([]int, len(params))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return len(params[b]) - len(params[a]) })
	l.macros.defs[strings.ToLower(args[0])] = &macro{name: args[0], params: slices.Clone(params), order: order, body: body, file: file, line: num}
}

// macroBody returns the lines up to the </Macro> closing the section just opened and
// moves pos past it.
func macroBody(lines []line, pos *int) []line {
	start, depth := *pos, 1
	for *pos < len(lines) {
		t := strings.ToLower(lines[*pos].text)
		*pos++
		switch {
		case strings.HasPrefix(t, "</macro"):
			depth--
			if depth == 0 {
				return lines[start : *pos-1]
			}
		case strings.HasPrefix(t, "<macro ") || strings.HasPrefix(t, "<macro\t") || t == "<macro>":
			depth++
		}
	}
	return lines[start:*pos]
}

// use expands "Use name value…": the macro's body with each parameter replaced by its
// value, read as if written in place. The values are the Use line's words before ${VAR}
// substitution, so an environment value reaches only what is resolved, never what is
// published (the expansion's words are substituted when they are read).
func (l *loader) use(d *directive, depth int) []*directive {
	if len(d.args) == 0 {
		l.r.Note("Use without a macro name at %s", d.source())
		return nil
	}
	values := d.args[1:]
	if len(d.raw) == len(d.args) {
		values = d.raw[1:]
	}
	key := strings.ToLower(d.args[0])
	m, ok := l.macros.defs[key]
	switch {
	case !ok:
		l.r.Note("Use of undefined macro %s at %s", d.args[0], d.source())
		return nil
	case len(values) != len(m.params):
		l.r.Note("Use %s at %s: %d arguments, the macro takes %d; not expanded", m.name, d.source(), len(values), len(m.params))
		return nil
	case slices.Contains(l.macros.active, key):
		l.r.Note("recursive Use of macro %s at %s; not expanded", m.name, d.source())
		return nil
	case len(l.macros.active) >= MaxMacroDepth:
		l.r.Note("macro nesting over %d at %s; not expanded", MaxMacroDepth, d.source())
		return nil
	case !l.r.Op():
		return nil
	}
	expanded := make([]line, 0, len(m.body))
	for _, ln := range m.body {
		text := substituteParams(ln.text, m.params, values, m.order)
		if !l.r.Spend(len(text)) {
			return nil
		}
		expanded = append(expanded, line{text: text, num: ln.num})
	}
	prevVia := l.macros.via
	l.macros.active = append(l.macros.active, key)
	l.macros.via = fmt.Sprintf("macro %s (Use at %s)", m.name, d.source())
	if prevVia != "" {
		l.macros.via += " in " + prevVia
	}
	defer func() {
		l.macros.active = l.macros.active[:len(l.macros.active)-1]
		l.macros.via = prevVia
	}()
	pos := 0
	return l.block(m.file, expanded, &pos, depth, "")
}

// substituteParams replaces every parameter in text by its value, scanning left to
// right and trying the longest parameter first at each position (mod_macro's rule).
// params and values are in definition order; order lists the parameter indexes longest
// first.
func substituteParams(text string, params, values []string, order []int) string {
	if len(params) == 0 {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); {
		matched := false
		for _, k := range order {
			if p := params[k]; p != "" && strings.HasPrefix(text[i:], p) {
				b.WriteString(values[k])
				i += len(p)
				matched = true
				break
			}
		}
		if !matched {
			b.WriteByte(text[i])
			i++
		}
	}
	return b.String()
}
