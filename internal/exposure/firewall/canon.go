package firewall

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Canonical is a stable text form of the ruleset for fingerprinting: every field of every
// chain, rule and expression, written explicitly in a fixed order (chains and rules in
// their evaluation order, which the dumps fix). Addresses and prefixes are written with
// String, strings quoted, so the text depends only on the rules: never on pointers or
// other in-memory detail (fmt's %#v of a netip.Addr prints its internal handle's
// address, which differs between processes).
func (rs *Ruleset) Canonical() string {
	var b strings.Builder
	for _, c := range rs.Chains {
		fmt.Fprintf(&b, "chain origin=%q family=%s table=%q name=%q hook=%d type=%d prio=%d policy=%d rules=%d\n",
			c.Origin, c.Family, c.Table, c.Name, int(c.Hook), int(c.Type), c.Prio, int(c.Policy), len(c.Rules))
		for _, r := range c.Rules {
			fmt.Fprintf(&b, " rule exprs=%d\n", len(r.Exprs))
			for _, e := range r.Exprs {
				b.WriteString("  ")
				writeExpr(&b, e)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

func writeExpr(b *strings.Builder, e Expr) {
	switch x := e.(type) {
	case Match:
		writeMatch(b, x)
	case VMap:
		b.WriteString("vmap key{")
		writeMatch(b, x.Key)
		fmt.Fprintf(b, "} unknown=%q elems=%d", x.Unknown, len(x.Elems))
		for _, el := range x.Elems {
			b.WriteString(" elem{")
			writeMatch(b, el.Match)
			fmt.Fprintf(b, " and=%d", len(el.And))
			for _, m := range el.And {
				b.WriteString(" {")
				writeMatch(b, m)
				b.WriteString("}")
			}
			b.WriteString(" ")
			writeVerdict(b, el.Verdict)
			b.WriteString("}")
		}
	case Mark:
		fmt.Fprintf(b, "mark clear=%d xor=%d unknown=%t", x.Clear, x.Xor, x.Unknown)
	case NAT:
		fmt.Fprintf(b, "nat kind=%d addr=%s port=%d unknown=%q", int(x.Kind), addr(x.Addr), x.Port, x.Unknown)
	case Verdict:
		writeVerdict(b, x)
	default:
		// A new expression type must get its own case; until then its type name keeps the
		// text stable (and its fields out of it).
		fmt.Fprintf(b, "expr type=%q", fmt.Sprintf("%T", e))
	}
}

func writeMatch(b *strings.Builder, m Match) {
	fmt.Fprintf(b, "match field=%d op=%d proto=%q family=%d ports=[", int(m.Field), int(m.Op), m.Proto, int(m.Family))
	for i, p := range m.Ports {
		sep(b, i)
		fmt.Fprintf(b, "%d-%d", p.Lo, p.Hi)
	}
	b.WriteString("] pfx=[")
	for i, p := range m.Pfx {
		sep(b, i)
		b.WriteString(prefix(p))
	}
	b.WriteString("] ranges=[")
	for i, r := range m.Ranges {
		sep(b, i)
		b.WriteString(addr(r.Lo) + "-" + addr(r.Hi))
	}
	b.WriteString("] names=[")
	for i, n := range m.Names {
		sep(b, i)
		b.WriteString(strconv.Quote(n))
	}
	fmt.Fprintf(b, "] mark=%d mask=%d unknown=%q any=%t note=%q", m.Mark, m.Mask, m.Unknown, m.Any, m.Note)
}

func writeVerdict(b *strings.Builder, v Verdict) {
	fmt.Fprintf(b, "verdict kind=%d target=%q", int(v.Kind), v.Target)
}

func sep(b *strings.Builder, i int) {
	if i > 0 {
		b.WriteByte(',')
	}
}

// addr and prefix write "-" for the zero value, which String renders as "invalid IP".
func addr(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}

func prefix(p netip.Prefix) string {
	if !p.IsValid() {
		return "-"
	}
	return p.String()
}
