// Package nft reads `nft -j list ruleset` output into the firewall model.
//
// Only what decides whether an inbound packet is accepted, dropped or DNAT'ed is kept:
// matches on ports, addresses, interfaces, protocols, ct state, fib address type and
// mark; verdicts; dnat/redirect; mark changes; verdict maps. Anything else that can
// affect a match becomes an Unknown match (three-valued "maybe"), so it is never
// silently read as a hit or a miss. Statements with no effect on the verdict (counter,
// log, …) are dropped.
package nft

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/exposure/firewall"
)

// Table is one table in the dump.
type Table struct {
	Family firewall.Family
	Name   string
	// HasXT: some rule holds an xtables expression (iptables-nft's compatibility layer),
	// whose details the JSON dump leaves out. iptables-save prints such a table in full.
	HasXT bool
}

// Ruleset is a parsed dump.
type Ruleset struct {
	Tables []Table
	Chains []*firewall.Chain
}

type document struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type tableObj struct {
	Family string   `json:"family"`
	Name   string   `json:"name"`
	Flags  []string `json:"flags"`
}

type chainObj struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Hook   string          `json:"hook"`
	Prio   json.RawMessage `json:"prio"`
	Policy string          `json:"policy"`
}

type ruleObj struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Expr   []json.RawMessage `json:"expr"`
}

type setObj struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Name   string            `json:"name"`
	Elem   []json.RawMessage `json:"elem"`
}

type tableKey struct {
	family firewall.Family
	name   string
}

type setKey struct {
	family firewall.Family
	table  string
	name   string
}

// Parse reads a `nft -j list ruleset` document. Tables of families other than ip, ip6
// and inet (bridge, arp, netdev) and dormant tables are left out.
func Parse(data []byte) (*Ruleset, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nft: decode: %w", err)
	}
	p := &parser{sets: make(map[setKey][]json.RawMessage), maps: make(map[setKey][]json.RawMessage)}
	skip := make(map[tableKey]bool)
	tables := make(map[tableKey]*Table)
	var order []tableKey
	chains := make(map[string]*firewall.Chain)
	var chainOrder []*firewall.Chain

	// Sets and maps can follow the rules that use them, so they are collected first.
	for _, obj := range doc.Nftables {
		for kind, raw := range obj {
			switch kind {
			case "set", "map":
				var s setObj
				if err := json.Unmarshal(raw, &s); err != nil {
					return nil, fmt.Errorf("nft: %s: %w", kind, err)
				}
				fam, ok := family(s.Family)
				if !ok {
					continue
				}
				k := setKey{fam, s.Table, s.Name}
				if kind == "set" {
					p.sets[k] = s.Elem
				} else {
					p.maps[k] = s.Elem
				}
			}
		}
	}

	for _, obj := range doc.Nftables {
		for kind, raw := range obj {
			switch kind {
			case "table":
				var t tableObj
				if err := json.Unmarshal(raw, &t); err != nil {
					return nil, fmt.Errorf("nft: table: %w", err)
				}
				fam, ok := family(t.Family)
				k := tableKey{fam, t.Name}
				if !ok || contains(t.Flags, "dormant") {
					skip[k] = true
					continue
				}
				tables[k] = &Table{Family: fam, Name: t.Name}
				order = append(order, k)
			case "chain":
				var c chainObj
				if err := json.Unmarshal(raw, &c); err != nil {
					return nil, fmt.Errorf("nft: chain: %w", err)
				}
				fam, ok := family(c.Family)
				if !ok || skip[tableKey{fam, c.Table}] {
					continue
				}
				ch, err := newChain(fam, c)
				if err != nil {
					return nil, err
				}
				chains[chainID(fam, c.Table, c.Name)] = ch
				chainOrder = append(chainOrder, ch)
			case "rule":
				var r ruleObj
				if err := json.Unmarshal(raw, &r); err != nil {
					return nil, fmt.Errorf("nft: rule: %w", err)
				}
				fam, ok := family(r.Family)
				if !ok || skip[tableKey{fam, r.Table}] {
					continue
				}
				ch := chains[chainID(fam, r.Table, r.Chain)]
				if ch == nil {
					return nil, fmt.Errorf("nft: rule for unknown chain %s %s %s", r.Family, r.Table, r.Chain)
				}
				rule, xt, err := p.rule(fam, r.Table, r.Expr)
				if err != nil {
					return nil, fmt.Errorf("nft: rule in %s: %w", ch.Where(), err)
				}
				if xt {
					if t := tables[tableKey{fam, r.Table}]; t != nil {
						t.HasXT = true
					}
				}
				ch.Rules = append(ch.Rules, rule)
			}
		}
	}

	rs := &Ruleset{Chains: chainOrder}
	for _, k := range order {
		rs.Tables = append(rs.Tables, *tables[k])
	}
	return rs, nil
}

func chainID(f firewall.Family, table, name string) string {
	return f.String() + "\x00" + table + "\x00" + name
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func family(s string) (firewall.Family, bool) {
	switch s {
	case "ip":
		return firewall.FamilyIP, true
	case "ip6":
		return firewall.FamilyIP6, true
	case "inet":
		return firewall.FamilyInet, true
	}
	return 0, false
}

// Named priorities (nft(8) "PRIORITY") for dumps that print names instead of numbers.
var namedPrio = map[string]int{"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}

func newChain(fam firewall.Family, c chainObj) (*firewall.Chain, error) {
	ch := &firewall.Chain{Origin: "nft", Family: fam, Table: c.Table, Name: c.Name, Policy: firewall.VerdictAccept}
	if c.Hook == "" {
		return ch, nil
	}
	switch c.Hook {
	case "prerouting":
		ch.Hook = firewall.HookPrerouting
	case "input":
		ch.Hook = firewall.HookInput
	case "forward":
		ch.Hook = firewall.HookForward
	case "output":
		ch.Hook = firewall.HookOutput
	case "postrouting":
		ch.Hook = firewall.HookPostrouting
	default:
		// ingress and other hooks see packets outside the path modelled here.
		return ch, nil
	}
	switch c.Type {
	case "nat":
		ch.Type = firewall.TypeNAT
	case "route":
		ch.Type = firewall.TypeRoute
	}
	if c.Policy == "drop" {
		ch.Policy = firewall.VerdictDrop
	}
	if len(c.Prio) > 0 {
		var n int
		if err := json.Unmarshal(c.Prio, &n); err != nil {
			var name string
			if json.Unmarshal(c.Prio, &name) != nil {
				return nil, fmt.Errorf("nft: chain %s prio %s", c.Name, c.Prio)
			}
			v, ok := namedPrio[name]
			if !ok {
				return nil, fmt.Errorf("nft: chain %s prio %q", c.Name, name)
			}
			n = v
		}
		ch.Prio = n
	}
	return ch, nil
}

type parser struct {
	sets map[setKey][]json.RawMessage
	maps map[setKey][]json.RawMessage
}

// ctx is where a rule lives, for resolving named sets.
type ctx struct {
	family firewall.Family
	table  string
}

// rule converts one rule's expressions. xt reports an xtables expression.
func (p *parser) rule(fam firewall.Family, table string, exprs []json.RawMessage) (firewall.Rule, bool, error) {
	c := ctx{fam, table}
	var r firewall.Rule
	xt := false
	for _, raw := range exprs {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return r, false, err
		}
		for kind, body := range obj {
			e, isXT, err := p.expr(c, kind, body)
			if err != nil {
				return r, false, fmt.Errorf("%s: %w", kind, err)
			}
			xt = xt || isXT
			if e != nil {
				r.Exprs = append(r.Exprs, e)
			}
		}
	}
	return r, xt, nil
}

func unknown(what string) firewall.Match {
	return firewall.Match{Field: firewall.FieldUnknown, Unknown: what}
}

func (p *parser) expr(c ctx, kind string, body json.RawMessage) (firewall.Expr, bool, error) {
	switch kind {
	case "match":
		m, err := p.match(c, body)
		return m, false, err
	case "accept":
		return firewall.Verdict{Kind: firewall.VerdictAccept}, false, nil
	case "drop", "reject":
		return firewall.Verdict{Kind: firewall.VerdictDrop}, false, nil
	case "return":
		return firewall.Verdict{Kind: firewall.VerdictReturn}, false, nil
	case "continue":
		return firewall.Verdict{Kind: firewall.VerdictContinue}, false, nil
	case "queue":
		return firewall.Verdict{Kind: firewall.VerdictQueue}, false, nil
	case "jump", "goto":
		var t struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal(body, &t); err != nil {
			return nil, false, err
		}
		k := firewall.VerdictJump
		if kind == "goto" {
			k = firewall.VerdictGoto
		}
		return firewall.Verdict{Kind: k, Target: t.Target}, false, nil
	case "dnat", "redirect":
		return natStmt(kind, body), false, nil
	case "snat", "masquerade":
		return firewall.NAT{Kind: firewall.NATOther}, false, nil
	case "mangle":
		return mangle(body), false, nil
	case "vmap":
		v, err := p.vmap(c, body)
		return v, false, err
	case "limit", "quota", "synproxy":
		return unknown(kind), false, nil
	case "xt":
		var x struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &x); err != nil {
			return nil, true, err
		}
		return xtExpr(x.Type, x.Name), true, nil
	}
	// Other statements (counter, log, set updates, meta/ct value changes, dup, fwd, …)
	// neither match nor end evaluation for an inbound packet's verdict.
	return nil, false, nil
}

// xtExpr turns an xtables blob into what is known of it: a match is maybe, a DNAT or
// REDIRECT target loses the destination, a MARK target the mark, REJECT drops.
func xtExpr(typ, name string) firewall.Expr {
	if typ == "match" {
		return unknown("xt " + name)
	}
	switch strings.ToUpper(name) {
	case "DNAT", "REDIRECT", "NETMAP":
		return firewall.NAT{Kind: firewall.NATDnat, Unknown: "xt " + name}
	case "MARK", "CONNMARK":
		return firewall.Mark{Unknown: true}
	case "REJECT":
		return firewall.Verdict{Kind: firewall.VerdictDrop}
	}
	return nil
}

func natStmt(kind string, body json.RawMessage) firewall.Expr {
	n := firewall.NAT{Kind: firewall.NATDnat}
	if kind == "redirect" {
		n.Kind = firewall.NATRedirect
	}
	var s struct {
		Addr json.RawMessage `json:"addr"`
		Port json.RawMessage `json:"port"`
	}
	if len(body) > 0 && string(body) != "null" {
		if err := json.Unmarshal(body, &s); err != nil {
			n.Unknown = kind + " target"
			return n
		}
	}
	if len(s.Addr) > 0 {
		var a string
		addr, err := netip.ParseAddr(strings.Trim(string(s.Addr), `"`))
		if json.Unmarshal(s.Addr, &a) != nil || err != nil {
			n.Unknown = kind + " target"
			return n
		}
		n.Addr = addr
	}
	if len(s.Port) > 0 {
		var port int
		if json.Unmarshal(s.Port, &port) != nil || port <= 0 || port > math.MaxUint16 {
			n.Unknown = kind + " port"
			return n
		}
		n.Port = uint16(port)
	}
	if n.Kind == firewall.NATDnat && !n.Addr.IsValid() {
		n.Unknown = kind + " target"
	}
	return n
}

// mangle handles `meta mark set …`; other mangles do not affect a match the model makes.
func mangle(body json.RawMessage) firewall.Expr {
	var m struct {
		Key   map[string]json.RawMessage `json:"key"`
		Value json.RawMessage            `json:"value"`
	}
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	if metaKey(m.Key["meta"]) != "mark" {
		return nil
	}
	var n uint32
	if json.Unmarshal(m.Value, &n) == nil {
		return firewall.Mark{Clear: math.MaxUint32, Xor: n}
	}
	var op map[string][]json.RawMessage
	if json.Unmarshal(m.Value, &op) == nil && len(op) == 1 {
		for sym, args := range op {
			if len(args) != 2 {
				break
			}
			var lhs map[string]json.RawMessage
			var v uint32
			if json.Unmarshal(args[0], &lhs) != nil || metaKey(lhs["meta"]) != "mark" || json.Unmarshal(args[1], &v) != nil {
				break
			}
			switch sym {
			case "|":
				return firewall.Mark{Clear: v, Xor: v}
			case "&":
				return firewall.Mark{Clear: ^v}
			case "^":
				return firewall.Mark{Xor: v}
			}
		}
	}
	return firewall.Mark{Unknown: true}
}

func metaKey(raw json.RawMessage) string {
	var m struct {
		Key string `json:"key"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return m.Key
}

type matchObj struct {
	Op    string          `json:"op"`
	Left  json.RawMessage `json:"left"`
	Right json.RawMessage `json:"right"`
}

// left decodes a match's left side into a field. A false ok means the model does not
// follow that field; desc then names it.
func left(raw json.RawMessage) (m firewall.Match, desc string, ok bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) != 1 {
		return m, "expression", false
	}
	for kind, body := range obj {
		switch kind {
		case "payload":
			var pl struct {
				Protocol string `json:"protocol"`
				Field    string `json:"field"`
			}
			if json.Unmarshal(body, &pl) != nil {
				return m, "payload", false
			}
			desc = pl.Protocol + " " + pl.Field
			switch {
			case (pl.Protocol == "tcp" || pl.Protocol == "udp" || pl.Protocol == "th") && pl.Field == "dport":
				m.Field = firewall.FieldDPort
			case (pl.Protocol == "tcp" || pl.Protocol == "udp" || pl.Protocol == "th") && pl.Field == "sport":
				m.Field = firewall.FieldSPort
			case pl.Protocol == "ip" && (pl.Field == "saddr" || pl.Field == "daddr"),
				pl.Protocol == "ip6" && (pl.Field == "saddr" || pl.Field == "daddr"):
				m.Field = firewall.FieldSAddr
				if pl.Field == "daddr" {
					m.Field = firewall.FieldDAddr
				}
			case pl.Protocol == "ip" && pl.Field == "protocol", pl.Protocol == "ip6" && pl.Field == "nexthdr":
				m.Field = firewall.FieldL4Proto
			default:
				return m, desc, false
			}
			switch pl.Protocol {
			case "tcp", "udp":
				m.Proto = pl.Protocol
			case "ip":
				m.Family = firewall.FamilyIP
			case "ip6":
				m.Family = firewall.FamilyIP6
			}
			return m, desc, true
		case "meta":
			key := metaKey(body)
			desc = "meta " + key
			switch key {
			case "l4proto":
				m.Field = firewall.FieldL4Proto
			case "iifname", "iif":
				m.Field = firewall.FieldIIf
			case "oifname", "oif":
				m.Field = firewall.FieldOIf
			case "nfproto":
				m.Field = firewall.FieldNFProto
			case "mark":
				m.Field, m.Mask = firewall.FieldMark, math.MaxUint32
			default:
				return m, desc, false
			}
			return m, desc, true
		case "ct":
			key := metaKey(body)
			desc = "ct " + key
			switch key {
			case "state", "status":
				m.Field = firewall.FieldCtState
				return m, desc, true
			}
			return m, desc, false
		case "fib":
			var f struct {
				Result string   `json:"result"`
				Flags  []string `json:"flags"`
			}
			if json.Unmarshal(body, &f) != nil || f.Result != "type" || len(f.Flags) != 1 || f.Flags[0] != "daddr" {
				return m, "fib", false
			}
			m.Field = firewall.FieldDAddrType
			return m, "fib daddr type", true
		case "&":
			// meta mark & mask
			var args []json.RawMessage
			var mask uint32
			if json.Unmarshal(body, &args) != nil || len(args) != 2 || json.Unmarshal(args[1], &mask) != nil {
				return m, "bitwise", false
			}
			var inner map[string]json.RawMessage
			if json.Unmarshal(args[0], &inner) != nil || metaKey(inner["meta"]) != "mark" {
				return m, "bitwise", false
			}
			m.Field, m.Mask = firewall.FieldMark, mask
			return m, "meta mark", true
		default:
			return m, kind, false
		}
	}
	return m, "expression", false
}

func (p *parser) match(c ctx, body json.RawMessage) (firewall.Expr, error) {
	var mo matchObj
	if err := json.Unmarshal(body, &mo); err != nil {
		return nil, err
	}
	m, desc, ok := left(mo.Left)
	if !ok {
		return unknown(desc), nil
	}
	switch mo.Op {
	case "==", "in", "":
		m.Op = firewall.OpEq
	case "!=":
		m.Op = firewall.OpNe
	case "<", ">", "<=", ">=":
		if m.Field != firewall.FieldDPort && m.Field != firewall.FieldSPort {
			return unknown(desc + " " + mo.Op), nil
		}
		var n int
		if json.Unmarshal(mo.Right, &n) != nil || n < 0 || n > math.MaxUint16 {
			return unknown(desc + " " + mo.Op), nil
		}
		m.Op = firewall.OpEq
		m.Ports = []firewall.PortRange{comparison(mo.Op, uint16(n))}
		return m, nil
	default:
		return unknown(desc + " " + mo.Op), nil
	}
	values, err := p.values(c, mo.Right)
	if err != nil {
		return unknown(desc + ": " + err.Error()), nil
	}
	if !fill(&m, values) {
		return unknown(desc + " value"), nil
	}
	return m, nil
}

func comparison(op string, n uint16) firewall.PortRange {
	switch op {
	case "<":
		if n == 0 {
			return firewall.PortRange{Lo: 1, Hi: 0} // empty
		}
		return firewall.PortRange{Lo: 0, Hi: n - 1}
	case "<=":
		return firewall.PortRange{Lo: 0, Hi: n}
	case ">":
		if n == math.MaxUint16 {
			return firewall.PortRange{Lo: 1, Hi: 0}
		}
		return firewall.PortRange{Lo: n + 1, Hi: math.MaxUint16}
	}
	return firewall.PortRange{Lo: n, Hi: math.MaxUint16}
}

// value is one decoded right-hand element: a scalar, a range or a prefix.
type value struct {
	scalar json.RawMessage
	lo, hi json.RawMessage // range
	pfx    netip.Prefix
	isPfx  bool
}

// values flattens a right-hand side (scalar, list, anonymous set, @named set, range,
// prefix) into elements.
func (p *parser) values(c ctx, raw json.RawMessage) ([]value, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil && strings.HasPrefix(s, "@") {
		elems, ok := p.sets[setKey{c.family, c.table, s[1:]}]
		if !ok {
			return nil, fmt.Errorf("set %s not in dump", s)
		}
		return p.elems(c, elems)
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		return p.elems(c, list)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		if set, ok := obj["set"]; ok && len(obj) == 1 {
			if json.Unmarshal(set, &list) != nil {
				// A one-element anonymous set can be printed as a bare value.
				return p.elems(c, []json.RawMessage{set})
			}
			return p.elems(c, list)
		}
	}
	return p.elems(c, []json.RawMessage{raw})
}

func (p *parser) elems(c ctx, raws []json.RawMessage) ([]value, error) {
	var out []value
	for _, raw := range raws {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil || len(obj) != 1 {
			out = append(out, value{scalar: raw})
			continue
		}
		for kind, body := range obj {
			switch kind {
			case "range":
				var r []json.RawMessage
				if json.Unmarshal(body, &r) != nil || len(r) != 2 {
					return nil, fmt.Errorf("bad range")
				}
				out = append(out, value{lo: r[0], hi: r[1]})
			case "prefix":
				var pf struct {
					Addr string `json:"addr"`
					Len  int    `json:"len"`
				}
				if json.Unmarshal(body, &pf) != nil {
					return nil, fmt.Errorf("bad prefix")
				}
				a, err := netip.ParseAddr(pf.Addr)
				if err != nil {
					return nil, err
				}
				pfx, err := a.Prefix(pf.Len)
				if err != nil {
					return nil, err
				}
				out = append(out, value{pfx: pfx, isPfx: true})
			case "elem":
				// An element with options (timeout, counter): {"elem": {"val": …}}.
				var e struct {
					Val json.RawMessage `json:"val"`
				}
				if json.Unmarshal(body, &e) != nil {
					return nil, fmt.Errorf("bad elem")
				}
				vs, err := p.elems(c, []json.RawMessage{e.Val})
				if err != nil {
					return nil, err
				}
				out = append(out, vs...)
			default:
				return nil, fmt.Errorf("unsupported element %s", kind)
			}
		}
	}
	return out, nil
}

// l4 protocol numbers the dumps may print instead of names.
var protoNames = map[int]string{1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp", 136: "udplite", 33: "dccp"}

// fill stores decoded values in the match according to its field; false when a value
// does not fit the field.
func fill(m *firewall.Match, vs []value) bool {
	for _, v := range vs {
		switch m.Field {
		case firewall.FieldDPort, firewall.FieldSPort:
			if v.isPfx {
				return false
			}
			if v.scalar != nil {
				n, ok := port(v.scalar)
				if !ok {
					return false
				}
				m.Ports = append(m.Ports, firewall.PortRange{Lo: n, Hi: n})
				continue
			}
			lo, ok1 := port(v.lo)
			hi, ok2 := port(v.hi)
			if !ok1 || !ok2 {
				return false
			}
			m.Ports = append(m.Ports, firewall.PortRange{Lo: lo, Hi: hi})
		case firewall.FieldSAddr, firewall.FieldDAddr:
			switch {
			case v.isPfx:
				m.Pfx = append(m.Pfx, v.pfx)
			case v.scalar != nil:
				a, ok := addr(v.scalar)
				if !ok {
					return false
				}
				m.Pfx = append(m.Pfx, netip.PrefixFrom(a, a.BitLen()))
			default:
				lo, ok1 := addr(v.lo)
				hi, ok2 := addr(v.hi)
				if !ok1 || !ok2 {
					return false
				}
				m.Ranges = append(m.Ranges, firewall.AddrRange{Lo: lo, Hi: hi})
			}
		case firewall.FieldMark:
			var n uint32
			if v.scalar == nil || json.Unmarshal(v.scalar, &n) != nil {
				return false
			}
			m.Mark = n
		default: // names
			if v.scalar == nil {
				return false
			}
			var s string
			if json.Unmarshal(v.scalar, &s) == nil {
				m.Names = append(m.Names, s)
				continue
			}
			var n int
			if json.Unmarshal(v.scalar, &n) != nil {
				return false
			}
			name, ok := protoNames[n]
			if m.Field != firewall.FieldL4Proto || !ok {
				name = strconv.Itoa(n)
			}
			m.Names = append(m.Names, name)
		}
	}
	return true
}

func port(raw json.RawMessage) (uint16, bool) {
	var n int
	if json.Unmarshal(raw, &n) != nil || n < 0 || n > math.MaxUint16 {
		return 0, false
	}
	return uint16(n), true
}

func addr(raw json.RawMessage) (netip.Addr, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	return a.Unmap(), err == nil
}

// vmap reads `<key> vmap { … }` or `<key> vmap @name`.
func (p *parser) vmap(c ctx, body json.RawMessage) (firewall.Expr, error) {
	var v struct {
		Key  json.RawMessage `json:"key"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}
	key, desc, ok := left(v.Key)
	if !ok {
		return unknown("vmap on " + desc), nil
	}
	var elems []json.RawMessage
	var name string
	if json.Unmarshal(v.Data, &name) == nil && strings.HasPrefix(name, "@") {
		e, ok := p.maps[setKey{c.family, c.table, name[1:]}]
		if !ok {
			return unknown("vmap " + name + " not in dump"), nil
		}
		elems = e
	} else {
		var obj struct {
			Set []json.RawMessage `json:"set"`
		}
		if json.Unmarshal(v.Data, &obj) != nil {
			return unknown("vmap data"), nil
		}
		elems = obj.Set
	}
	out := firewall.VMap{Key: key}
	for _, raw := range elems {
		var pair []json.RawMessage
		if json.Unmarshal(raw, &pair) != nil || len(pair) != 2 {
			return unknown("vmap element"), nil
		}
		vs, err := p.elems(c, []json.RawMessage{pair[0]})
		if err != nil {
			return unknown("vmap key: " + err.Error()), nil
		}
		m := key
		if !fill(&m, vs) {
			return unknown("vmap key value"), nil
		}
		var verdictObj map[string]json.RawMessage
		if json.Unmarshal(pair[1], &verdictObj) != nil || len(verdictObj) != 1 {
			return unknown("vmap verdict"), nil
		}
		var verdict firewall.Verdict
		for kind, vb := range verdictObj {
			e, _, err := p.expr(c, kind, vb)
			vv, isVerdict := e.(firewall.Verdict)
			if err != nil || !isVerdict {
				return unknown("vmap verdict " + kind), nil
			}
			verdict = vv
		}
		out.Elems = append(out.Elems, firewall.VMapElem{Match: m, Verdict: verdict})
	}
	return out, nil
}
