// Package firewall is the common model of a host's packet filter (nftables and iptables
// rules alike) and an evaluator that asks one question of it: does a new connection
// from anyone on the outside (0/0) reach a given address and port?
//
// Matching is three-valued. An expression the model cannot decide for that packet (a rate
// limit, a random statistic, an xtables blob the JSON dump hides, a set of an unsupported
// type) is "maybe": the evaluation forks, following both the matching and the
// non-matching path, so the answer is a set of outcomes. Only when every outcome agrees is
// the verdict definite.
package firewall

import (
	"net/netip"
	"strings"
)

// Family is a rule table's address family. Only the families that see IP packets on the
// host's hooks are modelled; bridge, arp and netdev tables are left out by the parsers.
type Family int

const (
	FamilyIP Family = iota + 1
	FamilyIP6
	FamilyInet
)

func (f Family) String() string {
	switch f {
	case FamilyIP:
		return "ip"
	case FamilyIP6:
		return "ip6"
	case FamilyInet:
		return "inet"
	}
	return "?"
}

// covers reports whether a table of family f sees packets of family pf (FamilyIP or FamilyIP6).
func (f Family) covers(pf Family) bool { return f == FamilyInet || f == pf }

// Hook is the netfilter hook a base chain is attached to.
type Hook int

const (
	HookNone Hook = iota // a regular chain, reached only by jump or goto
	HookPrerouting
	HookInput
	HookForward
	HookOutput
	HookPostrouting
)

// ChainType is a base chain's type. NAT chains can rewrite the destination (dnat,
// redirect); filter and route chains only accept or drop.
type ChainType int

const (
	TypeFilter ChainType = iota
	TypeNAT
	TypeRoute
)

// Chain is one chain of one table.
type Chain struct {
	// Origin is the tool the chain was read with: "nft" or "iptables". It prefixes the
	// evidence a verdict in this chain produces.
	Origin string
	Family Family
	Table  string
	Name   string
	Hook   Hook
	Type   ChainType
	Prio   int
	// Policy is the verdict when a packet falls off a base chain: Accept or Drop.
	Policy VerdictKind
	Rules  []Rule
}

// Where names the chain for evidence: "inet filter input".
func (c *Chain) Where() string { return c.Family.String() + " " + c.Table + " " + c.Name }

// Rule is a sequence of expressions evaluated in order, as nftables does: matches
// filter, statements change the packet, and a verdict ends the rule.
type Rule struct {
	Exprs []Expr
}

// Expr is a Match, a VMap, a Mark, a NAT or a Verdict.
type Expr interface{ expr() }

// Field is what a Match looks at.
type Field int

const (
	FieldL4Proto   Field = iota + 1 // Names: tcp, udp, icmp, …
	FieldDPort                      // Ports; Match.Proto qualifies it (tcp, udp, or "" for any transport)
	FieldSPort                      // Ports; the outside client picks its source port, so always maybe
	FieldSAddr                      // Prefixes; Match.Family qualifies it
	FieldDAddr                      // Prefixes; Match.Family qualifies it
	FieldIIf                        // Names, globs with a trailing '*'
	FieldOIf                        // Names, globs with a trailing '*'
	FieldCtState                    // Names: new, established, related, invalid, untracked, dnat, snat
	FieldNFProto                    // Names: ipv4, ipv6
	FieldDAddrType                  // Names: local, unicast, multicast, broadcast, …
	FieldMark                       // Mark, MarkMask
	FieldTCPFlags                   // Mark (value) and Mask, or Any: the first packet is SYN
	FieldAlways                     // always matches; used with Note for decided state (a rate limit the first packet passes)
	FieldUnknown                    // always maybe; Match.Unknown says what it was
)

// TCP flag bits as nftables numbers them.
const (
	TCPFin uint32 = 1 << iota
	TCPSyn
	TCPRst
	TCPPsh
	TCPAck
	TCPUrg
	TCPEcn
	TCPCwr
)

// tcpSYN is the first packet's flags.
const tcpSYN = TCPSyn

// Op is a match operator.
type Op int

const (
	OpEq Op = iota // in the set
	OpNe           // not in the set
)

// AddrRange is an inclusive address range.
type AddrRange struct{ Lo, Hi netip.Addr }

// PortRange is an inclusive port range.
type PortRange struct{ Lo, Hi uint16 }

// Match compares one field of the packet with a set of values.
type Match struct {
	Field  Field
	Op     Op
	Proto  string // FieldDPort, FieldSPort: "tcp", "udp", or "" for any transport protocol
	Family Family // FieldSAddr, FieldDAddr: FamilyIP or FamilyIP6
	Ports  []PortRange
	Pfx    []netip.Prefix
	Ranges []AddrRange // FieldSAddr, FieldDAddr: inclusive address ranges
	Names  []string
	Mark   uint32
	Mask   uint32
	// Unknown describes a match the model cannot decide ("limit", "xt addrtype", …); with
	// FieldUnknown it is always maybe.
	Unknown string
	// Any: FieldTCPFlags matches when any bit of Mark is set (nft "tcp flags syn").
	Any bool
	// Note is recorded on the path when the match holds (e.g. "rate-limited").
	Note string
}

// VMap jumps (or accepts, drops, …) by looking the packet's Key field up in a verdict
// map, as `oifname vmap @jumps` does. A key that matches no element falls through.
type VMap struct {
	Key   Match // Field, Proto and Family say what is looked up; its values are ignored
	Elems []VMapElem
	// Unknown is set for a map the model cannot read (a concatenated key, a missing
	// map): the packet may get any verdict from it or fall through.
	Unknown string
	// Pick marks a map keyed by a number generator (`numgen random mod N vmap {…}`):
	// the packet takes exactly one element, any of them, so every element's verdict is
	// a path. PickAll says the elements cover every value the generator yields; when it
	// is false the packet may also fall through. Element matches are ignored.
	Pick, PickAll bool
}

// VMapElem is one element of a verdict map: the values of Key that select Verdict.
// And holds the further components of a concatenated key ("meta l4proto . th dport");
// the element matches when Match and every one of And do.
type VMapElem struct {
	Match   Match // Key with this element's values
	And     []Match
	Verdict Verdict
}

// Mark sets the packet mark: mark = (mark &^ Clear) ^ Xor. Unknown makes the mark unknown
// (a mark set from an expression the model does not follow).
type Mark struct {
	Clear, Xor uint32
	Unknown    bool
}

// NATKind is the kind of a NAT statement.
type NATKind int

const (
	NATDnat     NATKind = iota + 1 // to Addr (if valid) and Port (if nonzero)
	NATRedirect                    // to the host itself, Port if nonzero
	NATOther                       // snat, masquerade: irrelevant to an inbound packet's destination
)

// NAT is a nat statement. In a NAT chain it ends the chain's evaluation for the packet.
//
// A target can be a range: Addr..AddrHi and Port..PortHi (AddrHi invalid and PortHi 0
// for a single address or port). The kernel picks one address of the range per
// connection, and keeps the packet's own port when it lies inside the port range,
// unless Random (random, random-fully) is set; otherwise it picks a port of the range.
type NAT struct {
	Kind   NATKind
	Addr   netip.Addr
	AddrHi netip.Addr
	Port   uint16
	PortHi uint16
	Random bool
	// Unknown is set when the target cannot be read (a map lookup, an xt DNAT blob):
	// the packet's destination becomes unknown.
	Unknown string
}

// VerdictKind is what a verdict does.
type VerdictKind int

const (
	VerdictContinue VerdictKind = iota // no verdict: next rule
	VerdictAccept
	VerdictDrop // drop and reject
	VerdictJump
	VerdictGoto
	VerdictReturn
	VerdictQueue // hands the packet to userspace: undeterminable
)

// Verdict ends a rule.
type Verdict struct {
	Kind   VerdictKind
	Target string // Jump, Goto: the chain name in the same table
}

func (Match) expr()   {}
func (VMap) expr()    {}
func (Mark) expr()    {}
func (NAT) expr()     {}
func (Verdict) expr() {}

// Ruleset is every chain the host's packet filter has, from all sources.
type Ruleset struct {
	Chains []*Chain
}

// chainKey finds a chain of the same origin, family and table by name.
type chainKey struct {
	origin string
	family Family
	table  string
	name   string
}

// globMatch matches an interface name against a pattern with an optional trailing '*'.
func globMatch(pattern, name string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(name, prefix)
	}
	return pattern == name
}
