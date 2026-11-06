package aws

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// outcome is a path's verdict (shared with the other clouds' judges).
type outcome = reach.Outcome

const (
	closed       = reach.Closed
	undetermined = reach.Undetermined
	open         = reach.Open
)

// Replies to a TCP client go back to its source port, which the client picks: 1-65535.
// Ordinary clients pick from 1024-65535 (every OS's ephemeral range lies inside it).
const (
	portLow, portHigh = 1, 65535
	ephemeralLow      = 1024
)

// maxRanges bounds the ranges an evidence line names.
const maxRanges = 4

// directPath judges the instance's own public addresses, per network interface and per
// address family: the internet addresses its security groups allow, that its subnet's
// network ACL lets in (and, for TCP, lets the replies out to), and that its subnet's
// route table sends back through an internet gateway.
func directPath(d HostData, p cloud.Port) (outcome, []string) {
	var why, maybe []string
	public := false
	for _, e := range paths(d.Instance) {
		for _, fam := range []reach.Family{reach.V4, reach.V6} {
			if (fam == reach.V4 && !e.v4) || (fam == reach.V6 && !e.v6) {
				continue
			}
			public = true
			res, lines := familyPath(d, e, fam, p)
			switch res {
			case open:
				return open, lines
			case undetermined:
				maybe = append(maybe, lines...)
			default:
				why = append(why, lines...)
			}
		}
	}
	if !public {
		return closed, []string{"cloud: instance has no public IPv4 or IPv6 address"}
	}
	if len(maybe) > 0 {
		return undetermined, append(maybe, why...)
	}
	return closed, why
}

// through is the internet addresses still getting through after each layer: sure ones,
// and maybe ones that get through only if data that was not read (or not understood)
// allows them. A path open only for maybe addresses is undetermined, never closed.
type through struct{ sure, maybe reach.Set }

func (t through) all() reach.Set { return t.sure.Union(t.maybe) }

func (t through) intersect(s reach.Set) through {
	return through{t.sure.Intersect(s), t.maybe.Intersect(s)}
}

// doubt turns every sure address into a maybe one (a layer that cannot be judged).
func (t through) doubt() through { return through{maybe: t.all()} }

func familyPath(d HostData, e eniPath, fam reach.Family, p cloud.Port) (outcome, []string) {
	pol := d.Policy
	sg := sgAllowed(d, e.groups, p.Proto, p.Port, fam)
	t := through{sure: pol.Exposed(sg.sure)}
	t.maybe = pol.Exposed(sg.maybe).Subtract(t.sure)
	if t.all().IsEmpty() {
		line := fmt.Sprintf("cloud: %s: no security group allows %s/%d from the internet (%s)", e.id, p.Proto, p.Port, reach.Anywhere(fam))
		if !sg.sure.IsEmpty() {
			line += "; allowed only from private or VPN ranges"
		}
		return closed, []string{line}
	}
	evidence := sg.why
	var doubts []string
	acl, read := d.NACLs[e.subnet]
	if !read {
		evidence = append(evidence, "cloud: nacl for "+e.subnet+" not read (assumed open)")
	} else if in, inWhy, err := naclInbound(acl, p, fam, t.all(), pol); err != nil {
		t = t.doubt()
		doubts = append(doubts, deref(acl.NetworkAclId)+" inbound: "+err.Error())
	} else {
		t = t.intersect(in)
		if t.all().IsEmpty() {
			return closed, prefixed(e.id, inWhy)
		}
		evidence = append(evidence, inWhy...)
		if p.Proto == "tcp" {
			var line string
			var ok bool
			if t, line, ok = naclReturnPath(acl, fam, p, t, pol); !ok {
				return closed, append(evidence, "cloud: "+e.id+": "+line)
			}
			if line != "" {
				doubts = append(doubts, line)
			}
		}
	}
	undecided := func(reason string) (outcome, []string) {
		reasons := strings.Join(append(doubts, reason), "; ")
		return undetermined, append(evidence, cloud.UndeterminedEvidence+" ("+e.id+": "+reasons+")")
	}
	if d.RoutesErr != "" {
		return undecided("route tables not read: " + d.RoutesErr)
	}
	rt, why, ok := routeTableFor(d.RouteTables, e)
	if !ok {
		return undecided(why)
	}
	rs := routeSets(rt, fam, gateways{d.GatewayEndpoints, d.GatewayEndpointsErr})
	if r := t.sure.Intersect(rs.igw); !r.IsEmpty() {
		return open, append(evidence, rs.igwWhy, fmt.Sprintf("cloud: %s reachable from %s", e.id, pol.Describe(r, maxRanges)))
	}
	if r := t.maybe.Intersect(rs.igw); !r.IsEmpty() {
		return undecided(fmt.Sprintf("%s; reachable from %s only if what was not read allows it", strings.TrimPrefix(rs.igwWhy, "cloud: "), pol.Describe(r, maxRanges)))
	}
	if !t.all().Intersect(rs.appliance).IsEmpty() {
		return undecided(rs.applianceWhy)
	}
	return closed, append(evidence, fmt.Sprintf("cloud: %s: %s has no route to an internet gateway for the addresses allowed in (%s)",
		e.id, deref(rt.RouteTableId), pol.Describe(t.all(), maxRanges)))
}

func prefixed(id string, lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = "cloud: " + id + ": " + strings.TrimPrefix(l, "cloud: ")
	}
	return out
}

// sgResult is what a set of security groups allows to one port and family: sure
// addresses, maybe ones (a prefix list or range that could not be read or parsed may
// hold any address), and one evidence line per group that lets some internet address in.
type sgResult struct {
	sure, maybe reach.Set
	why         []string
}

// sgAllowed judges groups for proto/port. A group that was not read allows everything
// (over-reporting beats under-reporting, as since M5).
func sgAllowed(d HostData, groups []string, proto string, port int, fam reach.Family) sgResult {
	var res sgResult
	for _, id := range groups {
		sg, ok := d.SecurityGroups[id]
		if !ok {
			res.sure = res.sure.Union(reach.All(fam))
			res.why = append(res.why, fmt.Sprintf("cloud: %s not read (assumed open for %s/%d)", id, proto, port))
			continue
		}
		var set, maybe reach.Set
		var unread []string
		add := func(cidr, from string) {
			s, err := parseFamily(cidr, fam)
			if err != nil {
				maybe = reach.All(fam)
				unread = append(unread, fmt.Sprintf("%q%s does not parse", cidr, from))
				return
			}
			set = set.Union(s)
		}
		for _, perm := range sg.IpPermissions {
			if !permMatches(perm, proto, port) {
				continue
			}
			if fam == reach.V4 {
				for _, r := range perm.IpRanges {
					add(deref(r.CidrIp), "")
				}
			} else {
				for _, r := range perm.Ipv6Ranges {
					add(deref(r.CidrIpv6), "")
				}
			}
			for _, ref := range perm.PrefixListIds {
				plID := deref(ref.PrefixListId)
				pl, read := d.PrefixLists[plID]
				switch {
				case !read:
					maybe = reach.All(fam)
					unread = append(unread, "prefix list "+plID+" not read")
				case pl.Err != "":
					maybe = reach.All(fam)
					unread = append(unread, "prefix list "+plID+" not read: "+pl.Err)
				case slices.Contains(pl.CIDRs, ""):
					maybe = reach.All(fam)
					unread = append(unread, "prefix list "+plID+" not read: an entry has no CIDR")
				default:
					for _, c := range pl.CIDRs {
						add(c, " (in "+plID+")")
					}
				}
			}
		}
		res.sure = res.sure.Union(set)
		res.maybe = res.maybe.Union(maybe)
		if ex := d.Policy.Exposed(set); !ex.IsEmpty() {
			res.why = append(res.why, fmt.Sprintf("cloud: %s allows %s/%d from %s", sgName(sg), proto, port, d.Policy.Describe(ex, maxRanges)))
		}
		if len(unread) > 0 {
			res.why = append(res.why, fmt.Sprintf("cloud: %s allows %s/%d from sources not judged (%s)", sgName(sg), proto, port, strings.Join(unread, "; ")))
		}
	}
	return res
}

// sgExposes judges a load balancer's groups over both families: open when they let
// some internet address in, undetermined when only unread sources might.
func sgExposes(d HostData, groups []string, proto string, port int) outcome {
	res := closed
	for _, fam := range []reach.Family{reach.V4, reach.V6} {
		sg := sgAllowed(d, groups, proto, port, fam)
		if !d.Policy.Exposed(sg.sure).IsEmpty() {
			return open
		}
		if !d.Policy.Exposed(sg.maybe).IsEmpty() {
			res = undetermined
		}
	}
	return res
}

// parseFamily parses a CIDR into its set when it is of the family (another family's is
// the empty set; "" is the empty set). One that does not parse is an error: the caller
// cannot tell what it allows.
func parseFamily(cidr string, fam reach.Family) (reach.Set, error) {
	if cidr == "" {
		return reach.Set{}, nil
	}
	pfx, err := parsePrefix(cidr)
	if err != nil {
		return reach.Set{}, err
	}
	if pfx.Addr().Is4() != (fam == reach.V4) {
		return reach.Set{}, nil
	}
	return reach.Prefix(pfx), nil
}

// naclEntries returns one direction's entries of the family in rule-number order, each
// with its CIDR for that family (IPv4 and IPv6 entries share one order).
func naclEntries(acl ec2types.NetworkAcl, egress bool, fam reach.Family) []ec2types.NetworkAclEntry {
	var out []ec2types.NetworkAclEntry
	for _, e := range acl.Entries {
		if (e.Egress != nil && *e.Egress) != egress {
			continue
		}
		cidr := deref(e.CidrBlock)
		if fam == reach.V6 {
			cidr = deref(e.Ipv6CidrBlock)
		}
		if cidr == "" {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return deref32(out[i].RuleNumber) < deref32(out[j].RuleNumber) })
	return out
}

func entryCIDR(e ec2types.NetworkAclEntry, fam reach.Family) string {
	if fam == reach.V6 {
		return deref(e.Ipv6CidrBlock)
	}
	return deref(e.CidrBlock)
}

// entryMatches: protocol -1 is everything; otherwise tcp/udp by name or number within the
// entry's port range.
func entryMatches(e ec2types.NetworkAclEntry, proto string, port int) bool {
	pr := strings.ToLower(deref(e.Protocol))
	if pr == "-1" || pr == "all" {
		return true
	}
	if !protoMatches(pr, proto) {
		return false
	}
	if e.PortRange == nil || e.PortRange.From == nil || e.PortRange.To == nil {
		return true
	}
	return port >= int(*e.PortRange.From) && port <= int(*e.PortRange.To)
}

func ruleName(e ec2types.NetworkAclEntry) string {
	if n := deref32(e.RuleNumber); n != 32767 && n != 32768 {
		return strconv.Itoa(int(n))
	}
	return "*"
}

// decide runs first-match over entries for one protocol and port: each address is
// decided by the first entry whose CIDR holds it. It returns the allowed addresses and,
// per deciding entry, the part of focus it decided.
func decide(entries []ec2types.NetworkAclEntry, fam reach.Family, proto string, port int, focus reach.Set) (reach.Set, []decision, error) {
	remaining := reach.All(fam)
	var allowed reach.Set
	var ds []decision
	for _, e := range entries {
		if !entryMatches(e, proto, port) {
			continue
		}
		set, err := parseFamily(entryCIDR(e, fam), fam)
		if err != nil {
			return reach.Set{}, nil, fmt.Errorf("rule %s: %q does not parse", ruleName(e), entryCIDR(e, fam))
		}
		part := set.Intersect(remaining)
		if part.IsEmpty() {
			continue
		}
		if e.RuleAction == ec2types.RuleActionAllow {
			allowed = allowed.Union(part)
		}
		if f := part.Intersect(focus); !f.IsEmpty() {
			ds = append(ds, decision{e, f})
		}
		remaining = remaining.Subtract(part)
		if remaining.IsEmpty() {
			break
		}
	}
	return allowed, ds, nil
}

type decision struct {
	entry ec2types.NetworkAclEntry
	part  reach.Set
}

// naclInbound returns the addresses the ACL lets in to proto/port and evidence naming
// the entries that decided for the internet addresses in focus (the allowing ones when
// some get in, the denying ones when none do).
func naclInbound(acl ec2types.NetworkAcl, p cloud.Port, fam reach.Family, focus reach.Set, pol reach.Policy) (reach.Set, []string, error) {
	allowed, ds, err := decide(naclEntries(acl, false, fam), fam, p.Proto, p.Port, focus)
	if err != nil {
		return reach.Set{}, nil, err
	}
	let := !allowed.Intersect(focus).IsEmpty()
	var why []string
	for _, d := range ds {
		isAllow := d.entry.RuleAction == ec2types.RuleActionAllow
		if isAllow != let {
			continue
		}
		verb := "denies"
		if isAllow {
			verb = "allows"
		}
		why = append(why, fmt.Sprintf("cloud: %s rule %s %s %s/%d from %s", deref(acl.NetworkAclId), ruleName(d.entry), verb,
			p.Proto, p.Port, describeRule(d.entry, fam, d.part, pol)))
	}
	if !let && len(ds) == 0 {
		why = append(why, fmt.Sprintf("cloud: %s has no inbound rule for %s/%d from the internet (%s) (denied)", deref(acl.NetworkAclId), p.Proto, p.Port, reach.Anywhere(fam)))
	}
	return allowed, why, nil
}

// describeRule names an entry by its own CIDR when it is /0, else by the internet part it
// decided.
func describeRule(e ec2types.NetworkAclEntry, fam reach.Family, part reach.Set, pol reach.Policy) string {
	if c := entryCIDR(e, fam); c == reach.Anywhere(fam) {
		return c
	}
	return pol.Describe(part, maxRanges)
}

// naclReturn returns, over every client port (1-65535), the addresses the ACL's outbound
// entries let replies out to on every ephemeral port (1024-65535: any client), and those
// they let replies out to on at least one port (a client that picks its port).
func naclReturn(acl ec2types.NetworkAcl, fam reach.Family) (every, some reach.Set, err error) {
	entries := naclEntries(acl, true, fam)
	// Every entry boundary starts a segment of ports judged alike.
	starts := []int{portLow, ephemeralLow}
	for _, e := range entries {
		if e.PortRange == nil || e.PortRange.From == nil || e.PortRange.To == nil {
			continue
		}
		for _, b := range []int{int(*e.PortRange.From), int(*e.PortRange.To) + 1} {
			if b > portLow && b <= portHigh {
				starts = append(starts, b)
			}
		}
	}
	sort.Ints(starts)
	every = reach.All(fam)
	for _, port := range slices.Compact(starts) {
		allowed, _, err := decide(entries, fam, "tcp", port, reach.Set{})
		if err != nil {
			return reach.Set{}, reach.Set{}, err
		}
		some = some.Union(allowed)
		if port >= ephemeralLow {
			every = every.Intersect(allowed)
		}
	}
	return every, some, nil
}

// naclReturnPath narrows t to the addresses TCP replies can go back to. Replies allowed
// to every ephemeral port keep their addresses sure; replies allowed only to some ports
// make them maybe (a client can pick such a port, so never closed). ok is false when no
// reply gets out at all (line says why); otherwise line, when set, names the doubt.
func naclReturnPath(acl ec2types.NetworkAcl, fam reach.Family, p cloud.Port, t through, pol reach.Policy) (through, string, bool) {
	id := deref(acl.NetworkAclId)
	every, some, err := naclReturn(acl, fam)
	if err != nil {
		return t.doubt(), id + " outbound: " + err.Error(), true
	}
	all := t.all().Intersect(some)
	if all.IsEmpty() {
		return t, fmt.Sprintf("%s outbound rules let no reply from tcp/%d out to the internet on any port (%d-%d)", id, p.Port, portLow, portHigh), false
	}
	sure := t.sure.Intersect(every)
	next := through{sure: sure, maybe: all.Subtract(sure)}
	if partial := t.sure.Intersect(some).Subtract(every); !partial.IsEmpty() {
		return next, fmt.Sprintf("%s outbound rules let replies from tcp/%d out to %s on some client ports only", id, p.Port, pol.Describe(partial, maxRanges)), true
	}
	return next, "", true
}

// routeTableFor returns the subnet's route table: the one associated with it, else its
// VPC's main table. Associations that are not "associated" (being made, failed, gone)
// are skipped. Without a VPC id the main table cannot be told apart: no table (why says
// so).
func routeTableFor(tables []ec2types.RouteTable, e eniPath) (ec2types.RouteTable, string, bool) {
	for _, t := range tables {
		for _, a := range t.Associations {
			if associated(a) && e.subnet != "" && deref(a.SubnetId) == e.subnet {
				return t, "", true
			}
		}
	}
	if e.vpc == "" {
		return ec2types.RouteTable{}, "no route table associated with " + e.subnet + " and no VPC id to find the main table", false
	}
	for _, t := range tables {
		if deref(t.VpcId) != e.vpc {
			continue
		}
		for _, a := range t.Associations {
			if associated(a) && a.Main != nil && *a.Main {
				return t, "", true
			}
		}
	}
	return ec2types.RouteTable{}, "no route table found for " + e.subnet, false
}

// associated: an association without a state (older responses) counts as associated.
func associated(a ec2types.RouteTableAssociation) bool {
	return a.AssociationState == nil || a.AssociationState.State == "" ||
		a.AssociationState.State == ec2types.RouteTableAssociationStateCodeAssociated
}

type routeKind int

const (
	routeNone routeKind = iota
	routeIGW
	routeAppliance
)

// gateways is the region's confirmed gateway endpoints (see HostData.GatewayEndpoints).
type gateways struct {
	ids map[string]bool
	err string
}

// routeTarget classifies where a route sends replies: an internet gateway; nowhere on
// the internet (local, a NAT gateway — replies would leave from another address —, an
// egress-only gateway, a peering, a blackhole, a confirmed S3/DynamoDB gateway endpoint,
// which delivers only to its service); or anything else, which may forward them to the
// internet (any other vpce-: a firewall or Gateway Load Balancer endpoint, or a gateway
// endpoint the region's endpoint read did not confirm; an appliance, a transit, VPN,
// local or carrier gateway, a core network, a target this code does not know).
func routeTarget(r ec2types.Route, gw gateways) (routeKind, string) {
	if r.State == ec2types.RouteStateBlackhole {
		return routeNone, "blackhole"
	}
	switch g := deref(r.GatewayId); {
	case strings.HasPrefix(g, "igw-"):
		return routeIGW, g
	case g == "local", strings.HasPrefix(g, "nat-"), strings.HasPrefix(g, "eigw-"):
		return routeNone, g
	case strings.HasPrefix(g, "vpce-") && gw.ids[g]:
		return routeNone, g
	case strings.HasPrefix(g, "vpce-") && gw.err != "":
		return routeAppliance, g + " (gateway endpoints not read: " + gw.err + ")"
	case g != "":
		return routeAppliance, g // vpce-, vgw-, and any other gateway
	}
	for _, t := range []*string{r.NatGatewayId, r.EgressOnlyInternetGatewayId, r.VpcPeeringConnectionId} {
		if s := deref(t); s != "" {
			return routeNone, s
		}
	}
	for _, t := range []*string{r.NetworkInterfaceId, r.InstanceId, r.TransitGatewayId, r.LocalGatewayId, r.CarrierGatewayId, r.CoreNetworkArn} {
		if s := deref(t); s != "" {
			return routeAppliance, s
		}
	}
	return routeAppliance, "an unknown target"
}

// routes is a table's judgement for one family: the destinations it sends to an internet
// gateway and those it sends to something that may forward to one, with an evidence line
// for each.
type routes struct {
	igw, appliance       reach.Set
	igwWhy, applianceWhy string
}

// routeSets judges rt by longest-prefix match. A prefix-list route to a confirmed gateway
// endpoint is not the internet (ignored, like one to a NAT gateway). One to an internet
// gateway or an appliance may cover any destination, more specific than any CIDR route
// (its ranges are not read), so it makes every destination an appliance one: the path is
// then open only through a CIDR route to an internet gateway, otherwise undetermined. So
// does a destination that does not parse.
func routeSets(rt ec2types.RouteTable, fam reach.Family, gw gateways) routes {
	type route struct {
		bits   int
		set    reach.Set
		kind   routeKind
		target string
		dest   string
	}
	var rs []route
	var out routes
	id := deref(rt.RouteTableId)
	anywhere := func(why string) {
		out.appliance = reach.All(fam)
		if out.applianceWhy == "" {
			out.applianceWhy = why
		}
	}
	for _, r := range rt.Routes {
		dest := deref(r.DestinationCidrBlock)
		if fam == reach.V6 {
			dest = deref(r.DestinationIpv6CidrBlock)
		}
		kind, target := routeTarget(r, gw)
		if dest == "" {
			if pl := deref(r.DestinationPrefixListId); pl != "" && kind != routeNone {
				anywhere(fmt.Sprintf("%s routes prefix list %s to %s (its ranges are not read)", id, pl, target))
			}
			continue
		}
		pfx, err := parsePrefix(dest)
		if err != nil {
			if kind != routeNone {
				anywhere(fmt.Sprintf("%s routes %q to %s, which does not parse", id, dest, target))
			}
			continue
		}
		if pfx.Addr().Is4() != (fam == reach.V4) {
			continue
		}
		rs = append(rs, route{pfx.Bits(), reach.Prefix(pfx), kind, target, dest})
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].bits > rs[j].bits })
	var covered reach.Set
	for _, r := range rs {
		part := r.set.Subtract(covered)
		covered = covered.Union(r.set)
		switch r.kind {
		case routeIGW:
			out.igw = out.igw.Union(part)
			if out.igwWhy == "" {
				out.igwWhy = fmt.Sprintf("cloud: %s routes %s to %s", id, r.dest, r.target)
			}
		case routeAppliance:
			out.appliance = out.appliance.Union(part)
			if out.applianceWhy == "" {
				out.applianceWhy = fmt.Sprintf("%s routes %s to %s, which may forward replies to the internet", id, r.dest, r.target)
			}
		}
	}
	return out
}
