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

// outcome is a path's verdict: closed, undetermined (the data cannot decide; the listener
// keeps its level) or open.
type outcome int

const (
	closed outcome = iota
	undetermined
	open
)

// ephemeralLow..ephemeralHigh are the client ports TCP replies go back to (any OS).
const ephemeralLow, ephemeralHigh = 1024, 65535

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

func familyPath(d HostData, e eniPath, fam reach.Family, p cloud.Port) (outcome, []string) {
	pol := d.Policy
	allowed, sgWhy := sgAllowed(d, e.groups, p.Proto, p.Port, fam)
	exposed := pol.Exposed(allowed)
	if exposed.IsEmpty() {
		line := fmt.Sprintf("cloud: %s: no security group allows %s/%d from the internet (%s)", e.id, p.Proto, p.Port, reach.Anywhere(fam))
		if !allowed.IsEmpty() {
			line += "; allowed only from private or VPN ranges"
		}
		return closed, []string{line}
	}
	evidence := sgWhy
	acl, read := d.NACLs[e.subnet]
	if !read {
		evidence = append(evidence, "cloud: nacl for "+e.subnet+" not read (assumed open)")
	} else {
		in, inWhy := naclInbound(acl, p, fam, exposed, pol)
		exposed = exposed.Intersect(in)
		if exposed.IsEmpty() {
			return closed, prefixed(e.id, inWhy)
		}
		evidence = append(evidence, inWhy...)
		if p.Proto == "tcp" {
			out := naclReturn(acl, fam)
			if exposed.Intersect(out).IsEmpty() {
				return closed, []string{fmt.Sprintf("cloud: %s: %s outbound rules let no reply from tcp/%d reach the internet's ephemeral ports (%d-%d)",
					e.id, deref(acl.NetworkAclId), p.Port, ephemeralLow, ephemeralHigh)}
			}
			exposed = exposed.Intersect(out)
		}
	}
	if d.RoutesErr != "" {
		return undetermined, []string{cloud.UndeterminedEvidence + " (" + e.id + ": route tables not read: " + d.RoutesErr + ")"}
	}
	rt, ok := routeTableFor(d.RouteTables, e)
	if !ok {
		return undetermined, []string{cloud.UndeterminedEvidence + " (" + e.id + ": no route table found for " + e.subnet + ")"}
	}
	igw, appliance, igwWhy, applianceWhy := routeSets(rt, fam)
	if r := exposed.Intersect(igw); !r.IsEmpty() {
		return open, append(evidence, igwWhy, fmt.Sprintf("cloud: %s reachable from %s", e.id, pol.Describe(r, maxRanges)))
	}
	if !exposed.Intersect(appliance).IsEmpty() {
		return undetermined, []string{cloud.UndeterminedEvidence + " (" + e.id + ": " + applianceWhy + ")"}
	}
	return closed, []string{fmt.Sprintf("cloud: %s: %s has no route to an internet gateway for the addresses allowed in (%s)",
		e.id, deref(rt.RouteTableId), reach.Anywhere(fam))}
}

func prefixed(id string, lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = "cloud: " + id + ": " + strings.TrimPrefix(l, "cloud: ")
	}
	return out
}

// sgAllowed returns the family's addresses that any of groups allows to proto/port, and
// one evidence line per group that allows some internet address. A group that was not
// read allows everything (over-reporting beats under-reporting).
func sgAllowed(d HostData, groups []string, proto string, port int, fam reach.Family) (reach.Set, []string) {
	var all reach.Set
	var why []string
	for _, id := range groups {
		sg, ok := d.SecurityGroups[id]
		if !ok {
			all = all.Union(reach.All(fam))
			why = append(why, fmt.Sprintf("cloud: %s not read (assumed open for %s/%d)", id, proto, port))
			continue
		}
		var set reach.Set
		for _, perm := range sg.IpPermissions {
			if !permMatches(perm, proto, port) {
				continue
			}
			if fam == reach.V4 {
				for _, r := range perm.IpRanges {
					set = set.Union(cidrSet(deref(r.CidrIp), fam))
				}
			} else {
				for _, r := range perm.Ipv6Ranges {
					set = set.Union(cidrSet(deref(r.CidrIpv6), fam))
				}
			}
		}
		all = all.Union(set)
		if ex := d.Policy.Exposed(set); !ex.IsEmpty() {
			why = append(why, fmt.Sprintf("cloud: %s allows %s/%d from %s", sgName(sg), proto, port, d.Policy.Describe(ex, maxRanges)))
		}
	}
	return all, why
}

// sgExposes reports whether groups let some internet address in (load balancers: IPv4).
func sgExposes(d HostData, groups []string, proto string, port int) bool {
	allowed, _ := sgAllowed(d, groups, proto, port, reach.V4)
	return !d.Policy.Exposed(allowed).IsEmpty()
}

// cidrSet parses one family's CIDR; anything else is the empty set.
func cidrSet(cidr string, fam reach.Family) reach.Set {
	if cidr == "" {
		return reach.Set{}
	}
	s, err := parseFamily(cidr, fam)
	if err != nil {
		return reach.Set{}
	}
	return s
}

func parseFamily(cidr string, fam reach.Family) (reach.Set, error) {
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
func decide(entries []ec2types.NetworkAclEntry, fam reach.Family, proto string, port int, focus reach.Set) (reach.Set, []decision) {
	remaining := reach.All(fam)
	var allowed reach.Set
	var ds []decision
	for _, e := range entries {
		if !entryMatches(e, proto, port) {
			continue
		}
		part := cidrSet(entryCIDR(e, fam), fam).Intersect(remaining)
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
	return allowed, ds
}

type decision struct {
	entry ec2types.NetworkAclEntry
	part  reach.Set
}

// naclInbound returns the addresses the ACL lets in to proto/port and evidence naming
// the entries that decided for the internet addresses in focus (the allowing ones when
// some get in, the denying ones when none do).
func naclInbound(acl ec2types.NetworkAcl, p cloud.Port, fam reach.Family, focus reach.Set, pol reach.Policy) (reach.Set, []string) {
	allowed, ds := decide(naclEntries(acl, false, fam), fam, p.Proto, p.Port, focus)
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
	return allowed, why
}

// describeRule names an entry by its own CIDR when it is /0, else by the internet part it
// decided.
func describeRule(e ec2types.NetworkAclEntry, fam reach.Family, part reach.Set, pol reach.Policy) string {
	if c := entryCIDR(e, fam); c == reach.Anywhere(fam) {
		return c
	}
	return pol.Describe(part, maxRanges)
}

// naclReturn returns the addresses some TCP reply may go back to: those that the ACL's
// outbound entries let out on at least one ephemeral port.
func naclReturn(acl ec2types.NetworkAcl, fam reach.Family) reach.Set {
	entries := naclEntries(acl, true, fam)
	// Every entry boundary inside the ephemeral range starts a segment judged alike.
	starts := []int{ephemeralLow}
	for _, e := range entries {
		if e.PortRange == nil || e.PortRange.From == nil || e.PortRange.To == nil {
			continue
		}
		for _, b := range []int{int(*e.PortRange.From), int(*e.PortRange.To) + 1} {
			if b > ephemeralLow && b <= ephemeralHigh {
				starts = append(starts, b)
			}
		}
	}
	sort.Ints(starts)
	var out reach.Set
	for _, port := range slices.Compact(starts) {
		allowed, _ := decide(entries, fam, "tcp", port, reach.Set{})
		out = out.Union(allowed)
	}
	return out
}

// routeTableFor returns the subnet's route table: the one associated with it, else its
// VPC's main table.
func routeTableFor(tables []ec2types.RouteTable, e eniPath) (ec2types.RouteTable, bool) {
	for _, t := range tables {
		for _, a := range t.Associations {
			if deref(a.SubnetId) == e.subnet && e.subnet != "" {
				return t, true
			}
		}
	}
	for _, t := range tables {
		if e.vpc != "" && deref(t.VpcId) != e.vpc {
			continue
		}
		for _, a := range t.Associations {
			if a.Main != nil && *a.Main {
				return t, true
			}
		}
	}
	return ec2types.RouteTable{}, false
}

type routeKind int

const (
	routeNone routeKind = iota
	routeIGW
	routeAppliance
)

// routeTarget classifies where a route sends replies: an internet gateway; something
// that may forward them to the internet (an appliance, firewall or gateway-LB endpoint, a
// transit gateway, a local or carrier gateway, a core network); or nowhere on the
// internet (local, a NAT gateway — replies would leave from another address —, an
// egress-only gateway, a VPN gateway, a peering, a blackhole).
func routeTarget(r ec2types.Route) (routeKind, string) {
	if r.State == ec2types.RouteStateBlackhole {
		return routeNone, "blackhole"
	}
	switch g := deref(r.GatewayId); {
	case strings.HasPrefix(g, "igw-"):
		return routeIGW, g
	case strings.HasPrefix(g, "vpce-"):
		return routeAppliance, g
	case g != "":
		return routeNone, g // local, vgw-
	}
	for _, t := range []*string{r.NetworkInterfaceId, r.InstanceId, r.TransitGatewayId, r.LocalGatewayId, r.CarrierGatewayId, r.CoreNetworkArn} {
		if s := deref(t); s != "" {
			return routeAppliance, s
		}
	}
	for _, t := range []*string{r.NatGatewayId, r.EgressOnlyInternetGatewayId, r.VpcPeeringConnectionId} {
		if s := deref(t); s != "" {
			return routeNone, s
		}
	}
	return routeAppliance, "an unknown target"
}

// routeSets returns, by longest-prefix match, the family's destinations the table sends
// to an internet gateway and those it sends to something that may forward to one, with
// an evidence line for each. A prefix-list route to either may cover any destination, so
// it adds the family's addresses not decided by a CIDR route to the appliance set.
func routeSets(rt ec2types.RouteTable, fam reach.Family) (igw, appliance reach.Set, igwWhy, applianceWhy string) {
	type route struct {
		bits   int
		set    reach.Set
		kind   routeKind
		target string
		dest   string
	}
	var rs []route
	prefixList := false
	plTarget := ""
	for _, r := range rt.Routes {
		dest := deref(r.DestinationCidrBlock)
		if fam == reach.V6 {
			dest = deref(r.DestinationIpv6CidrBlock)
		}
		kind, target := routeTarget(r)
		if dest == "" {
			if deref(r.DestinationPrefixListId) != "" && kind != routeNone {
				prefixList, plTarget = true, target
			}
			continue
		}
		pfx, err := parsePrefix(dest)
		if err != nil || pfx.Addr().Is4() != (fam == reach.V4) {
			continue
		}
		rs = append(rs, route{pfx.Bits(), reach.Prefix(pfx), kind, target, dest})
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].bits > rs[j].bits })
	var covered reach.Set
	id := deref(rt.RouteTableId)
	for _, r := range rs {
		part := r.set.Subtract(covered)
		covered = covered.Union(r.set)
		switch r.kind {
		case routeIGW:
			igw = igw.Union(part)
			if igwWhy == "" {
				igwWhy = fmt.Sprintf("cloud: %s routes %s to %s", id, r.dest, r.target)
			}
		case routeAppliance:
			appliance = appliance.Union(part)
			if applianceWhy == "" {
				applianceWhy = fmt.Sprintf("%s routes %s to %s, which may forward replies to the internet", id, r.dest, r.target)
			}
		}
	}
	if prefixList {
		appliance = appliance.Union(reach.All(fam).Subtract(covered))
		if applianceWhy == "" {
			applianceWhy = fmt.Sprintf("%s routes a prefix list to %s (its ranges are not read)", id, plTarget)
		}
	}
	return igw, appliance, igwWhy, applianceWhy
}
