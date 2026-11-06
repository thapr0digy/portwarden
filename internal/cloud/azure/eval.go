// Package azure is the Azure cloud look-up (M10 phase 3): a VM's network interfaces,
// their public IPs, and the network security groups (NSGs) on their subnets and on the
// NICs themselves, read over plain HTTPS from Azure Resource Manager (client.go) and
// judged here, purely, with the shared reach rule.
//
// Order (docs "How network security groups filter network traffic"): inbound traffic
// passes the subnet's NSG, then the NIC's; both must allow it. A layer without an NSG
// does not filter, but a Standard public IP with no NSG on either layer is closed to
// inbound traffic (a Basic one is open). Within an NSG, rules are taken by priority, the
// lowest number first, the default rules (65000+) after the user's; the first rule that
// matches decides. Rules see the VM's private address as the destination (Azure translates
// the public IP first).
//
// What cannot be resolved is never guessed: a service tag missing from the location's
// list (or a list not read), a destination tag, an unknown protocol or access, a range
// that does not parse, a rule limiting client source ports, a layer that could not be
// read. Such rules may or may not match, so each path ends with sure addresses (open),
// maybe ones (undetermined: the listener keeps its level) or none (closed).
package azure

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// HostData is everything fetched about one VM. Maps are keyed by lowercased resource id.
type HostData struct {
	VM        VM
	NICs      []NICData
	PublicIPs map[string]PublicIP
	Subnets   map[string]Subnet
	NSGs      map[string]NSG
	// Errs says why a followed resource was not read (its layer is then undetermined).
	Errs map[string]string
	// Tags is the location's service-tag list, nil when not read (TagsErr says why) or
	// not needed.
	Tags     TagSet
	TagsErr  string
	Location string
	// TooManyConfigs: the VM has more than maxIPConfigs IP configurations.
	TooManyConfigs bool
	Policy         reach.Policy
}

// NICData is one NIC, or why it was not read.
type NICData struct {
	ID  string
	NIC *NIC
	Err string
}

// maxRanges bounds the ranges an evidence line names.
const maxRanges = 4

// clientPortLow is the lowest port ordinary clients pick as their source port.
const clientPortLow = 1024

// tagRe is a service-tag name (AzureCloud, Storage.WestEurope, AzureFrontDoor.Backend).
var tagRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)

// Evaluate judges each port against d.
func Evaluate(d HostData, ports []cloud.Port) []cloud.Verdict {
	out := make([]cloud.Verdict, 0, len(ports))
	for _, p := range ports {
		out = append(out, evaluatePort(d, p))
	}
	return out
}

func evaluatePort(d HostData, p cloud.Port) cloud.Verdict {
	v := cloud.Verdict{Key: p.Key, Complete: true}
	undecided := func(reason string) cloud.Verdict {
		v.Complete = false
		v.Evidence = []string{cloud.UndeterminedEvidence + " (" + reason + ")"}
		return v
	}
	switch n := len(d.VM.Properties.NetworkProfile.NetworkInterfaces); {
	case n == 0:
		return undecided("virtualMachines/get returned no network interfaces")
	case n > maxNICs:
		return undecided(fmt.Sprintf("VM has %d network interfaces (more than %d)", n, maxNICs))
	case d.TooManyConfigs:
		return undecided(fmt.Sprintf("VM has more than %d IP configurations", maxIPConfigs))
	}
	var lines []string
	reachable, public := false, false
	for _, pa := range paths(d, p) {
		lines = append(lines, pa.lines...)
		public = public || pa.public || pa.backend
		switch {
		case pa.res == reach.Open && pa.public && p.AgentLevel >= cloud.LevelHostFirewallOpen:
			v.Open = true
			v.Evidence = pa.lines
			return v
		case pa.res == reach.Closed:
		case pa.res == reach.Open && pa.public:
			// The host firewall may admit only a load balancer's traffic.
			reachable = true
			lines = append(lines, cloud.UndeterminedEvidence+" ("+pa.id+": direct path not counted (host firewall does not allow 0/0); may be reachable via a load balancer, not read)")
		default:
			reachable = true
		}
	}
	if !public && !reachable {
		lines = append(lines, "cloud: VM has no public IPv4 or IPv6 address and is in no load balancer or application gateway backend")
	}
	v.Evidence = lines
	if reachable {
		v.Complete = false // undetermined: neither raises nor lowers
	}
	return v
}

// path is one IP configuration's judgement (each configuration has one family).
// public: it has a public IP of its family (a direct path); backend: it is in a load
// balancer, NAT rule or application gateway backend.
type path struct {
	id              string
	public, backend bool
	res             reach.Outcome
	lines           []string
}

// target is an IP configuration and its NIC.
type target struct {
	nic *NIC
	cfg IPConfig
}

// paths judges every IP configuration the listener can be reached on.
func paths(d HostData, p cloud.Port) []path {
	var out []path
	for _, nd := range d.NICs {
		if nd.NIC == nil {
			id := "NIC " + lastSegment(nd.ID)
			out = append(out, path{id: id, res: reach.Undetermined,
				lines: []string{cloud.UndeterminedEvidence + " (" + id + ": not read: " + nd.Err + ")"}})
		}
	}
	for _, t := range targetsFor(d, p.Addr) {
		out = append(out, judgeConfig(d, t, p))
	}
	return out
}

// targetsFor returns the IP configurations a listener can be reached on: the one whose
// private address it is bound to, else (a wildcard or another address) all of them.
func targetsFor(d HostData, bind string) []target {
	var all []target
	for _, nd := range d.NICs {
		if nd.NIC == nil {
			continue
		}
		for _, c := range nd.NIC.Properties.IPConfigurations {
			all = append(all, target{nd.NIC, c})
		}
	}
	a, err := netip.ParseAddr(bind)
	if err == nil && !a.IsUnspecified() {
		a = a.Unmap()
		for _, t := range all {
			if own, err := netip.ParseAddr(t.cfg.Properties.PrivateIPAddress); err == nil && own.Unmap() == a {
				return []target{t}
			}
		}
	}
	return all
}

func family(c IPConfig) reach.Family {
	if strings.EqualFold(c.Properties.PrivateIPAddressVersion, "IPv6") {
		return reach.V6
	}
	if a, err := netip.ParseAddr(c.Properties.PrivateIPAddress); err == nil && a.Is6() && !a.Is4In6() {
		return reach.V6
	}
	return reach.V4
}

// publicState is an IP configuration's public address: none, read (addr), or unread.
type publicState struct {
	addr, sku, unread string
	has               bool
}

func publicOf(d HostData, c IPConfig, fam reach.Family) publicState {
	ref := c.Properties.PublicIPAddress
	if ref == nil {
		return publicState{}
	}
	k := key(ref.ID)
	if e, failed := d.Errs[k]; failed {
		return publicState{unread: e}
	}
	pip, ok := d.PublicIPs[k]
	if !ok {
		return publicState{unread: "not read"}
	}
	a, err := netip.ParseAddr(pip.Properties.IPAddress)
	if err != nil {
		return publicState{} // not allocated (a dynamic IP of a stopped VM)
	}
	if (fam == reach.V6) != (a.Is6() && !a.Is4In6()) {
		return publicState{}
	}
	return publicState{addr: a.String(), sku: pip.SKU.Name, has: true}
}

// layer is one NSG layer's judgement for a path.
type layer struct {
	name                 string // "subnet NSG web-subnet-nsg", "no NSG on the NIC"
	absent               bool
	sure, maybe          reach.Set
	allowBy, denyBy, why []labelled
}

func judgeConfig(d HostData, t target, p cloud.Port) path {
	fam := family(t.cfg)
	pub := publicOf(d, t.cfg, fam)
	nicName := t.nic.Name
	if nicName == "" {
		nicName = lastSegment(t.nic.ID)
	}
	pa := path{id: nicName + "/" + t.cfg.Name, public: pub.has, backend: t.cfg.inBackend()}
	switch {
	case pub.has:
		pa.id += " (" + pub.addr + ")"
	case pub.unread != "":
		pa.id += " (public IP not read)"
	default:
		pa.id += fmt.Sprintf(" (no public IPv%d address)", fam)
	}
	private, _ := netip.ParseAddr(t.cfg.Properties.PrivateIPAddress)
	start := d.Policy.Internet(fam)

	var subnet, nic layer
	if t.cfg.Properties.Subnet == nil {
		subnet = unreadLayer("subnet", "the IP configuration names no subnet", start)
	} else if e, failed := d.Errs[key(t.cfg.Properties.Subnet.ID)]; failed {
		subnet = unreadLayer("subnet", "subnet not read: "+e, start)
	} else if s, ok := d.Subnets[key(t.cfg.Properties.Subnet.ID)]; !ok {
		subnet = unreadLayer("subnet", "subnet not read", start)
	} else {
		subnet = nsgLayer(d, "subnet", s.Properties.NetworkSecurityGroup, t.cfg, private, fam, p, start)
	}
	nic = nsgLayer(d, "NIC", t.nic.Properties.NetworkSecurityGroup, t.cfg, private, fam, p, start)

	what := fmt.Sprintf("%s/%d", p.Proto, p.Port)
	if subnet.absent && nic.absent && pub.has {
		switch {
		case strings.EqualFold(pub.sku, "Standard"):
			pa.res = reach.Closed
			pa.lines = []string{fmt.Sprintf("cloud: %s: Standard public IP with no NSG on the subnet or NIC: closed to inbound traffic", pa.id)}
			return pa
		case strings.EqualFold(pub.sku, "Basic"):
			pa.res = reach.Open
			pa.lines = []string{fmt.Sprintf("cloud: %s: Basic public IP with no NSG on the subnet or NIC: %s open from %s", pa.id, what, d.Policy.Describe(start, maxRanges)),
				fmt.Sprintf("cloud: %s reachable from %s", pa.id, d.Policy.Describe(start, maxRanges))}
			return pa
		default:
			pa.res = reach.Undetermined
			pa.lines = []string{fmt.Sprintf("%s (%s: no NSG on the subnet or NIC, and the public IP's SKU %q is not known)", cloud.UndeterminedEvidence, pa.id, pub.sku)}
			return pa
		}
	}

	sure := subnet.sure.Intersect(nic.sure)
	passable := subnet.sure.Union(subnet.maybe).Intersect(nic.sure.Union(nic.maybe))
	maybe := passable.Subtract(sure)
	switch {
	case !sure.IsEmpty():
		pa.res = reach.Open
	case !maybe.IsEmpty():
		pa.res = reach.Undetermined
	default:
		pa.res = reach.Closed
	}
	if pa.res == reach.Closed {
		var by []string
		for _, l := range []layer{subnet, nic} {
			for _, dn := range l.denyBy {
				if !dn.set.Intersect(start).IsEmpty() {
					by = append(by, dn.label)
				}
			}
		}
		line := fmt.Sprintf("cloud: %s: no rule lets %s in from the internet (%s) through both NSG layers", pa.id, what, reach.Anywhere(fam))
		if len(by) > 0 {
			line += "; denied by " + strings.Join(by, ", ")
		}
		pa.lines = []string{line}
		return pa
	}
	// Firewalls let something in; whether the internet can reach it depends on the path.
	switch {
	case pub.has:
	case pub.unread != "":
		pa.res = reach.Undetermined
		pa.lines = []string{fmt.Sprintf("%s (%s: internet sources get through its NSGs, and its public IP was not read: %s)", cloud.UndeterminedEvidence, pa.id, pub.unread)}
		return pa
	case pa.backend:
		pa.res = reach.Undetermined
		pa.lines = []string{fmt.Sprintf("%s (%s: internet sources get through its NSGs; it is in a load balancer, NAT rule or application gateway backend, not read)", cloud.UndeterminedEvidence, pa.id)}
		return pa
	default:
		pa.res = reach.Closed
		pa.lines = []string{fmt.Sprintf("cloud: %s: no public IPv%d address and in no load balancer or application gateway backend", pa.id, fam)}
		return pa
	}
	if pa.res == reach.Open {
		for _, l := range []layer{subnet, nic} {
			if l.absent {
				pa.lines = append(pa.lines, fmt.Sprintf("cloud: %s: %s", pa.id, l.name))
				continue
			}
			for _, a := range l.allowBy {
				if part := a.set.Intersect(sure); !part.IsEmpty() {
					pa.lines = append(pa.lines, fmt.Sprintf("cloud: %s: %s allows %s from %s", pa.id, a.label, what, d.Policy.Describe(part, maxRanges)))
				}
			}
		}
		pa.lines = append(pa.lines, fmt.Sprintf("cloud: %s reachable from %s", pa.id, d.Policy.Describe(sure, maxRanges)))
		return pa
	}
	var reasons []string
	for _, l := range []layer{subnet, nic} {
		for _, w := range l.why {
			if !w.set.Intersect(maybe).IsEmpty() && !slices.Contains(reasons, w.label) {
				reasons = append(reasons, w.label)
			}
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "rules that may or may not match disagree")
	}
	pa.lines = []string{fmt.Sprintf("%s (%s: %s allowed from %s only if %s)", cloud.UndeterminedEvidence, pa.id, what,
		d.Policy.Describe(maybe, maxRanges), strings.Join(reasons, "; "))}
	return pa
}

func unreadLayer(where, reason string, start reach.Set) layer {
	return layer{name: where, maybe: start, why: []labelled{{where + " " + reason, start}}}
}

// nsgLayer judges one layer: no NSG (allows everything), an NSG not read (maybe), or
// the NSG's rules.
func nsgLayer(d HostData, where string, ref *Ref, cfg IPConfig, private netip.Addr, fam reach.Family, p cloud.Port, start reach.Set) layer {
	if ref == nil {
		return layer{name: "no NSG on the " + where, absent: true, sure: start}
	}
	k := key(ref.ID)
	if e, failed := d.Errs[k]; failed {
		return unreadLayer(where, "NSG "+lastSegment(ref.ID)+" not read: "+e, start)
	}
	nsg, ok := d.NSGs[k]
	if !ok {
		return unreadLayer(where, "NSG "+lastSegment(ref.ID)+" not read", start)
	}
	name := nsg.Name
	if name == "" {
		name = lastSegment(ref.ID)
	}
	l := layer{name: where + " NSG " + name}
	rules := compileNSG(d, where+" NSG "+name, nsg, cfg, private, fam, p)
	l.walk(rules, start)
	return l
}

// rule is a compiled NSG rule for one path and port.
type rule struct {
	label       string
	access      string // "allow", "deny" or the raw value
	prio        int
	sure, maybe reach.Set
	reason      string
	tie         bool
}

func (r *rule) demote(reason string) {
	r.maybe = r.maybe.Union(r.sure)
	r.sure = reach.Set{}
	if r.reason == "" {
		r.reason = reason
	} else if !strings.Contains(r.reason, reason) {
		r.reason += "; " + reason
	}
}

// tri is yes, no or maybe.
type tri int

const (
	triNo tri = iota
	triMaybe
	triYes
)

func compileNSG(d HostData, label string, nsg NSG, cfg IPConfig, private netip.Addr, fam reach.Family, p cloud.Port) []rule {
	var out []rule
	for _, sr := range slices.Concat(nsg.Properties.SecurityRules, nsg.Properties.DefaultSecurityRules) {
		pr := sr.Properties
		r := rule{label: fmt.Sprintf("%s rule %s (priority %d)", label, sr.Name, pr.Priority), prio: pr.Priority}
		oddDirection := false
		switch {
		case strings.EqualFold(pr.Direction, "Inbound"):
		case strings.EqualFold(pr.Direction, "Outbound"):
			continue
		default:
			oddDirection = true
		}
		switch strings.ToLower(pr.Access) {
		case "allow", "deny":
			r.access = strings.ToLower(pr.Access)
		default:
			r.access = pr.Access
		}
		pm := protoMatch(pr.Protocol, p.Proto)
		if pm == triNo {
			continue
		}
		dp := portsMatch(pr.DestinationPortRange, pr.DestinationPortRanges, p.Port)
		if dp == triNo {
			continue
		}
		dest := destMatch(pr.DestinationAddressPrefix, pr.DestinationAddressPrefixes, pr.DestinationApplicationSecurityGroups, cfg, private)
		if dest == triNo {
			continue
		}
		var srcTags []string
		r.sure, r.maybe, srcTags = sourceSets(d, r.label, sr, fam, &r.reason)
		if len(srcTags) > 0 {
			r.label += " (service tag " + strings.Join(srcTags, ", ") + ")"
		}
		if pm == triMaybe {
			r.demote(r.label + ": protocol " + strconv.Quote(pr.Protocol) + " not understood")
		}
		if dp == triMaybe {
			r.demote(r.label + ": destination ports not understood")
		}
		if dest == triMaybe {
			r.demote(r.label + ": destination " + destDescribe(pr.DestinationAddressPrefix, pr.DestinationAddressPrefixes) + " may or may not be this VM")
		}
		if sp := clientPorts(pr.SourcePortRange, pr.SourcePortRanges); sp != triYes {
			r.demote(r.label + ": allows only some client source ports")
		}
		if oddDirection {
			r.demote(r.label + ": direction " + strconv.Quote(truncate(pr.Direction, 20)) + " not understood")
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].prio < out[j].prio })
	for i := range out {
		for j := range out {
			if i != j && out[i].prio == out[j].prio && out[i].access != out[j].access {
				out[i].tie = true
				if out[i].reason == "" {
					out[i].reason = out[i].label + ": another rule has the same priority"
				}
			}
		}
	}
	return out
}

// walk evaluates the rules in priority order. live is what is still being evaluated; a
// rule's sure hits leave it, its maybe hits stay (where the rule did not match they go
// on). Anything left at the end meets the default deny.
func (l *layer) walk(rules []rule, start reach.Set) {
	live := start
	var allowed, denied reach.Set
	for _, r := range rules {
		var hit, may reach.Set
		if r.tie {
			may = live.Intersect(r.sure.Union(r.maybe))
		} else {
			hit = live.Intersect(r.sure)
			may = live.Intersect(r.maybe).Subtract(hit)
		}
		all := hit.Union(may)
		if all.IsEmpty() {
			continue
		}
		if !may.IsEmpty() {
			l.why = add(l.why, r.reason, may)
		}
		switch r.access {
		case "allow":
			allowed = allowed.Union(all)
			l.allowBy = add(l.allowBy, r.label, all)
		case "deny":
			denied = denied.Union(all)
			l.denyBy = add(l.denyBy, r.label, all)
		default:
			allowed = allowed.Union(all)
			denied = denied.Union(all)
			l.why = add(l.why, r.label+" has access "+strconv.Quote(r.access)+", which is not understood", all)
		}
		live = live.Subtract(hit)
	}
	denied = denied.Union(live)
	l.denyBy = add(l.denyBy, "no rule matched (deny)", live)
	l.sure = allowed.Subtract(denied)
	l.maybe = allowed.Intersect(denied)
}

type labelled struct {
	label string
	set   reach.Set
}

func add(list []labelled, label string, s reach.Set) []labelled {
	if s.IsEmpty() {
		return list
	}
	for i := range list {
		if list[i].label == label {
			list[i].set = list[i].set.Union(s)
			return list
		}
	}
	return append(list, labelled{label, s})
}

// builtinSource judges the sources known without the service-tag list: "*", "Any" and
// "Internet" are every address; "VirtualNetwork" and "AzureLoadBalancer" are never the
// internet (the M10 phase 3 decision).
func builtinSource(s string) (all bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "*", "any", "internet":
		return true, true
	case "virtualnetwork", "azureloadbalancer":
		return false, true
	}
	return false, false
}

func sources(r SecurityRule) []string {
	pr := r.Properties
	var out []string
	if pr.SourceAddressPrefix != "" {
		out = append(out, pr.SourceAddressPrefix)
	}
	return append(out, pr.SourceAddressPrefixes...)
}

// sourceSets is the rule's source addresses of the family: the sure part and the part
// that may match (a tag not listed, a list not read, a range that does not parse), and
// the service tags it resolved through the list.
func sourceSets(d HostData, label string, r SecurityRule, fam reach.Family, reason *string) (sure, maybe reach.Set, tags []string) {
	all := reach.All(fam)
	note := func(why string) {
		maybe = all
		if *reason == "" {
			*reason = label + ": " + why
		} else if !strings.Contains(*reason, why) {
			*reason += "; " + why
		}
	}
	srcs := sources(r)
	if len(srcs) == 0 && len(r.Properties.SourceApplicationSecurityGroups) == 0 {
		note("no source address prefix")
	}
	// sourceApplicationSecurityGroups name VMs: never internet traffic.
	for _, s := range srcs {
		s = strings.TrimSpace(s)
		if isAll, ok := builtinSource(s); ok {
			if isAll {
				sure = sure.Union(all)
			}
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			if pfx.Addr().Is4() == (fam == reach.V4) {
				sure = sure.Union(reach.Prefix(pfx.Masked()))
			}
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			if a.Is4() == (fam == reach.V4) {
				sure = sure.Union(reach.Prefix(netip.PrefixFrom(a, a.BitLen())))
			}
			continue
		}
		if !tagRe.MatchString(s) {
			note(fmt.Sprintf("source %q does not parse", truncate(s, 60)))
			continue
		}
		if d.Tags == nil {
			why := "service tags not read"
			if d.TagsErr != "" {
				why += ": " + d.TagsErr
			}
			note(fmt.Sprintf("names service tag %s (%s)", s, why))
			continue
		}
		prefixes, found := d.Tags.lookup(s)
		if !found {
			note(fmt.Sprintf("names service tag %s, not in the %s list", s, d.Location))
			continue
		}
		tags = append(tags, s)
		for _, c := range prefixes {
			pfx, err := netip.ParsePrefix(c)
			if err != nil {
				note(fmt.Sprintf("service tag %s holds %q, which does not parse", s, truncate(c, 60)))
				continue
			}
			if pfx.Addr().Is4() == (fam == reach.V4) {
				sure = sure.Union(reach.Prefix(pfx.Masked()))
			}
		}
	}
	return sure, maybe.Subtract(sure), tags
}

// protoMatch: "*" (Any) is every protocol; Tcp and Udp match their own; Icmp, Esp and Ah
// never match a TCP or UDP listener; anything else may.
func protoMatch(rule, proto string) tri {
	switch strings.ToLower(rule) {
	case "*", "any":
		return triYes
	case "tcp", "udp":
		if strings.EqualFold(rule, proto) {
			return triYes
		}
		return triNo
	case "icmp", "esp", "ah":
		return triNo
	}
	return triMaybe
}

// portsMatch: "*", "80" or "8000-9000", from destinationPortRange and
// destinationPortRanges.
func portsMatch(one string, many []string, port int) tri {
	list := slices.Clone(many)
	if one != "" {
		list = append(list, one)
	}
	if len(list) == 0 {
		return triMaybe
	}
	res := triNo
	for _, s := range list {
		lo, hi, ok := portRange(s)
		switch {
		case !ok:
			res = triMaybe
		case lo <= port && port <= hi:
			return triYes
		}
	}
	return res
}

func portRange(s string) (int, int, bool) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return 0, 65535, true
	}
	a, b, isRange := strings.Cut(s, "-")
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi := lo
	var err2 error
	if isRange {
		hi, err2 = strconv.Atoi(strings.TrimSpace(b))
	}
	if err1 != nil || err2 != nil || lo < 0 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

// clientPorts: a rule matches every ordinary client when its source ports cover
// 1024-65535 (a client picks its own source port); narrower is maybe.
func clientPorts(one string, many []string) tri {
	list := slices.Clone(many)
	if one != "" {
		list = append(list, one)
	}
	if len(list) == 0 {
		return triYes
	}
	covered := clientPortLow
	type span struct{ lo, hi int }
	var spans []span
	for _, s := range list {
		lo, hi, ok := portRange(s)
		if !ok {
			return triMaybe
		}
		spans = append(spans, span{lo, hi})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	for _, sp := range spans {
		if sp.lo > covered {
			break
		}
		if sp.hi >= covered {
			covered = sp.hi + 1
		}
	}
	if covered > 65535 {
		return triYes
	}
	return triMaybe
}

// destMatch: does the rule's destination hold this IP configuration? "*" and
// VirtualNetwork (the VNet's own space) do; a prefix does when it covers the private
// address; an application security group when the configuration is a member; any other
// tag may.
func destMatch(one string, many []string, asgs []Ref, cfg IPConfig, private netip.Addr) tri {
	list := slices.Clone(many)
	if one != "" {
		list = append(list, one)
	}
	res := triNo
	if len(list) == 0 && len(asgs) == 0 {
		return triMaybe
	}
	for _, s := range list {
		s = strings.TrimSpace(s)
		switch strings.ToLower(s) {
		case "*", "any", "virtualnetwork":
			return triYes
		case "internet":
			continue // the destination is the private address, never in Internet
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			if a, aerr := netip.ParseAddr(s); aerr == nil {
				pfx, err = netip.PrefixFrom(a, a.BitLen()), nil
			}
		}
		switch {
		case err != nil || !private.IsValid():
			res = triMaybe
		case pfx.Contains(private.Unmap()):
			return triYes
		}
	}
	for _, g := range asgs {
		if slices.ContainsFunc(cfg.Properties.ApplicationSecurityGroups, func(m Ref) bool { return strings.EqualFold(m.ID, g.ID) }) {
			return triYes
		}
	}
	return res
}

func destDescribe(one string, many []string) string {
	list := slices.Clone(many)
	if one != "" {
		list = append(list, one)
	}
	return truncate(strings.Join(list, ","), 80)
}

func lastSegment(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return truncate(id[i+1:], 80)
	}
	return truncate(id, 80)
}
