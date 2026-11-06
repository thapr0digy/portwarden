// Package gcp is the GCP cloud look-up (M10 phase 2): the firewall rules and firewall
// policies in effect on each of an instance's network interfaces, read with
// instances.get and instances.getEffectiveFirewalls over plain HTTPS (client.go), and
// judged here, purely, with the shared reach rule.
//
// Order (docs "Policy and rule evaluation order"): hierarchical policies (organisation,
// then folders down), system policies, then VPC firewall rules and network firewall
// policies (global, then regional) in the network's enforcement order, then the implied
// ingress deny. Within a policy, lower priority numbers first; among VPC rules a deny
// beats an allow of equal priority; goto_next passes traffic on to the next step.
//
// What the response does not say is never guessed: the order of hierarchical policies
// among themselves, the network's enforcement order (it needs another permission), equal
// priorities with different actions. Every possible order is evaluated, and an address
// counts as getting through for sure only if every order lets it through. Likewise a rule
// whose sources or targets cannot be resolved (FQDNs, geolocation, threat-intelligence
// lists, address groups, secure tags) may or may not match. So each interface and family
// ends with sure addresses (open), maybe ones (undetermined: the listener keeps its level)
// or none (closed).
package gcp

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// HostData is everything fetched about one instance.
type HostData struct {
	Instance Instance
	// Effective holds getEffectiveFirewalls by interface name; EffectiveErr says why an
	// interface's call failed (that interface is then undetermined).
	Effective    map[string]Effective
	EffectiveErr map[string]string
	Policy       reach.Policy
}

const (
	// maxRanges bounds the ranges an evidence line names.
	maxRanges = 4
	// maxHierarchical bounds the hierarchical policies whose orders are all tried.
	maxHierarchical = 5
	// maxOrders bounds the orders evaluated per interface; beyond it, undetermined.
	maxOrders = 1000
	// vpcDefaultPriority is a VPC rule's priority when the API omits it.
	vpcDefaultPriority = 1000
)

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
	res, lines := directPath(d, p)
	switch {
	case res == reach.Open && p.AgentLevel >= cloud.LevelHostFirewallOpen:
		v.Open = true
		v.Evidence = lines
	case res == reach.Open:
		v.Evidence = append(lines, "cloud: direct path not counted (host firewall does not allow 0/0)")
	case res == reach.Undetermined && p.AgentLevel >= cloud.LevelHostFirewallOpen:
		v.Complete = false // undetermined: neither raises nor lowers
		v.Evidence = lines
	default:
		v.Evidence = lines
	}
	return v
}

// directPath judges every interface with an external address, each family on its own:
// open when one lets some internet address in for sure.
func directPath(d HostData, p cloud.Port) (reach.Outcome, []string) {
	var why, maybe []string
	public := false
	for _, nic := range interfacesFor(d.Instance, p.Addr) {
		for _, fam := range []reach.Family{reach.V4, reach.V6} {
			addr := externalAddress(nic, fam)
			if addr == "" {
				continue
			}
			public = true
			id := fmt.Sprintf("%s (%s)", nic.Name, addr)
			res, lines := interfacePath(d, nic, id, fam, p)
			switch res {
			case reach.Open:
				return reach.Open, lines
			case reach.Undetermined:
				maybe = append(maybe, lines...)
			default:
				why = append(why, lines...)
			}
		}
	}
	if !public {
		return reach.Closed, []string{"cloud: instance has no external IPv4 or IPv6 address"}
	}
	if len(maybe) > 0 {
		return reach.Undetermined, append(maybe, why...)
	}
	return reach.Closed, why
}

// interfacesFor returns the interfaces a listener can be reached on: the one whose
// internal address it is bound to, else (a wildcard or another address) all of them.
func interfacesFor(inst Instance, bind string) []Interface {
	a, err := netip.ParseAddr(bind)
	if err == nil && !a.IsUnspecified() {
		a = a.Unmap()
		for _, nic := range inst.Interfaces {
			for _, own := range []string{nic.NetworkIP, nic.IPv6Address} {
				if o, err := netip.ParseAddr(own); err == nil && o == a {
					return []Interface{nic}
				}
			}
		}
	}
	return inst.Interfaces
}

// externalAddress is the interface's external address of the family ("" when none).
func externalAddress(nic Interface, fam reach.Family) string {
	if fam == reach.V4 {
		for _, ac := range nic.AccessConfigs {
			if ac.NatIP != "" {
				return ac.NatIP
			}
		}
		return ""
	}
	for _, ac := range nic.IPv6AccessConfigs {
		if ac.ExternalIPv6 != "" {
			return ac.ExternalIPv6
		}
	}
	return ""
}

func interfacePath(d HostData, nic Interface, id string, fam reach.Family, p cloud.Port) (reach.Outcome, []string) {
	undecided := func(reason string) (reach.Outcome, []string) {
		return reach.Undetermined, []string{cloud.UndeterminedEvidence + " (" + id + ": " + reason + ")"}
	}
	if e, failed := d.EffectiveErr[nic.Name]; failed {
		return undecided("getEffectiveFirewalls failed: " + e)
	}
	eff, read := d.Effective[nic.Name]
	if !read {
		return undecided("getEffectiveFirewalls not read")
	}
	seqs, err := sequences(eff, d.Instance, nic, p)
	if err != "" {
		return undecided(err)
	}
	var acc tally
	start := d.Policy.Internet(fam)
	for _, seq := range seqs {
		acc.run(seq, start)
	}
	return acc.verdict(d.Policy, id, fam, p)
}

// rule is a compiled rule for one port: the source addresses it surely matches and the
// ones it may match (with why), its action and its name for evidence.
type rule struct {
	label       string
	action      string
	sure, maybe reach.Set
	reason      string
	// tie: another rule of the same policy has the same priority and another action, so
	// which one comes first is not known: every hit is only a maybe.
	tie bool
}

// step is one policy (or the VPC rules) in evaluation order.
type step []rule

// compiled is a policy and its rules compiled for one port and interface.
type compiled struct {
	pol  Policy
	step step
}

// sequences builds every order of steps the response allows. A non-empty string means
// the interface cannot be judged (too many orders).
func sequences(eff Effective, inst Instance, nic Interface, p cloud.Port) ([][]step, string) {
	var hier, system, global, regional []compiled
	var odd step
	for _, pol := range eff.Policies {
		switch strings.ToUpper(pol.Type) {
		case "HIERARCHY":
			hier = append(hier, compiled{pol, policyStep(pol, inst, nic, p, false)})
		case "SYSTEM_GLOBAL", "SYSTEM_REGIONAL":
			system = append(system, compiled{pol, policyStep(pol, inst, nic, p, false)})
		case "NETWORK":
			global = append(global, compiled{pol, policyStep(pol, inst, nic, p, false)})
		case "NETWORK_REGIONAL":
			regional = append(regional, compiled{pol, policyStep(pol, inst, nic, p, false)})
		default:
			odd = append(odd, policyStep(pol, inst, nic, p, true)...)
		}
	}
	if len(hier) > maxHierarchical {
		return nil, fmt.Sprintf("%d hierarchical firewall policies (more than %d): their order is not known", len(hier), maxHierarchical)
	}
	hierOrders := permutations(hier)
	systemOrders := byPriority(system, "SYSTEM_GLOBAL")
	networkOrders := cross(byPriority(global, ""), byPriority(regional, ""))
	if n := len(hierOrders) * len(systemOrders) * len(networkOrders) * 2; n > maxOrders {
		return nil, fmt.Sprintf("%d possible policy orders (more than %d)", n, maxOrders)
	}
	vpc := vpcStep(eff.Firewalls, inst, p)
	var out [][]step
	for _, h := range hierOrders {
		for _, sys := range systemOrders {
			for _, net := range networkOrders {
				head := steps(h, sys)
				if len(odd) > 0 {
					head = append(head, odd)
				}
				nets := steps(net)
				after := append(append(slices.Clone(head), vpc), nets...)  // AFTER_CLASSIC_FIREWALL (the default)
				before := append(append(slices.Clone(head), nets...), vpc) // BEFORE_CLASSIC_FIREWALL
				out = append(out, after, before)
			}
		}
	}
	return out, ""
}

func steps(groups ...[]compiled) []step {
	var out []step
	for _, g := range groups {
		for _, c := range g {
			out = append(out, c.step)
		}
	}
	return out
}

// permutations returns every order of cs (one empty order for none).
func permutations(cs []compiled) [][]compiled {
	if len(cs) <= 1 {
		return [][]compiled{slices.Clone(cs)}
	}
	var out [][]compiled
	for i := range cs {
		rest := append(slices.Clone(cs[:i]), cs[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]compiled{cs[i]}, tail...))
		}
	}
	return out
}

// byPriority orders policies by their association priority; policies of equal priority
// (or without one) are tried in every order. first, when set, is a type that goes before
// the others (system global before system regional).
func byPriority(cs []compiled, first string) [][]compiled {
	key := func(c compiled) (int, int) {
		rank := 1
		if first != "" && strings.EqualFold(c.pol.Type, first) {
			rank = 0
		}
		prio := -1
		if c.pol.Priority != nil {
			prio = *c.pol.Priority
		}
		return rank, prio
	}
	sorted := slices.Clone(cs)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, pi := key(sorted[i])
		rj, pj := key(sorted[j])
		if ri != rj {
			return ri < rj
		}
		return pi < pj
	})
	orders := [][]compiled{{}}
	for i := 0; i < len(sorted); {
		j := i
		ri, pi := key(sorted[i])
		for j < len(sorted) {
			if rj, pj := key(sorted[j]); rj != ri || pj != pi {
				break
			}
			j++
		}
		orders = cross(orders, permutations(sorted[i:j]))
		i = j
	}
	return orders
}

func cross(a, b [][]compiled) [][]compiled {
	var out [][]compiled
	for _, x := range a {
		for _, y := range b {
			out = append(out, append(slices.Clone(x), y...))
		}
	}
	return out
}

// tally unites the outcomes of every order: addresses allowed in some order, denied in
// some order, and which rule (or reason) put them there.
type tally struct {
	allowed, denied reach.Set
	allowBy, denyBy []labelled
	why             []labelled
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

// run evaluates one order. live is what is still being evaluated; a rule's sure hits
// leave it, its maybe hits stay (in the world where the rule did not match they go on).
func (t *tally) run(seq []step, start reach.Set) {
	live := start
	for _, s := range seq {
		var next reach.Set
		for _, r := range s {
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
				t.why = add(t.why, r.reason, may)
			}
			switch r.action {
			case "allow", "apply_security_profile_group":
				t.allowed = t.allowed.Union(all)
				t.allowBy = add(t.allowBy, r.label, all)
			case "deny":
				t.denied = t.denied.Union(all)
				t.denyBy = add(t.denyBy, r.label, all)
			case "goto_next":
				next = next.Union(all)
			default:
				t.allowed = t.allowed.Union(all)
				t.denied = t.denied.Union(all)
				t.why = add(t.why, r.label+" has action "+strconv.Quote(r.action)+", which is not understood", all)
			}
			live = live.Subtract(hit)
		}
		live = next.Union(live)
	}
	t.denied = t.denied.Union(live)
	t.denyBy = add(t.denyBy, "implied deny", live)
}

func (t *tally) verdict(pol reach.Policy, id string, fam reach.Family, p cloud.Port) (reach.Outcome, []string) {
	sure := t.allowed.Subtract(t.denied)
	maybe := t.allowed.Intersect(t.denied)
	what := fmt.Sprintf("%s/%d", p.Proto, p.Port)
	if !sure.IsEmpty() {
		var lines []string
		for _, a := range t.allowBy {
			if part := a.set.Intersect(sure); !part.IsEmpty() {
				lines = append(lines, fmt.Sprintf("cloud: %s: %s allows %s from %s", id, a.label, what, pol.Describe(part, maxRanges)))
			}
		}
		return reach.Open, append(lines, fmt.Sprintf("cloud: %s reachable from %s", id, pol.Describe(sure, maxRanges)))
	}
	if !maybe.IsEmpty() {
		var reasons []string
		for _, w := range t.why {
			if !w.set.Intersect(maybe).IsEmpty() {
				reasons = append(reasons, w.label)
			}
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "the policy orders Google does not report (hierarchical policies, network enforcement order, equal priorities) disagree")
		}
		return reach.Undetermined, []string{fmt.Sprintf("%s (%s: %s allowed from %s only if %s)", cloud.UndeterminedEvidence, id, what,
			pol.Describe(maybe, maxRanges), strings.Join(reasons, "; "))}
	}
	var by []string
	for _, dn := range t.denyBy {
		by = append(by, dn.label)
	}
	return reach.Closed, []string{fmt.Sprintf("cloud: %s: no rule allows %s from the internet (%s); denied by %s", id, what, reach.Anywhere(fam), strings.Join(by, ", "))}
}

// vpcStep compiles the VPC firewall rules into one step: priority order, a deny before an
// allow of equal priority (deny wins the tie), no goto_next.
func vpcStep(fws []Firewall, inst Instance, p cloud.Port) step {
	type prioritised struct {
		prio int
		r    rule
	}
	var rules []prioritised
	for _, fw := range fws {
		if fw.Disabled || !ingress(fw.Direction) {
			continue
		}
		action := ""
		lm := triNo
		if m := l4Any(fw.Denied, p); m != triNo {
			action, lm = "deny", m
		} else if m := l4Any(fw.Allowed, p); m != triNo {
			action, lm = "allow", m
		}
		if action == "" {
			continue
		}
		prio := vpcDefaultPriority
		if fw.Priority != nil {
			prio = *fw.Priority
		}
		r := rule{label: fmt.Sprintf("firewall %s (vpc, priority %d)", fw.Name, prio), action: action}
		applies := vpcApplies(fw, inst)
		if applies == triNo {
			continue
		}
		r.sure, r.maybe, r.reason = vpcSources(fw)
		if lm == triMaybe {
			r.demote(r.label + ": ports not understood")
		}
		rules = append(rules, prioritised{prio, r})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].prio != rules[j].prio {
			return rules[i].prio < rules[j].prio
		}
		return rules[i].r.action == "deny" && rules[j].r.action != "deny"
	})
	out := make(step, 0, len(rules))
	for _, pr := range rules {
		out = append(out, pr.r)
	}
	return out
}

func (r *rule) demote(reason string) {
	r.maybe = r.maybe.Union(r.sure)
	r.sure = reach.Set{}
	if r.reason == "" {
		r.reason = reason
	} else {
		r.reason += "; " + reason
	}
}

func ingress(dir string) bool { return dir == "" || strings.EqualFold(dir, "INGRESS") }

// vpcApplies: target tags, else target service accounts, else every instance.
func vpcApplies(fw Firewall, inst Instance) tri {
	switch {
	case len(fw.TargetTags) > 0:
		if slices.ContainsFunc(fw.TargetTags, func(t string) bool { return slices.Contains(inst.Tags.Items, t) }) {
			return triYes
		}
		return triNo
	case len(fw.TargetServiceAccounts) > 0:
		if hasServiceAccount(inst, fw.TargetServiceAccounts) {
			return triYes
		}
		return triNo
	}
	return triYes
}

func hasServiceAccount(inst Instance, emails []string) bool {
	for _, sa := range inst.ServiceAccounts {
		if slices.ContainsFunc(emails, func(e string) bool { return strings.EqualFold(e, sa.Email) }) {
			return true
		}
	}
	return false
}

// vpcSources: sourceRanges (source tags and service accounts name VMs, never internet
// traffic); an ingress rule with no source at all applies to 0.0.0.0/0 (the API default).
func vpcSources(fw Firewall) (sure, maybe reach.Set, reason string) {
	if len(fw.SourceRanges) == 0 && len(fw.SourceTags) == 0 && len(fw.SourceServiceAccounts) == 0 {
		return reach.All(reach.V4), reach.Set{}, ""
	}
	return ranges(fw.SourceRanges, "firewall "+fw.Name)
}

var everything = reach.All(reach.V4).Union(reach.All(reach.V6))

// ranges parses CIDRs (a bare address is one address); one that does not parse may be
// any address.
func ranges(cidrs []string, owner string) (sure, maybe reach.Set, reason string) {
	var bad []string
	for _, c := range cidrs {
		pfx, err := parsePrefix(c)
		if err != nil {
			bad = append(bad, strconv.Quote(c))
			continue
		}
		sure = sure.Union(reach.Prefix(pfx))
	}
	if len(bad) > 0 {
		maybe = everything
		reason = owner + ": source ranges " + strings.Join(bad, ", ") + " do not parse"
	}
	return sure, maybe, reason
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

// policyStep compiles one policy's ingress rules for the port, in priority order. forced
// makes every hit a maybe (a policy of a type the judge does not know).
func policyStep(pol Policy, inst Instance, nic Interface, p cloud.Port, forced bool) step {
	name := pol.ShortName
	if name == "" {
		name = pol.Name
	}
	kind := strings.ToLower(pol.Type)
	rules := slices.Clone(pol.Rules)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	var out step
	for i, r := range rules {
		if r.Disabled || !ingress(r.Direction) {
			continue
		}
		lm := l4Policy(r.Match.Layer4Configs, p)
		if lm == triNo {
			continue
		}
		label := fmt.Sprintf("policy %s rule %d (%s)", name, r.Priority, kind)
		applies, why := policyApplies(r, inst, nic)
		if applies == triNo {
			continue
		}
		c := rule{label: label, action: strings.ToLower(r.Action)}
		c.sure, c.maybe, c.reason = policySources(r.Match, label)
		if applies == triMaybe {
			c.demote(label + " " + why)
		}
		if lm == triMaybe {
			c.demote(label + ": ports not understood")
		}
		if forced {
			c.demote(fmt.Sprintf("policy %s has type %q, which is not understood", name, pol.Type))
		}
		for j, o := range rules {
			if j != i && o.Priority == r.Priority && !strings.EqualFold(o.Action, r.Action) && !o.Disabled && ingress(o.Direction) {
				c.tie = true
				c.reason = joinReason(c.reason, fmt.Sprintf("policy %s has rules of equal priority %d with different actions", name, r.Priority))
			}
		}
		out = append(out, c)
	}
	return out
}

func joinReason(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// policyApplies: a target type other than instances, or target networks not holding
// the interface's, never apply; target service accounts by membership; target secure
// tags may (the instance's secure tags are not readable with the role's permissions).
func policyApplies(r Rule, inst Instance, nic Interface) (tri, string) {
	if r.TargetType != "" && !strings.EqualFold(r.TargetType, "INSTANCES") {
		return triNo, ""
	}
	if len(r.TargetResources) > 0 && !slices.ContainsFunc(r.TargetResources, func(n string) bool { return sameNetwork(n, nic.Network) }) {
		return triNo, ""
	}
	if len(r.TargetServiceAccounts) > 0 && hasServiceAccount(inst, r.TargetServiceAccounts) {
		return triYes, ""
	}
	if len(r.TargetSecureTags) > 0 {
		if slices.ContainsFunc(r.TargetSecureTags, func(t SecureTag) bool { return !strings.EqualFold(t.State, "INEFFECTIVE") }) {
			return triMaybe, "targets secure tags, which are not readable"
		}
		return triNo, ""
	}
	if len(r.TargetServiceAccounts) > 0 {
		return triNo, ""
	}
	return triYes, ""
}

// sameNetwork compares network references by their projects/… path (full URLs and
// relative names both occur).
func sameNetwork(a, b string) bool {
	norm := func(s string) string {
		if i := strings.Index(s, "projects/"); i >= 0 {
			s = s[i:]
		}
		return strings.TrimSuffix(s, "/")
	}
	return norm(a) != "" && norm(a) == norm(b)
}

// policySources: srcIpRanges are sure; FQDN, geolocation, threat-intelligence and
// address-group sources may be any address; secure tags and VPC networks name VMs, never
// internet traffic. A network type other than INTERNET keeps internet traffic out.
func policySources(m Match, label string) (sure, maybe reach.Set, reason string) {
	nt := strings.ToUpper(m.SrcNetworkType)
	if nt == "" {
		nt = strings.ToUpper(m.SrcNetworkContext)
	}
	switch nt {
	case "", "UNSPECIFIED", "INTERNET":
	case "NON_INTERNET", "INTRA_VPC", "VPC_NETWORKS":
		return reach.Set{}, reach.Set{}, ""
	}
	sure, maybe, reason = ranges(m.SrcIPRanges, label)
	var unresolved []string
	for _, u := range []struct {
		vals []string
		what string
	}{{m.SrcFqdns, "FQDN sources"}, {m.SrcRegionCodes, "geolocation sources"},
		{m.SrcThreatIntelligences, "threat-intelligence sources"}, {m.SrcAddressGroups, "address-group sources"}} {
		if len(u.vals) > 0 {
			unresolved = append(unresolved, u.what)
		}
	}
	if len(unresolved) > 0 {
		maybe = everything
		reason = joinReason(reason, label+" matches "+strings.Join(unresolved, ", "))
	}
	known := len(m.SrcIPRanges) > 0 || len(unresolved) > 0 || len(m.SrcSecureTags) > 0 || len(m.SrcNetworks) > 0
	switch {
	case !known && nt == "INTERNET":
		sure = everything
	case !known:
		maybe = everything
		reason = joinReason(reason, label+" has no source matcher the judge understands")
	}
	switch nt {
	case "", "UNSPECIFIED", "INTERNET":
	default:
		maybe = maybe.Union(sure)
		sure = reach.Set{}
		reason = joinReason(reason, label+" has source network type "+strconv.Quote(nt)+", which is not understood")
	}
	return sure, maybe, reason
}

// tri is a three-valued match.
type tri int

const (
	triNo tri = iota
	triMaybe
	triYes
)

func l4Any(l4 []L4, p cloud.Port) tri {
	best := triNo
	for _, x := range l4 {
		best = max(best, l4Match(x.Protocol, x.Ports, p))
	}
	return best
}

// l4Policy: a policy rule's layer-4 configs; none at all match every protocol.
func l4Policy(l4 []PolicyL4, p cloud.Port) tri {
	if len(l4) == 0 {
		return triYes
	}
	best := triNo
	for _, x := range l4 {
		best = max(best, l4Match(x.Protocol, x.Ports, p))
	}
	return best
}

// l4Match: protocol all, tcp/6 or udp/17; ports "22" or "8000-9000", none = every port.
// A port spec that does not parse may match.
func l4Match(proto string, ports []string, p cloud.Port) tri {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "all":
		return triYes
	case "tcp", "6":
		if p.Proto != "tcp" {
			return triNo
		}
	case "udp", "17":
		if p.Proto != "udp" {
			return triNo
		}
	default:
		return triNo
	}
	if len(ports) == 0 {
		return triYes
	}
	res := triNo
	for _, spec := range ports {
		lo, hi, err := portRange(spec)
		if err != nil {
			res = triMaybe
			continue
		}
		if p.Port >= lo && p.Port <= hi {
			return triYes
		}
	}
	return res
}

func portRange(spec string) (int, int, error) {
	a, b, isRange := strings.Cut(strings.TrimSpace(spec), "-")
	lo, err := strconv.Atoi(a)
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if isRange {
		if hi, err = strconv.Atoi(b); err != nil {
			return 0, 0, err
		}
	}
	if lo < 0 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("port range %q out of bounds", spec)
	}
	return lo, hi, nil
}
