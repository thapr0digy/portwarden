// Package aws is the AWS cloud look-up: EC2 security groups and subnet network ACLs for
// the direct path, and Elastic Load Balancing (ALB/NLB via elbv2, Classic ELB) for the
// load-balancer path. eval.go is pure: it judges data the client (client.go) fetched.
//
// Direct path (needs the agent's level ≥ host_firewall_open): the instance has a public
// IPv4 or an IPv6 address, one of its security groups allows the protocol and port from
// 0.0.0.0/0 or ::/0, and its subnet's network ACL lets that traffic in from 0/0 (rules in
// rule-number order; the first /0 rule that matches decides). Narrower rules and outbound
// NACL rules (return traffic) are not judged.
//
// Load-balancer path (needs level ≥ bound: the host firewall may admit only the LB): an
// internet-facing ALB/NLB whose listener forwards (default action or any rule; rule
// conditions are not judged) to a target group holding this instance (by id, or by
// private IP for ip targets) on the listener's port, and whose security groups (when it
// has any) allow the LB port from 0/0; or an internet-facing Classic ELB with the
// instance registered and a listener to the port.
package aws

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/thapr0digy/portwarden/internal/cloud"
)

// HostData is everything fetched about one instance.
type HostData struct {
	Instance       ec2types.Instance
	SecurityGroups map[string]ec2types.SecurityGroup // by group id (instance and LB groups)
	// NACLs maps subnet id to its network ACL; a subnet missing here was not readable.
	NACLs map[string]ec2types.NetworkAcl
	LBs   RegionLBs
}

// RegionLBs is the region's internet-facing load balancers.
type RegionLBs struct {
	V2      []V2LB
	Classic []elbtypes.LoadBalancerDescription
}

// V2LB is an ALB/NLB with its listeners, rules and target groups.
type V2LB struct {
	LB        elbv2types.LoadBalancer
	Listeners []V2Listener
	// TargetGroups by ARN, with their registered targets.
	TargetGroups map[string]V2TargetGroup
	// truncated: some listeners, rules or target groups were not read (page cap).
	truncated bool
}

// V2Listener is a listener with the actions of its non-default rules.
type V2Listener struct {
	Listener    elbv2types.Listener
	RuleActions []elbv2types.Action
}

// V2TargetGroup is a target group and its targets' health.
type V2TargetGroup struct {
	TG      elbv2types.TargetGroup
	Targets []elbv2types.TargetHealthDescription
}

// Evaluate judges each port against data.
func Evaluate(d HostData, ports []cloud.Port) []cloud.Verdict {
	out := make([]cloud.Verdict, 0, len(ports))
	for _, p := range ports {
		out = append(out, evaluatePort(d, p))
	}
	return out
}

func evaluatePort(d HostData, p cloud.Port) cloud.Verdict {
	v := cloud.Verdict{Key: p.Key, Complete: true}
	direct, directWhy := directPath(d, p)
	lb := lbPaths(d, p)
	switch {
	case direct && p.AgentLevel >= cloud.LevelHostFirewallOpen:
		v.Open = true
		v.Evidence = append(v.Evidence, directWhy...)
	case direct:
		v.Evidence = append(v.Evidence, append(directWhy, "cloud: direct path not counted (host firewall does not allow 0/0)")...)
	default:
		v.Evidence = append(v.Evidence, directWhy...)
	}
	if len(lb) > 0 && p.AgentLevel >= cloud.LevelBound {
		v.Open = true
		v.Evidence = append(v.Evidence, lb...)
	} else if len(lb) == 0 {
		v.Evidence = append(v.Evidence, fmt.Sprintf("cloud: no internet-facing load balancer forwards to %s:%d", deref(d.Instance.InstanceId), p.Port))
	}
	return v
}

// eniPath is one network interface's way in: its public addresses by family, its groups
// and its subnet.
type eniPath struct {
	id     string
	v4, v6 bool
	groups []string
	subnet string
}

// paths lists the instance's interfaces. An instance described without interfaces is one
// path from its instance-level fields.
func paths(inst ec2types.Instance) []eniPath {
	var out []eniPath
	anyV4 := false
	for _, n := range inst.NetworkInterfaces {
		p := eniPath{id: deref(n.NetworkInterfaceId), v4: n.Association != nil && deref(n.Association.PublicIp) != "",
			v6: len(n.Ipv6Addresses) > 0, subnet: deref(n.SubnetId)}
		for _, g := range n.Groups {
			p.groups = append(p.groups, deref(g.GroupId))
		}
		if len(p.groups) == 0 {
			p.groups = instanceGroups(inst)
		}
		if p.subnet == "" {
			p.subnet = deref(inst.SubnetId)
		}
		anyV4 = anyV4 || p.v4
		out = append(out, p)
	}
	if len(out) == 0 {
		return []eniPath{{id: deref(inst.InstanceId), v4: deref(inst.PublicIpAddress) != "", v6: deref(inst.Ipv6Address) != "",
			groups: instanceGroups(inst), subnet: deref(inst.SubnetId)}}
	}
	if !anyV4 && deref(inst.PublicIpAddress) != "" {
		out[0].v4 = true // the instance's public IPv4 belongs to its primary interface
	}
	return out
}

// directPath reports whether some interface of the instance lets the port in from 0/0
// (each interface with its own groups and subnet ACL, each address family on its own),
// and why (not).
func directPath(d HostData, p cloud.Port) (bool, []string) {
	var why []string
	public := false
	for _, e := range paths(d.Instance) {
		for _, fam := range []int{4, 6} {
			if (fam == 4 && !e.v4) || (fam == 6 && !e.v6) {
				continue
			}
			public = true
			sgWhy, ok := sgAllows(d, e.groups, p.Proto, p.Port, fam)
			if !ok {
				why = append(why, fmt.Sprintf("cloud: %s: no security group allows %s/%d from %s", e.id, p.Proto, p.Port, anywhere(fam)))
				continue
			}
			acl, read := d.NACLs[e.subnet]
			if !read {
				return true, []string{sgWhy, "cloud: nacl for " + e.subnet + " not read (assumed open)"}
			}
			allowed, ruleWhy := naclAllows(acl, p.Proto, p.Port, fam)
			if allowed {
				return true, []string{sgWhy, ruleWhy}
			}
			why = append(why, "cloud: "+e.id+": "+strings.TrimPrefix(ruleWhy, "cloud: "))
		}
	}
	if !public {
		return false, []string{"cloud: instance has no public IPv4 or IPv6 address"}
	}
	return false, why
}

func anywhere(fam int) string {
	if fam == 6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

func instanceGroups(inst ec2types.Instance) []string {
	var ids []string
	for _, g := range inst.SecurityGroups {
		ids = append(ids, deref(g.GroupId))
	}
	for _, n := range inst.NetworkInterfaces {
		for _, g := range n.Groups {
			ids = append(ids, deref(g.GroupId))
		}
	}
	sort.Strings(ids)
	return slices.Compact(ids)
}

func instanceSubnets(inst ec2types.Instance) []string {
	var ids []string
	if s := deref(inst.SubnetId); s != "" {
		ids = append(ids, s)
	}
	for _, n := range inst.NetworkInterfaces {
		if s := deref(n.SubnetId); s != "" {
			ids = append(ids, s)
		}
	}
	sort.Strings(ids)
	return slices.Compact(ids)
}

func instancePrivateIPs(inst ec2types.Instance) []string {
	var ips []string
	if s := deref(inst.PrivateIpAddress); s != "" {
		ips = append(ips, s)
	}
	for _, n := range inst.NetworkInterfaces {
		if s := deref(n.PrivateIpAddress); s != "" {
			ips = append(ips, s)
		}
		for _, a := range n.PrivateIpAddresses {
			if s := deref(a.PrivateIpAddress); s != "" {
				ips = append(ips, s)
			}
		}
		for _, a := range n.Ipv6Addresses {
			if s := deref(a.Ipv6Address); s != "" {
				ips = append(ips, s)
			}
		}
	}
	return ips
}

// sgAllows reports whether any of groups allows proto/port from 0.0.0.0/0 or ::/0. A
// group that was not read counts as allowing (over-reporting beats under-reporting).
func sgAllows(d HostData, groups []string, proto string, port int, fam int) (string, bool) {
	for _, id := range groups {
		sg, ok := d.SecurityGroups[id]
		if !ok {
			return fmt.Sprintf("cloud: %s not read (assumed open for %s/%d)", id, proto, port), true
		}
		for _, perm := range sg.IpPermissions {
			if !permMatches(perm, proto, port) {
				continue
			}
			for _, r := range perm.IpRanges {
				if fam == 4 && isAnywhere(deref(r.CidrIp)) {
					return fmt.Sprintf("cloud: %s allows %s/%d from %s", sgName(sg), proto, port, deref(r.CidrIp)), true
				}
			}
			for _, r := range perm.Ipv6Ranges {
				if fam == 6 && isAnywhere(deref(r.CidrIpv6)) {
					return fmt.Sprintf("cloud: %s allows %s/%d from %s", sgName(sg), proto, port, deref(r.CidrIpv6)), true
				}
			}
		}
	}
	return "", false
}

func sgName(sg ec2types.SecurityGroup) string {
	if n := deref(sg.GroupName); n != "" {
		return deref(sg.GroupId) + " (" + n + ")"
	}
	return deref(sg.GroupId)
}

// permMatches: protocol "-1" is every protocol and port; "tcp"/"6" and "udp"/"17" match
// by name or number within FromPort..ToPort.
func permMatches(perm ec2types.IpPermission, proto string, port int) bool {
	pr := strings.ToLower(deref(perm.IpProtocol))
	if pr == "-1" || pr == "all" {
		return true
	}
	if !protoMatches(pr, proto) {
		return false
	}
	if perm.FromPort == nil || perm.ToPort == nil {
		return true
	}
	from, to := int(*perm.FromPort), int(*perm.ToPort)
	if from == -1 && to == -1 {
		return true
	}
	return port >= from && port <= to
}

func protoMatches(cloudProto, proto string) bool {
	switch cloudProto {
	case "tcp", "6":
		return proto == "tcp"
	case "udp", "17":
		return proto == "udp"
	}
	return false
}

func isAnywhere(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Bits() == 0
}

// naclAllows evaluates inbound entries in rule-number order: the first entry whose CIDR is
// 0/0 and that matches protocol and port decides.
func naclAllows(acl ec2types.NetworkAcl, proto string, port int, fam int) (bool, string) {
	entries := slices.Clone(acl.Entries)
	sort.Slice(entries, func(i, j int) bool { return deref32(entries[i].RuleNumber) < deref32(entries[j].RuleNumber) })
	for _, e := range entries {
		if e.Egress != nil && *e.Egress {
			continue
		}
		// IPv4 and IPv6 entries share one rule order but a path is judged by its own
		// family's entries only.
		cidr := deref(e.CidrBlock)
		if fam == 6 {
			cidr = deref(e.Ipv6CidrBlock)
		}
		if !isAnywhere(cidr) {
			continue
		}
		pr := deref(e.Protocol)
		if pr != "-1" && !protoMatches(strings.ToLower(pr), proto) {
			continue
		}
		if pr != "-1" && e.PortRange != nil && e.PortRange.From != nil && e.PortRange.To != nil &&
			(port < int(*e.PortRange.From) || port > int(*e.PortRange.To)) {
			continue
		}
		rule := strconv.Itoa(int(deref32(e.RuleNumber)))
		if deref32(e.RuleNumber) == 32767 {
			rule = "*"
		}
		if e.RuleAction == ec2types.RuleActionAllow {
			return true, fmt.Sprintf("cloud: %s rule %s allows %s/%d from %s", deref(acl.NetworkAclId), rule, proto, port, cidr)
		}
		return false, fmt.Sprintf("cloud: %s rule %s denies %s/%d from %s", deref(acl.NetworkAclId), rule, proto, port, cidr)
	}
	return false, fmt.Sprintf("cloud: %s has no inbound rule for %s/%d from %s (denied)", deref(acl.NetworkAclId), proto, port, anywhere(fam))
}

// lbPaths returns one evidence line per internet-facing load balancer path to the port.
func lbPaths(d HostData, p cloud.Port) []string {
	inst := d.Instance
	id := deref(inst.InstanceId)
	privIPs := instancePrivateIPs(inst)
	var out []string
	for _, lb := range d.LBs.V2 {
		if lb.LB.Scheme != elbv2types.LoadBalancerSchemeEnumInternetFacing {
			continue
		}
		for _, l := range lb.Listeners {
			lport := int(deref32(l.Listener.Port))
			for _, tgArn := range forwardTargets(append(slices.Clone(l.Listener.DefaultActions), l.RuleActions...)) {
				tg, ok := lb.TargetGroups[tgArn]
				if !ok || !tgProtoMatches(tg.TG.Protocol, p.Proto) {
					continue
				}
				for _, t := range tg.Targets {
					if t.Target == nil {
						continue
					}
					tid := deref(t.Target.Id)
					if tid != id && !slices.Contains(privIPs, tid) {
						continue
					}
					tport := int(deref32(t.Target.Port))
					if tport == 0 {
						tport = int(deref32(tg.TG.Port))
					}
					if tport != p.Port {
						continue
					}
					if len(lb.LB.SecurityGroups) > 0 {
						if _, ok := sgAllows(d, lb.LB.SecurityGroups, lbFrontProto(l.Listener.Protocol), lport, 4); !ok {
							continue
						}
					}
					health := ""
					if t.TargetHealth != nil && t.TargetHealth.State != "" {
						health = " (" + string(t.TargetHealth.State) + ")"
					}
					out = append(out, fmt.Sprintf("cloud: lb %s (internet-facing) listener %s:%d -> tg %s -> %s:%d%s",
						deref(lb.LB.LoadBalancerName), l.Listener.Protocol, lport, deref(tg.TG.TargetGroupName), tid, tport, health))
				}
			}
		}
	}
	for _, lb := range d.LBs.Classic {
		if deref(lb.Scheme) != "internet-facing" || !slices.ContainsFunc(lb.Instances, func(i elbtypes.Instance) bool { return deref(i.InstanceId) == id }) {
			continue
		}
		for _, ld := range lb.ListenerDescriptions {
			l := ld.Listener
			if l == nil || int(deref32(l.InstancePort)) != p.Port || p.Proto != "tcp" {
				continue
			}
			if len(lb.SecurityGroups) > 0 {
				if _, ok := sgAllows(d, lb.SecurityGroups, "tcp", int(l.LoadBalancerPort), 4); !ok {
					continue
				}
			}
			out = append(out, fmt.Sprintf("cloud: classic elb %s (internet-facing) listener %s:%d -> %s:%d",
				deref(lb.LoadBalancerName), deref(l.Protocol), l.LoadBalancerPort, id, p.Port))
		}
	}
	return out
}

func forwardTargets(actions []elbv2types.Action) []string {
	var arns []string
	for _, a := range actions {
		if a.Type != elbv2types.ActionTypeEnumForward {
			continue
		}
		if s := deref(a.TargetGroupArn); s != "" {
			arns = append(arns, s)
		}
		if a.ForwardConfig != nil {
			for _, t := range a.ForwardConfig.TargetGroups {
				if s := deref(t.TargetGroupArn); s != "" {
					arns = append(arns, s)
				}
			}
		}
	}
	sort.Strings(arns)
	return slices.Compact(arns)
}

// tgProtoMatches maps a target group's protocol to the listener's transport.
func tgProtoMatches(p elbv2types.ProtocolEnum, proto string) bool {
	switch p {
	case elbv2types.ProtocolEnumUdp:
		return proto == "udp"
	case elbv2types.ProtocolEnumTcpUdp:
		return true
	case elbv2types.ProtocolEnumGeneve:
		return false
	}
	return proto == "tcp" // HTTP, HTTPS, TCP, TLS, and an unset protocol (lambda never matches an instance)
}

func lbFrontProto(p elbv2types.ProtocolEnum) string {
	if p == elbv2types.ProtocolEnumUdp {
		return "udp"
	}
	return "tcp"
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func deref32(n *int32) int32 {
	if n == nil {
		return 0
	}
	return *n
}
