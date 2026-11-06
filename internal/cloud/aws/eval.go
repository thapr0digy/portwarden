// Package aws is the AWS cloud look-up: EC2 security groups and subnet network ACLs for
// the direct path, and Elastic Load Balancing (ALB/NLB via elbv2, Classic ELB) for the
// load-balancer path. eval.go is pure: it judges data the client (client.go) fetched.
//
// Direct path (needs the agent's level ≥ host_firewall_open; direct.go), per network
// interface and address family: the interface has a public address; its security groups
// allow the port from some internet address (the reach rule, package reach: anything but
// private and VPN ranges); its subnet's network ACL lets some of those addresses in
// (first match in rule-number order, over every range) and, for TCP, lets replies out to
// them on some ephemeral port; and its subnet's route table sends replies to them through
// an internet gateway. A route to an appliance that may forward them makes the path
// undetermined, as does a route table that could not be read.
//
// Load-balancer path (needs level ≥ bound: the host firewall may admit only the LB): an
// internet-facing ALB/NLB whose listener forwards (default action or any rule; rule
// conditions are not judged) to a target group holding this instance (by id, or by
// private IP for ip targets) on the listener's port, and whose security groups (when it
// has any) allow the LB port from some internet address; or an internet-facing Classic
// ELB with the instance registered and a listener to the port.
package aws

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// HostData is everything fetched about one instance.
type HostData struct {
	Instance       ec2types.Instance
	SecurityGroups map[string]ec2types.SecurityGroup // by group id (instance and LB groups)
	// NACLs maps subnet id to its network ACL; a subnet missing here was not readable.
	NACLs map[string]ec2types.NetworkAcl
	// RouteTables are the route tables of the instance's VPCs; RoutesErr, when set, says
	// why they could not be read (every direct path is then undetermined).
	RouteTables []ec2types.RouteTable
	RoutesErr   string
	LBs         RegionLBs
	// PrefixLists are the managed prefix lists the security groups name, by id; a list
	// missing here, or with Err set, was not read (rules naming it are undetermined).
	PrefixLists map[string]PrefixList
	// GatewayEndpoints are the region's VPC endpoints of type Gateway (S3, DynamoDB), which
	// deliver only to their AWS service: a route to one is not the internet. Any other
	// vpce- (a Gateway Load Balancer endpoint) may forward on. GatewayEndpointsErr, when
	// set, says why the set may be incomplete (unread or truncated).
	GatewayEndpoints    map[string]bool
	GatewayEndpointsErr string
	// Policy is the reach rule (the operator's VPN ranges).
	Policy reach.Policy
}

// PrefixList is a managed prefix list's entries, or why they could not be read.
type PrefixList struct {
	CIDRs []string
	Err   string
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
	lb, lbMaybe := lbPaths(d, p)
	undecided := false
	switch {
	case direct == open && p.AgentLevel >= cloud.LevelHostFirewallOpen:
		v.Open = true
		v.Evidence = append(v.Evidence, directWhy...)
	case direct == open:
		v.Evidence = append(v.Evidence, append(directWhy, "cloud: direct path not counted (host firewall does not allow 0/0)")...)
	case direct == undetermined && p.AgentLevel >= cloud.LevelHostFirewallOpen:
		undecided = true
		v.Evidence = append(v.Evidence, directWhy...)
	default:
		v.Evidence = append(v.Evidence, directWhy...)
	}
	switch {
	case len(lb) > 0 && p.AgentLevel >= cloud.LevelBound:
		v.Open = true
		v.Evidence = append(v.Evidence, lb...)
	case len(lbMaybe) > 0 && p.AgentLevel >= cloud.LevelBound:
		undecided = true
		v.Evidence = append(v.Evidence, lbMaybe...)
	case len(lb) == 0 && len(lbMaybe) == 0:
		v.Evidence = append(v.Evidence, fmt.Sprintf("cloud: no internet-facing load balancer forwards to %s:%d", deref(d.Instance.InstanceId), p.Port))
	}
	if undecided && !v.Open {
		v.Complete = false // undetermined: neither raises nor lowers
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
	vpc    string
}

// paths lists the instance's interfaces. An instance described without interfaces is one
// path from its instance-level fields.
func paths(inst ec2types.Instance) []eniPath {
	var out []eniPath
	anyV4 := false
	for _, n := range inst.NetworkInterfaces {
		p := eniPath{id: deref(n.NetworkInterfaceId), v4: n.Association != nil && deref(n.Association.PublicIp) != "",
			v6: len(n.Ipv6Addresses) > 0, subnet: deref(n.SubnetId), vpc: deref(n.VpcId)}
		for _, g := range n.Groups {
			p.groups = append(p.groups, deref(g.GroupId))
		}
		if len(p.groups) == 0 {
			p.groups = instanceGroups(inst)
		}
		if p.subnet == "" {
			p.subnet = deref(inst.SubnetId)
		}
		if p.vpc == "" {
			p.vpc = deref(inst.VpcId)
		}
		anyV4 = anyV4 || p.v4
		out = append(out, p)
	}
	if len(out) == 0 {
		return []eniPath{{id: deref(inst.InstanceId), v4: deref(inst.PublicIpAddress) != "", v6: deref(inst.Ipv6Address) != "",
			groups: instanceGroups(inst), subnet: deref(inst.SubnetId), vpc: deref(inst.VpcId)}}
	}
	if !anyV4 && deref(inst.PublicIpAddress) != "" {
		out[0].v4 = true // the instance's public IPv4 belongs to its primary interface
	}
	return out
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

func instanceVPCs(inst ec2types.Instance) []string {
	var ids []string
	if s := deref(inst.VpcId); s != "" {
		ids = append(ids, s)
	}
	for _, n := range inst.NetworkInterfaces {
		if s := deref(n.VpcId); s != "" {
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

func parsePrefix(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	return p.Masked(), err
}

// lbPaths returns one evidence line per internet-facing load balancer path to the port,
// and one per path whose security groups only unread sources might open (undetermined).
func lbPaths(d HostData, p cloud.Port) (out, maybe []string) {
	inst := d.Instance
	id := deref(inst.InstanceId)
	privIPs := instancePrivateIPs(inst)
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
					res := open
					if len(lb.LB.SecurityGroups) > 0 {
						res = sgExposes(d, lb.LB.SecurityGroups, lbFrontProto(l.Listener.Protocol), lport)
					}
					health := ""
					if t.TargetHealth != nil && t.TargetHealth.State != "" {
						health = " (" + string(t.TargetHealth.State) + ")"
					}
					line := fmt.Sprintf("lb %s (internet-facing) listener %s:%d -> tg %s -> %s:%d%s",
						deref(lb.LB.LoadBalancerName), l.Listener.Protocol, lport, deref(tg.TG.TargetGroupName), tid, tport, health)
					out, maybe = addLBPath(out, maybe, res, line)
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
			res := open
			if len(lb.SecurityGroups) > 0 {
				res = sgExposes(d, lb.SecurityGroups, "tcp", int(l.LoadBalancerPort))
			}
			out, maybe = addLBPath(out, maybe, res, fmt.Sprintf("classic elb %s (internet-facing) listener %s:%d -> %s:%d",
				deref(lb.LoadBalancerName), deref(l.Protocol), l.LoadBalancerPort, id, p.Port))
		}
	}
	return out, maybe
}

func addLBPath(out, maybe []string, res outcome, line string) ([]string, []string) {
	switch res {
	case open:
		out = append(out, "cloud: "+line)
	case undetermined:
		maybe = append(maybe, cloud.UndeterminedEvidence+" ("+line+": its security groups allow the port only from sources not read)")
	}
	return out, maybe
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
