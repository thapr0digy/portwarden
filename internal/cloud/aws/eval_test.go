package aws

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

const instanceID = "i-0abc"

func instance(public bool) ec2types.Instance {
	inst := ec2types.Instance{
		InstanceId:       awssdk.String(instanceID),
		SubnetId:         awssdk.String("subnet-1"),
		PrivateIpAddress: awssdk.String("10.0.1.5"),
		SecurityGroups:   []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-web")}},
	}
	if public {
		inst.PublicIpAddress = awssdk.String("54.1.2.3")
	}
	return inst
}

func withIPv6(inst ec2types.Instance) ec2types.Instance {
	inst.Ipv6Address = awssdk.String("2001:db8::5")
	return inst
}

func perm(proto string, from, to int32, cidrs ...string) ec2types.IpPermission {
	p := ec2types.IpPermission{IpProtocol: awssdk.String(proto), FromPort: awssdk.Int32(from), ToPort: awssdk.Int32(to)}
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			p.Ipv6Ranges = append(p.Ipv6Ranges, ec2types.Ipv6Range{CidrIpv6: awssdk.String(c)})
		} else {
			p.IpRanges = append(p.IpRanges, ec2types.IpRange{CidrIp: awssdk.String(c)})
		}
	}
	return p
}

func sg(id string, perms ...ec2types.IpPermission) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{GroupId: awssdk.String(id), GroupName: awssdk.String("web"), IpPermissions: perms}
}

func entry(n int32, proto string, from, to int32, cidr string, allow bool) ec2types.NetworkAclEntry {
	e := ec2types.NetworkAclEntry{RuleNumber: awssdk.Int32(n), Protocol: awssdk.String(proto), CidrBlock: awssdk.String(cidr),
		Egress: awssdk.Bool(false), RuleAction: ec2types.RuleActionDeny}
	if allow {
		e.RuleAction = ec2types.RuleActionAllow
	}
	if proto != "-1" {
		e.PortRange = &ec2types.PortRange{From: awssdk.Int32(from), To: awssdk.Int32(to)}
	}
	return e
}

func v6entry(n int32, allow bool) ec2types.NetworkAclEntry {
	e := entry(n, "-1", 0, 0, "", allow)
	e.CidrBlock, e.Ipv6CidrBlock = nil, awssdk.String("::/0")
	return e
}

// defaultNACL is AWS's default ACL: allow all, then the implicit denies, both families.
func defaultNACL() map[string]ec2types.NetworkAcl {
	return map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-1"), Entries: []ec2types.NetworkAclEntry{
		entry(100, "-1", 0, 0, "0.0.0.0/0", true), v6entry(101, true),
		entry(32767, "-1", 0, 0, "0.0.0.0/0", false), v6entry(32768, false),
	}}}
}

func egress(n int32, cidr string, allow bool) ec2types.NetworkAclEntry {
	e := entry(n, "-1", 0, 0, cidr, allow)
	e.Egress = awssdk.Bool(true)
	if strings.Contains(cidr, ":") {
		e.CidrBlock, e.Ipv6CidrBlock = nil, awssdk.String(cidr)
	}
	return e
}

func routeTable(id, subnet string, routes ...ec2types.Route) ec2types.RouteTable {
	rt := ec2types.RouteTable{RouteTableId: awssdk.String(id), VpcId: awssdk.String("vpc-1"), Routes: routes}
	if subnet == "" {
		rt.Associations = []ec2types.RouteTableAssociation{{Main: awssdk.Bool(true)}}
	} else {
		rt.Associations = []ec2types.RouteTableAssociation{{SubnetId: awssdk.String(subnet), Main: awssdk.Bool(false)}}
	}
	return rt
}

func route(dest, target string) ec2types.Route {
	r := ec2types.Route{State: ec2types.RouteStateActive}
	if strings.Contains(dest, ":") {
		r.DestinationIpv6CidrBlock = awssdk.String(dest)
	} else {
		r.DestinationCidrBlock = awssdk.String(dest)
	}
	switch {
	case strings.HasPrefix(target, "nat-"):
		r.NatGatewayId = awssdk.String(target)
	case strings.HasPrefix(target, "eigw-"):
		r.EgressOnlyInternetGatewayId = awssdk.String(target)
	case strings.HasPrefix(target, "eni-"):
		r.NetworkInterfaceId = awssdk.String(target)
	case strings.HasPrefix(target, "tgw-"):
		r.TransitGatewayId = awssdk.String(target)
	default:
		r.GatewayId = awssdk.String(target) // igw-, vpce-, local, vgw-
	}
	return r
}

// publicRoutes is a public subnet's main table: local, and both families to igw-1.
func publicRoutes() []ec2types.RouteTable {
	return []ec2types.RouteTable{routeTable("rtb-main", "", route("10.0.0.0/16", "local"), route("0.0.0.0/0", "igw-1"), route("::/0", "igw-1"))}
}

// withAWSDefaults fills what a test leaves out the way a new VPC has it: the ACL's
// outbound allow-all (both families) and a main route table to an internet gateway.
func withAWSDefaults(d HostData) HostData {
	if d.RouteTables == nil && d.RoutesErr == "" {
		d.RouteTables = publicRoutes()
	}
	for k, acl := range d.NACLs {
		hasEgress := false
		for _, e := range acl.Entries {
			hasEgress = hasEgress || (e.Egress != nil && *e.Egress)
		}
		if !hasEgress {
			acl.Entries = append(slices.Clone(acl.Entries), egress(100, "0.0.0.0/0", true), egress(101, "::/0", true))
			d.NACLs[k] = acl
		}
	}
	return d
}

func port(p int, level int) cloud.Port {
	return cloud.Port{Key: "k", Proto: "tcp", Addr: "0.0.0.0", Port: p, AgentLevel: level}
}

func TestDirectPath(t *testing.T) {
	tests := []struct {
		name     string
		data     HostData
		port     cloud.Port
		open     bool
		evidence string
	}{
		{"sg allows 0/0", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL()},
			port(443, 3), true, "cloud: sg-web (web) allows tcp/443 from 0.0.0.0/0"},
		{"port range and ipv6", HostData{Instance: withIPv6(instance(false)), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("6", 8000, 8100, "::/0"))}, NACLs: defaultNACL()},
			port(8080, 3), true, "allows tcp/8080 from ::/0"},
		{"all traffic -1", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("-1", -1, -1, "0.0.0.0/0"))}, NACLs: defaultNACL()},
			port(22, 3), true, "allows tcp/22"},
		// The user's rule (M10 review): an office's public address is the internet unless it
		// is listed in vpn_cidrs (TestVPNRanges).
		{"sg only from an office public ip is open", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 22, 22, "81.2.69.160/32"))}, NACLs: defaultNACL()},
			port(22, 3), true, "cloud: sg-web (web) allows tcp/22 from 81.2.69.160/32"},
		{"sg only from private ranges", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 22, 22, "10.0.0.0/8", "100.64.0.0/10"))}, NACLs: defaultNACL()},
			port(22, 3), false, "no security group allows tcp/22 from the internet (0.0.0.0/0); allowed only from private or VPN ranges"},
		{"sg halves add up to anywhere", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/1", "128.0.0.0/1"))}, NACLs: defaultNACL()},
			port(443, 3), true, "allows tcp/443 from 0.0.0.0/0"},
		{"udp rule does not open tcp", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("udp", 53, 53, "0.0.0.0/0"))}, NACLs: defaultNACL()},
			port(53, 3), false, "no security group"},
		{"no public address", HostData{Instance: instance(false), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL()},
			port(443, 3), false, "no public IPv4 or IPv6"},
		{"nacl deny before allow", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-2"), Entries: []ec2types.NetworkAclEntry{
				entry(200, "-1", 0, 0, "0.0.0.0/0", true),
				entry(90, "6", 443, 443, "0.0.0.0/0", false),
			}}}},
			port(443, 3), false, "acl-2 rule 90 denies tcp/443 from 0.0.0.0/0"},
		{"nacl narrow deny before allow stays open", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-4"), Entries: []ec2types.NetworkAclEntry{
				entry(50, "6", 443, 443, "81.2.69.0/24", false),
				entry(100, "-1", 0, 0, "0.0.0.0/0", true),
			}}}},
			port(443, 3), true, "acl-4 rule 100 allows tcp/443 from 0.0.0.0/0"},
		{"nacl narrow public allow then deny all is open", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 22, 22, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-5"), Entries: []ec2types.NetworkAclEntry{
				entry(100, "6", 22, 22, "81.2.69.160/32", true),
				entry(32767, "-1", 0, 0, "0.0.0.0/0", false),
			}}}},
			port(22, 3), true, "acl-5 rule 100 allows tcp/22 from 81.2.69.160/32"},
		{"nacl narrow denies covering everything", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-6"), Entries: []ec2types.NetworkAclEntry{
				entry(10, "-1", 0, 0, "0.0.0.0/1", false),
				entry(20, "-1", 0, 0, "128.0.0.0/1", false),
				entry(100, "-1", 0, 0, "0.0.0.0/0", true),
			}}}},
			port(443, 3), false, "acl-6 rule 10 denies tcp/443 from"},
		{"nacl outbound blocks tcp replies", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-7"), Entries: []ec2types.NetworkAclEntry{
				entry(100, "-1", 0, 0, "0.0.0.0/0", true),
				egressPorts(100, "6", 0, 1023, "0.0.0.0/0", true),
				egress(32767, "0.0.0.0/0", false),
			}}}},
			port(443, 3), false, "acl-7 outbound rules let no reply from tcp/443 reach the internet's ephemeral ports (1024-65535)"},
		{"nacl outbound allows some ephemeral ports", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-8"), Entries: []ec2types.NetworkAclEntry{
				entry(100, "-1", 0, 0, "0.0.0.0/0", true),
				egressPorts(90, "6", 1024, 32767, "0.0.0.0/0", false),
				egressPorts(100, "6", 1024, 65535, "0.0.0.0/0", true),
				egress(32767, "0.0.0.0/0", false),
			}}}},
			port(443, 3), true, "acl-8 rule 100 allows tcp/443"},
		{"nacl outbound does not judge udp", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("udp", 53, 53, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-9"), Entries: []ec2types.NetworkAclEntry{
				entry(100, "-1", 0, 0, "0.0.0.0/0", true),
				egress(32767, "0.0.0.0/0", false),
			}}}},
			udpPort(53, 3), true, "acl-9 rule 100 allows udp/53"},
		{"nacl narrower allow ignored, default deny", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-3"), Entries: []ec2types.NetworkAclEntry{
				entry(100, "6", 443, 443, "10.0.0.0/8", true),
				entry(32767, "-1", 0, 0, "0.0.0.0/0", false),
			}}}},
			port(443, 3), false, "rule * denies"},
		{"no route to an internet gateway", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL(),
			RouteTables: []ec2types.RouteTable{routeTable("rtb-priv", "subnet-1", route("10.0.0.0/16", "local"), route("0.0.0.0/0", "nat-1"))}},
			port(443, 3), false, "rtb-priv has no route to an internet gateway"},
		{"explicit association beats the main table", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL(),
			RouteTables: append(publicRoutes(), routeTable("rtb-priv", "subnet-1", route("10.0.0.0/16", "local")))},
			port(443, 3), false, "rtb-priv has no route"},
		{"main table applies without an association", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL(),
			RouteTables: append(publicRoutes(), routeTable("rtb-other", "subnet-9", route("0.0.0.0/0", "nat-1")))},
			port(443, 3), true, "cloud: rtb-main routes 0.0.0.0/0 to igw-1"},
		{"narrow igw route reaches part of the internet", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL(),
			RouteTables: []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("0.0.0.0/0", "nat-1"), route("81.2.69.0/24", "igw-1"))}},
			port(443, 3), true, "reachable from 81.2.69.0/24"},
		{"more specific nat route wins over igw", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 22, 22, "81.2.69.160/32"))}, NACLs: defaultNACL(),
			RouteTables: []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("0.0.0.0/0", "igw-1"), route("81.2.69.0/24", "nat-1"))}},
			port(22, 3), false, "no route to an internet gateway"},
		{"ipv6 default route to an egress-only gateway", HostData{Instance: withIPv6(instance(false)), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "::/0"))}, NACLs: defaultNACL(),
			RouteTables: []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("0.0.0.0/0", "igw-1"), route("::/0", "eigw-1"))}},
			port(443, 3), false, "rtb-1 has no route to an internet gateway for the addresses allowed in (::/0)"},
		{"blackhole igw route", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL(),
			RouteTables: []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", blackhole(route("0.0.0.0/0", "igw-1")))}},
			port(443, 3), false, "no route to an internet gateway"},
		{"unread sg and nacl count as open", HostData{Instance: instance(true)},
			port(443, 3), true, "sg-web not read (assumed open"},
		{"sg open but host firewall closed", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL()},
			port(443, 2), false, "direct path not counted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Evaluate(withAWSDefaults(tt.data), []cloud.Port{tt.port})[0]
			if v.Open != tt.open || !v.Complete || !strings.Contains(strings.Join(v.Evidence, "\n"), tt.evidence) {
				t.Fatalf("open=%v complete=%v evidence=%q", v.Open, v.Complete, v.Evidence)
			}
		})
	}
}

func egressPorts(n int32, proto string, from, to int32, cidr string, allow bool) ec2types.NetworkAclEntry {
	e := entry(n, proto, from, to, cidr, allow)
	e.Egress = awssdk.Bool(true)
	return e
}

func blackhole(r ec2types.Route) ec2types.Route {
	r.State = ec2types.RouteStateBlackhole
	return r
}

func udpPort(p int, level int) cloud.Port {
	return cloud.Port{Key: "k", Proto: "udp", Addr: "0.0.0.0", Port: p, AgentLevel: level}
}

// Undetermined: the data cannot decide, so the verdict is neither open nor complete (the
// inventory then neither raises nor lowers the listener).
func TestDirectPathUndetermined(t *testing.T) {
	base := func() HostData {
		return HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL()}
	}
	tests := []struct {
		name     string
		mod      func(*HostData)
		evidence string
	}{
		{"route tables not read", func(d *HostData) { d.RoutesErr = "UnauthorizedOperation" }, "cloud:undetermined (i-0abc: route tables not read: UnauthorizedOperation)"},
		{"no table for the subnet", func(d *HostData) {
			d.RouteTables = []ec2types.RouteTable{routeTable("rtb-x", "subnet-9", route("0.0.0.0/0", "igw-1"))}
		}, "no route table found for subnet-1"},
		{"default route to a firewall endpoint", func(d *HostData) {
			d.RouteTables = []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("0.0.0.0/0", "vpce-1"))}
		}, "rtb-1 routes 0.0.0.0/0 to vpce-1, which may forward replies to the internet"},
		{"default route to an appliance interface", func(d *HostData) {
			d.RouteTables = []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("0.0.0.0/0", "eni-9"))}
		}, "to eni-9"},
		{"default route to a transit gateway", func(d *HostData) {
			d.RouteTables = []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("0.0.0.0/0", "tgw-1"))}
		}, "to tgw-1"},
		{"prefix-list route to an igw", func(d *HostData) {
			d.RouteTables = []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("10.0.0.0/16", "local"),
				ec2types.Route{DestinationPrefixListId: awssdk.String("pl-1"), GatewayId: awssdk.String("igw-1"), State: ec2types.RouteStateActive})}
		}, "rtb-1 routes a prefix list to igw-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := base()
			tt.mod(&d)
			v := Evaluate(withAWSDefaults(d), []cloud.Port{port(443, 3)})[0]
			if v.Open || v.Complete || !strings.Contains(strings.Join(v.Evidence, "\n"), tt.evidence) {
				t.Fatalf("open=%v complete=%v evidence=%q", v.Open, v.Complete, v.Evidence)
			}
		})
	}
	// A load balancer path still opens a listener whose direct path is undetermined.
	d := v2Data(elbv2types.LoadBalancerSchemeEnumInternetFacing, instanceID, 8080, nil)
	d.Instance = instance(true)
	d.SecurityGroups["sg-web"] = sg("sg-web", perm("tcp", 8080, 8080, "0.0.0.0/0"))
	d.NACLs = defaultNACL()
	d.RoutesErr = "denied"
	if v := Evaluate(withAWSDefaults(d), []cloud.Port{port(8080, 3)})[0]; !v.Open || !v.Complete {
		t.Fatalf("lb path with an undetermined direct path: %+v", v)
	}
	// The agent's level below host_firewall_open never counts the direct path, so an
	// undetermined one does not make the verdict incomplete.
	d2 := base()
	d2.RoutesErr = "denied"
	if v := Evaluate(withAWSDefaults(d2), []cloud.Port{port(443, 2)})[0]; v.Open || !v.Complete {
		t.Fatalf("bound listener: %+v", v)
	}
}

// The operator's VPN ranges never count as the internet, on every layer.
func TestVPNRanges(t *testing.T) {
	d := HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
		"sg-web": sg("sg-web", perm("tcp", 22, 22, "81.2.69.160/32"))}, NACLs: defaultNACL()}
	d.Policy = reach.NewPolicy([]netip.Prefix{netip.MustParsePrefix("81.2.69.160/28")})
	if v := Evaluate(withAWSDefaults(d), []cloud.Port{port(22, 3)})[0]; v.Open {
		t.Fatalf("ssh from a VPN range opened: %+v", v)
	}
	d.SecurityGroups["sg-web"] = sg("sg-web", perm("tcp", 22, 22, "81.2.69.160/32", "81.2.69.200/32"))
	v := Evaluate(withAWSDefaults(d), []cloud.Port{port(22, 3)})[0]
	if !v.Open || !strings.Contains(strings.Join(v.Evidence, "\n"), "allows tcp/22 from 81.2.69.200/32") {
		t.Fatalf("an unlisted public address: %+v", v)
	}
}

func v2Data(scheme elbv2types.LoadBalancerSchemeEnum, targetID string, targetPort int32, lbSGs []string) HostData {
	tgArn := "arn:tg/web"
	return HostData{
		Instance:       instance(false),
		SecurityGroups: map[string]ec2types.SecurityGroup{"sg-alb": sg("sg-alb", perm("tcp", 443, 443, "0.0.0.0/0"))},
		LBs: RegionLBs{V2: []V2LB{{
			LB: elbv2types.LoadBalancer{LoadBalancerName: awssdk.String("web-alb"), Scheme: scheme, SecurityGroups: lbSGs},
			Listeners: []V2Listener{{Listener: elbv2types.Listener{Port: awssdk.Int32(443), Protocol: elbv2types.ProtocolEnumHttps,
				DefaultActions: []elbv2types.Action{{Type: elbv2types.ActionTypeEnumFixedResponse}}},
				RuleActions: []elbv2types.Action{{Type: elbv2types.ActionTypeEnumForward,
					ForwardConfig: &elbv2types.ForwardActionConfig{TargetGroups: []elbv2types.TargetGroupTuple{{TargetGroupArn: awssdk.String(tgArn)}}}}}}},
			TargetGroups: map[string]V2TargetGroup{tgArn: {
				TG: elbv2types.TargetGroup{TargetGroupName: awssdk.String("web-tg"), Port: awssdk.Int32(8080), Protocol: elbv2types.ProtocolEnumHttp},
				Targets: []elbv2types.TargetHealthDescription{{Target: &elbv2types.TargetDescription{Id: awssdk.String(targetID), Port: awssdk.Int32(targetPort)},
					TargetHealth: &elbv2types.TargetHealth{State: elbv2types.TargetHealthStateEnumHealthy}}},
			}},
		}}},
	}
}

func TestLoadBalancerPath(t *testing.T) {
	v := Evaluate(v2Data(elbv2types.LoadBalancerSchemeEnumInternetFacing, instanceID, 8080, []string{"sg-alb"}), []cloud.Port{port(8080, 2)})[0]
	want := "cloud: lb web-alb (internet-facing) listener HTTPS:443 -> tg web-tg -> i-0abc:8080 (healthy)"
	if !v.Open || !strings.Contains(strings.Join(v.Evidence, "\n"), want) {
		t.Fatalf("alb by instance: %+v", v)
	}
	if v := Evaluate(v2Data(elbv2types.LoadBalancerSchemeEnumInternetFacing, "10.0.1.5", 8080, nil), []cloud.Port{port(8080, 2)})[0]; !v.Open {
		t.Fatalf("ip target, nlb without sgs: %+v", v)
	}
	if v := Evaluate(v2Data(elbv2types.LoadBalancerSchemeEnumInternal, instanceID, 8080, nil), []cloud.Port{port(8080, 2)})[0]; v.Open {
		t.Fatalf("internal lb opened it: %+v", v)
	}
	if v := Evaluate(v2Data(elbv2types.LoadBalancerSchemeEnumInternetFacing, instanceID, 9090, nil), []cloud.Port{port(8080, 2)})[0]; v.Open {
		t.Fatalf("other target port opened it: %+v", v)
	}
	closedSG := v2Data(elbv2types.LoadBalancerSchemeEnumInternetFacing, instanceID, 8080, []string{"sg-alb"})
	closedSG.SecurityGroups["sg-alb"] = sg("sg-alb", perm("tcp", 443, 443, "10.0.0.0/8"))
	if v := Evaluate(closedSG, []cloud.Port{port(8080, 2)})[0]; v.Open {
		t.Fatalf("lb sg closed to 0/0 opened it: %+v", v)
	}
	if v := Evaluate(v2Data(elbv2types.LoadBalancerSchemeEnumInternetFacing, instanceID, 8080, nil), []cloud.Port{port(8080, 1)})[0]; v.Open {
		t.Fatalf("a local listener cannot be opened by an lb: %+v", v)
	}
}

func TestClassicELB(t *testing.T) {
	d := HostData{Instance: instance(false), LBs: RegionLBs{Classic: []elbtypes.LoadBalancerDescription{{
		LoadBalancerName: awssdk.String("legacy"), Scheme: awssdk.String("internet-facing"),
		Instances: []elbtypes.Instance{{InstanceId: awssdk.String(instanceID)}},
		ListenerDescriptions: []elbtypes.ListenerDescription{{Listener: &elbtypes.Listener{
			Protocol: awssdk.String("HTTP"), LoadBalancerPort: 80, InstancePort: awssdk.Int32(8000), InstanceProtocol: awssdk.String("HTTP")}}},
	}}}}
	v := Evaluate(d, []cloud.Port{port(8000, 2)})[0]
	if !v.Open || !strings.Contains(strings.Join(v.Evidence, "\n"), "classic elb legacy (internet-facing) listener HTTP:80 -> i-0abc:8000") {
		t.Fatalf("%+v", v)
	}
}

// Each interface is judged with its own subnet's ACL: a private interface in a denying
// subnet does not hide the public one.
func TestPerInterface(t *testing.T) {
	inst := ec2types.Instance{InstanceId: awssdk.String(instanceID), SubnetId: awssdk.String("subnet-a"),
		NetworkInterfaces: []ec2types.InstanceNetworkInterface{
			{NetworkInterfaceId: awssdk.String("eni-a"), SubnetId: awssdk.String("subnet-a"),
				Association: &ec2types.InstanceNetworkInterfaceAssociation{PublicIp: awssdk.String("54.1.2.3")},
				Groups:      []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-web")}}},
			{NetworkInterfaceId: awssdk.String("eni-b"), SubnetId: awssdk.String("subnet-b"),
				Groups: []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-web")}}},
		}}
	d := HostData{Instance: inst, SecurityGroups: map[string]ec2types.SecurityGroup{"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
		NACLs: map[string]ec2types.NetworkAcl{
			"subnet-a": {NetworkAclId: awssdk.String("acl-a"), Entries: []ec2types.NetworkAclEntry{entry(100, "-1", 0, 0, "0.0.0.0/0", true)}},
			"subnet-b": {NetworkAclId: awssdk.String("acl-b"), Entries: []ec2types.NetworkAclEntry{entry(100, "-1", 0, 0, "0.0.0.0/0", false)}},
		}}
	if v := Evaluate(withAWSDefaults(d), []cloud.Port{port(443, 3)})[0]; !v.Open {
		t.Fatalf("public interface in an allowing subnet: %+v", v)
	}
}

// An IPv6 deny with a lower rule number does not decide for IPv4 traffic.
func TestNACLFamiliesSeparate(t *testing.T) {
	v6deny := entry(90, "6", 22, 22, "", false)
	v6deny.CidrBlock, v6deny.Ipv6CidrBlock = nil, awssdk.String("::/0")
	d := HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{"sg-web": sg("sg-web", perm("tcp", 22, 22, "0.0.0.0/0"))},
		NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-1"), Entries: []ec2types.NetworkAclEntry{
			v6deny, entry(100, "6", 22, 22, "0.0.0.0/0", true)}}}}
	d = withAWSDefaults(d)
	if v := Evaluate(d, []cloud.Port{port(22, 3)})[0]; !v.Open {
		t.Fatalf("ipv4 path decided by an ipv6 rule: %+v", v)
	}
	// ::/0 in a security group does not open an IPv4-only instance.
	d.SecurityGroups["sg-web"] = sg("sg-web", perm("tcp", 22, 22, "::/0"))
	if v := Evaluate(d, []cloud.Port{port(22, 3)})[0]; v.Open {
		t.Fatalf("::/0 opened an ipv4-only instance: %+v", v)
	}
}
