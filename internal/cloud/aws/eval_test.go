package aws

import (
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/thapr0digy/portwarden/internal/cloud"
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

func defaultNACL() map[string]ec2types.NetworkAcl {
	return map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-1"), Entries: []ec2types.NetworkAclEntry{
		entry(100, "-1", 0, 0, "0.0.0.0/0", true),
		entry(32767, "-1", 0, 0, "0.0.0.0/0", false),
	}}}
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
		{"port range and ipv6", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("6", 8000, 8100, "::/0"))}, NACLs: defaultNACL()},
			port(8080, 3), true, "allows tcp/8080 from ::/0"},
		{"all traffic -1", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("-1", -1, -1, "0.0.0.0/0"))}, NACLs: defaultNACL()},
			port(22, 3), true, "allows tcp/22"},
		{"sg only from office", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 22, 22, "203.0.113.0/24"))}, NACLs: defaultNACL()},
			port(22, 3), false, "no security group allows tcp/22 from 0/0"},
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
			port(443, 3), false, "cloud: acl-2 rule 90 denies tcp/443 from 0.0.0.0/0"},
		{"nacl narrower allow ignored, default deny", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))},
			NACLs: map[string]ec2types.NetworkAcl{"subnet-1": {NetworkAclId: awssdk.String("acl-3"), Entries: []ec2types.NetworkAclEntry{
				entry(100, "6", 443, 443, "10.0.0.0/8", true),
				entry(32767, "-1", 0, 0, "0.0.0.0/0", false),
			}}}},
			port(443, 3), false, "rule * denies"},
		{"unread sg and nacl count as open", HostData{Instance: instance(true)},
			port(443, 3), true, "sg-web not read (assumed open"},
		{"sg open but host firewall closed", HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
			"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL()},
			port(443, 2), false, "direct path not counted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Evaluate(tt.data, []cloud.Port{tt.port})[0]
			if v.Open != tt.open || !strings.Contains(strings.Join(v.Evidence, "\n"), tt.evidence) {
				t.Fatalf("open=%v evidence=%q", v.Open, v.Evidence)
			}
		})
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
