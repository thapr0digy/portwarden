package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/thapr0digy/portwarden/internal/cloud"
)

// Handwritten API responses in each service's wire format (EC2 query protocol, ELB
// awsquery), element names checked against the SDK deserializers (ec2 v1.343.0,
// elasticloadbalancingv2 v1.63.6, elasticloadbalancing v1.41.6).
var responses = map[string]string{
	"ec2:DescribeInstances": `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r1</requestId>
<reservationSet><item><reservationId>r-1</reservationId><instancesSet><item>
  <instanceId>i-0abc</instanceId><subnetId>subnet-1</subnetId><vpcId>vpc-1</vpcId>
  <privateIpAddress>10.0.1.5</privateIpAddress><ipAddress>54.1.2.3</ipAddress>
  <groupSet><item><groupId>sg-web</groupId><groupName>web</groupName></item></groupSet>
  <networkInterfaceSet><item><networkInterfaceId>eni-1</networkInterfaceId><subnetId>subnet-1</subnetId>
    <privateIpAddress>10.0.1.5</privateIpAddress>
    <association><publicIp>54.1.2.3</publicIp></association>
    <groupSet><item><groupId>sg-web</groupId><groupName>web</groupName></item></groupSet>
  </item></networkInterfaceSet>
</item></instancesSet></item></reservationSet>
</DescribeInstancesResponse>`,
	"ec2:DescribeSecurityGroups": `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r2</requestId>
<securityGroupInfo>
  <item><groupId>sg-web</groupId><groupName>web</groupName><vpcId>vpc-1</vpcId>
    <ipPermissions>
      <item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort>
        <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges><ipv6Ranges/></item>
      <item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort>
        <ipRanges><item><cidrIp>203.0.113.0/24</cidrIp></item></ipRanges></item>
      <item><ipProtocol>tcp</ipProtocol><fromPort>8080</fromPort><toPort>8080</toPort>
        <groups><item><groupId>sg-alb</groupId></item></groups></item>
      <item><ipProtocol>tcp</ipProtocol><fromPort>3389</fromPort><toPort>3389</toPort>
        <prefixListIds><item><prefixListId>pl-office</prefixListId><description>office</description></item></prefixListIds></item>
    </ipPermissions>
  </item>
  <item><groupId>sg-alb</groupId><groupName>alb</groupName>
    <ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>80</fromPort><toPort>80</toPort>
      <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions>
  </item>
</securityGroupInfo>
</DescribeSecurityGroupsResponse>`,
	"ec2:DescribeNetworkAcls": `<DescribeNetworkAclsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r3</requestId>
<networkAclSet><item><networkAclId>acl-1</networkAclId><vpcId>vpc-1</vpcId><default>true</default>
  <entrySet>
    <item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>
    <item><ruleNumber>32767</ruleNumber><protocol>-1</protocol><ruleAction>deny</ruleAction><egress>false</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>
    <item><ruleNumber>100</ruleNumber><protocol>-1</protocol><ruleAction>allow</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>
    <item><ruleNumber>32767</ruleNumber><protocol>-1</protocol><ruleAction>deny</ruleAction><egress>true</egress><cidrBlock>0.0.0.0/0</cidrBlock></item>
  </entrySet>
  <associationSet><item><networkAclAssociationId>aclassoc-1</networkAclAssociationId><networkAclId>acl-1</networkAclId><subnetId>subnet-1</subnetId></item></associationSet>
</item></networkAclSet>
</DescribeNetworkAclsResponse>`,
	// The subnet has no association of its own: the VPC's main table applies.
	"ec2:DescribeRouteTables": `<DescribeRouteTablesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r3b</requestId>
<routeTableSet>
  <item><routeTableId>rtb-main</routeTableId><vpcId>vpc-1</vpcId>
    <routeSet>
      <item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId><state>active</state><origin>CreateRouteTable</origin></item>
      <item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><gatewayId>igw-1</gatewayId><state>active</state><origin>CreateRoute</origin></item>
    </routeSet>
    <associationSet><item><routeTableAssociationId>rtbassoc-1</routeTableAssociationId><routeTableId>rtb-main</routeTableId><main>true</main>
      <associationState><state>associated</state></associationState></item></associationSet>
  </item>
  <item><routeTableId>rtb-private</routeTableId><vpcId>vpc-1</vpcId>
    <routeSet><item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><natGatewayId>nat-1</natGatewayId><state>active</state></item></routeSet>
    <associationSet><item><routeTableAssociationId>rtbassoc-2</routeTableAssociationId><routeTableId>rtb-private</routeTableId><subnetId>subnet-9</subnetId><main>false</main></item></associationSet>
  </item>
</routeTableSet>
</DescribeRouteTablesResponse>`,
	"ec2:GetManagedPrefixListEntries": `<GetManagedPrefixListEntriesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r3c</requestId>
<entrySet>
  <item><cidr>81.2.69.160/28</cidr><description>office</description></item>
  <item><cidr>10.20.0.0/16</cidr></item>
</entrySet>
</GetManagedPrefixListEntriesResponse>`,
	// One gateway endpoint (S3) and one Gateway Load Balancer endpoint: the filter asks for
	// gateways only, but the type is checked on every item.
	"ec2:DescribeVpcEndpoints": `<DescribeVpcEndpointsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r3d</requestId>
<vpcEndpointSet>
  <item><vpcEndpointId>vpce-gw</vpcEndpointId><vpcEndpointType>Gateway</vpcEndpointType><vpcId>vpc-1</vpcId>
    <serviceName>com.amazonaws.eu-west-1.s3</serviceName><state>available</state></item>
  <item><vpcEndpointId>vpce-gwlb</vpcEndpointId><vpcEndpointType>GatewayLoadBalancer</vpcEndpointType><vpcId>vpc-1</vpcId><state>available</state></item>
</vpcEndpointSet>
</DescribeVpcEndpointsResponse>`,
	"elbv2:DescribeLoadBalancers": `<DescribeLoadBalancersResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/">
<DescribeLoadBalancersResult><LoadBalancers>
  <member><LoadBalancerArn>arn:lb/web</LoadBalancerArn><LoadBalancerName>web-alb</LoadBalancerName><Scheme>internet-facing</Scheme>
    <Type>application</Type><SecurityGroups><member>sg-alb</member></SecurityGroups><State><Code>active</Code></State></member>
  <member><LoadBalancerArn>arn:lb/int</LoadBalancerArn><LoadBalancerName>int-nlb</LoadBalancerName><Scheme>internal</Scheme><Type>network</Type></member>
</LoadBalancers></DescribeLoadBalancersResult>
<ResponseMetadata><RequestId>r4</RequestId></ResponseMetadata>
</DescribeLoadBalancersResponse>`,
	"elbv2:DescribeListeners": `<DescribeListenersResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/">
<DescribeListenersResult><Listeners>
  <member><ListenerArn>arn:listener/web/80</ListenerArn><LoadBalancerArn>arn:lb/web</LoadBalancerArn><Port>80</Port><Protocol>HTTP</Protocol>
    <DefaultActions><member><Type>forward</Type><TargetGroupArn>arn:tg/web</TargetGroupArn></member></DefaultActions></member>
</Listeners></DescribeListenersResult>
<ResponseMetadata><RequestId>r5</RequestId></ResponseMetadata>
</DescribeListenersResponse>`,
	"elbv2:DescribeRules": `<DescribeRulesResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/">
<DescribeRulesResult><Rules>
  <member><RuleArn>arn:rule/default</RuleArn><IsDefault>true</IsDefault><Priority>default</Priority>
    <Actions><member><Type>forward</Type><TargetGroupArn>arn:tg/web</TargetGroupArn></member></Actions></member>
</Rules></DescribeRulesResult>
<ResponseMetadata><RequestId>r6</RequestId></ResponseMetadata>
</DescribeRulesResponse>`,
	"elbv2:DescribeTargetGroups": `<DescribeTargetGroupsResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/">
<DescribeTargetGroupsResult><TargetGroups>
  <member><TargetGroupArn>arn:tg/web</TargetGroupArn><TargetGroupName>web-tg</TargetGroupName><Port>8080</Port><Protocol>HTTP</Protocol>
    <TargetType>instance</TargetType><LoadBalancerArns><member>arn:lb/web</member></LoadBalancerArns></member>
</TargetGroups></DescribeTargetGroupsResult>
<ResponseMetadata><RequestId>r7</RequestId></ResponseMetadata>
</DescribeTargetGroupsResponse>`,
	"elbv2:DescribeTargetHealth": `<DescribeTargetHealthResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/">
<DescribeTargetHealthResult><TargetHealthDescriptions>
  <member><Target><Id>i-0abc</Id><Port>8080</Port></Target><TargetHealth><State>healthy</State></TargetHealth></member>
</TargetHealthDescriptions></DescribeTargetHealthResult>
<ResponseMetadata><RequestId>r8</RequestId></ResponseMetadata>
</DescribeTargetHealthResponse>`,
	"elb:DescribeLoadBalancers": `<DescribeLoadBalancersResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2012-06-01/">
<DescribeLoadBalancersResult><LoadBalancerDescriptions>
  <member><LoadBalancerName>legacy</LoadBalancerName><Scheme>internet-facing</Scheme>
    <Instances><member><InstanceId>i-0abc</InstanceId></member></Instances>
    <ListenerDescriptions><member><Listener><Protocol>TCP</Protocol><LoadBalancerPort>2222</LoadBalancerPort>
      <InstanceProtocol>TCP</InstanceProtocol><InstancePort>22</InstancePort></Listener></member></ListenerDescriptions>
  </member>
</LoadBalancerDescriptions></DescribeLoadBalancersResult>
<ResponseMetadata><RequestId>r9</RequestId></ResponseMetadata>
</DescribeLoadBalancersResponse>`,
}

// fakeAWS answers the query-protocol calls; elbv2 and Classic ELB share the action name
// DescribeLoadBalancers and differ by API version.
type fakeAWS struct {
	failELB bool
	mu      sync.Mutex
	calls   []string
	nacl    string // the association.subnet-id filter value seen
	routes  string // the vpc-id filter value seen
	// failRoutes answers DescribeRouteTables with UnauthorizedOperation (an M5 IAM policy).
	failRoutes bool
	// failPrefixLists does the same for GetManagedPrefixListEntries.
	failPrefixLists bool
	prefixList      string // the PrefixListId seen
	// overrides replace responses by key ("ec2:DescribeSecurityGroups").
	overrides map[string]string
	// throttlePrefixLists answers GetManagedPrefixListEntries with RequestLimitExceeded.
	throttlePrefixLists bool
	// pagePrefixLists answers every GetManagedPrefixListEntries page with a NextToken.
	pagePrefixLists bool
	// blockPrefixLists holds GetManagedPrefixListEntries until the client gives up.
	blockPrefixLists bool
	// failEndpoints answers DescribeVpcEndpoints with UnauthorizedOperation.
	failEndpoints bool
	endpointsFilter string // the Filter.1 seen on DescribeVpcEndpoints
}

// count returns how many times key was called.
func (f *fakeAWS) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == key {
			n++
		}
	}
	return n
}

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	action := r.Form.Get("Action")
	svc := map[string]string{"2016-11-15": "ec2", "2015-12-01": "elbv2", "2012-06-01": "elb"}[r.Form.Get("Version")]
	key := svc + ":" + action
	f.mu.Lock()
	f.calls = append(f.calls, key)
	if action == "DescribeNetworkAcls" {
		f.nacl = r.Form.Get("Filter.1.Name") + "=" + r.Form.Get("Filter.1.Value.1")
	}
	if action == "DescribeRouteTables" {
		f.routes = r.Form.Get("Filter.1.Name") + "=" + r.Form.Get("Filter.1.Value.1")
	}
	if action == "GetManagedPrefixListEntries" {
		f.prefixList = r.Form.Get("PrefixListId")
	}
	if action == "DescribeVpcEndpoints" {
		f.endpointsFilter = r.Form.Get("Filter.1.Name") + "=" + r.Form.Get("Filter.1.Value.1")
	}
	f.mu.Unlock()
	if action == "GetManagedPrefixListEntries" {
		switch {
		case f.blockPrefixLists:
			<-r.Context().Done()
			return
		case f.throttlePrefixLists:
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`<Response><Errors><Error><Code>RequestLimitExceeded</Code><Message>Request limit exceeded.</Message></Error></Errors><RequestID>x</RequestID></Response>`))
			return
		case f.pagePrefixLists:
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<GetManagedPrefixListEntriesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>p</requestId>
<entrySet><item><cidr>81.2.69.160/28</cidr></item></entrySet><nextToken>more</nextToken></GetManagedPrefixListEntriesResponse>`))
			return
		}
	}
	if f.failEndpoints && action == "DescribeVpcEndpoints" {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>not authorized</Message></Error></Errors><RequestID>x</RequestID></Response>`))
		return
	}
	if (f.failRoutes && action == "DescribeRouteTables") || (f.failPrefixLists && action == "GetManagedPrefixListEntries") {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>not authorized</Message></Error></Errors><RequestID>x</RequestID></Response>`))
		return
	}
	if f.failELB && svc != "ec2" {
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ServiceUnavailable</Code><Message>down</Message></Error><RequestId>x</RequestId></ErrorResponse>`))
		return
	}
	body, ok := f.overrides[key]
	if !ok {
		body, ok = responses[key]
	}
	if !ok {
		http.Error(w, "unexpected call "+key, 400)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(body))
}

func TestProviderAgainstRecordedAPI(t *testing.T) {
	fake := &fakeAWS{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := awssdk.Config{
		Region:           "eu-west-1",
		Credentials:      credentials.NewStaticCredentialsProvider("AKIDTEST", "test-secret-not-real", ""),
		Retryer:          func() awssdk.Retryer { return awssdk.NopRetryer{} },
		RetryMaxAttempts: 1,
	}
	p := NewWithConfig(cfg, Options{Endpoint: srv.URL})
	host := cloud.Host{ID: "h1", Cloud: "aws", InstanceID: "i-0abc", Region: "eu-west-1"}
	ports := []cloud.Port{
		{Key: "a", Proto: "tcp", Addr: "0.0.0.0", Port: 443, AgentLevel: 3},
		{Key: "b", Proto: "tcp", Addr: "0.0.0.0", Port: 22, AgentLevel: 3},
		{Key: "c", Proto: "tcp", Addr: "0.0.0.0", Port: 8080, AgentLevel: 2},
		{Key: "d", Proto: "udp", Addr: "0.0.0.0", Port: 53, AgentLevel: 3},
		{Key: "e", Proto: "tcp", Addr: "0.0.0.0", Port: 3389, AgentLevel: 3},
	}
	vs, err := p.Evaluate(context.Background(), host, ports)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"a": "cloud: sg-web (web) allows tcp/443 from 0.0.0.0/0",
		"b": "cloud: classic elb legacy (internet-facing) listener TCP:2222 -> i-0abc:22",
		"c": "cloud: lb web-alb (internet-facing) listener HTTP:80 -> tg web-tg -> i-0abc:8080 (healthy)",
		"e": "cloud: sg-web (web) allows tcp/3389 from 81.2.69.160/28",
	}
	for _, v := range vs {
		ev := strings.Join(v.Evidence, "\n")
		if w, ok := want[v.Key]; ok {
			if !v.Open || !strings.Contains(ev, w) {
				t.Errorf("%s: open=%v evidence:\n%s", v.Key, v.Open, ev)
			}
		} else if v.Open {
			t.Errorf("%s opened: %s", v.Key, ev)
		}
	}
	if fake.nacl != "association.subnet-id=subnet-1" {
		t.Errorf("nacl filter %q", fake.nacl)
	}
	if fake.routes != "vpc-id=vpc-1" {
		t.Errorf("route table filter %q", fake.routes)
	}
	if fake.prefixList != "pl-office" {
		t.Errorf("prefix list read %q", fake.prefixList)
	}
	for _, c := range fake.calls {
		action := c[strings.Index(c, ":")+1:]
		if !strings.HasPrefix(action, "Describe") && action != "GetManagedPrefixListEntries" {
			t.Errorf("non-read-only call %s", c)
		}
	}
	// The region's load balancers are cached: a second host evaluation reads only EC2.
	n := len(fake.calls)
	if _, err := p.Evaluate(context.Background(), host, ports[:1]); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(fake.calls[n:], func(c string) bool { return strings.HasPrefix(c, "elb") }) {
		t.Errorf("load balancers re-read within the TTL: %v", fake.calls[n:])
	}
	p.now = func() time.Time { return time.Now().Add(time.Hour) }
	n = len(fake.calls)
	if _, err := p.Evaluate(context.Background(), host, ports[:1]); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fake.calls[n:], "elbv2:DescribeLoadBalancers") {
		t.Errorf("load balancers not re-read after the TTL: %v", fake.calls[n:])
	}
}

func TestProviderErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors><RequestID>x</RequestID></Response>`))
	}))
	defer srv.Close()
	cfg := awssdk.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "x", ""),
		Retryer: func() awssdk.Retryer { return awssdk.NopRetryer{} }}
	p := NewWithConfig(cfg, Options{Endpoint: srv.URL})
	if _, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: "i-1", Region: "eu-west-1"}, nil); err == nil ||
		!strings.Contains(err.Error(), "UnauthorizedOperation") {
		t.Fatalf("err %v", err)
	}
	if _, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: "i-1"}, nil); err == nil {
		t.Fatal("missing region accepted")
	}
}

// A load-balancer read that fails does not fail the host: its direct-path verdicts come
// back, marked incomplete (so they may raise but never lower), with the reason.
func TestLBFailureIsIncompleteNotFatal(t *testing.T) {
	fake := &fakeAWS{failELB: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := awssdk.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "x", ""),
		Retryer: func() awssdk.Retryer { return awssdk.NopRetryer{} }}
	p := NewWithConfig(cfg, Options{Endpoint: srv.URL})
	vs, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: "i-0abc", Region: "eu-west-1"},
		[]cloud.Port{{Key: "a", Proto: "tcp", Addr: "0.0.0.0", Port: 443, AgentLevel: 3}, {Key: "c", Proto: "tcp", Addr: "0.0.0.0", Port: 8080, AgentLevel: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !vs[0].Open || vs[0].Complete || vs[1].Open || vs[1].Complete ||
		!strings.Contains(strings.Join(vs[1].Evidence, "\n"), "cloud:incomplete (load balancers unreadable") {
		t.Fatalf("%+v", vs)
	}
}

// An IAM policy from before M10 (no ec2:DescribeRouteTables) does not fail the host: its
// direct paths are undetermined (not open, not complete), so nothing is raised or lowered.
func TestRouteTablesUnreadableIsUndetermined(t *testing.T) {
	fake := &fakeAWS{failRoutes: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := awssdk.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "x", ""),
		Retryer: func() awssdk.Retryer { return awssdk.NopRetryer{} }}
	p := NewWithConfig(cfg, Options{Endpoint: srv.URL})
	vs, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: "i-0abc", Region: "eu-west-1"},
		[]cloud.Port{{Key: "a", Proto: "tcp", Addr: "0.0.0.0", Port: 443, AgentLevel: 3}})
	if err != nil {
		t.Fatal(err)
	}
	ev := strings.Join(vs[0].Evidence, "\n")
	if vs[0].Open || vs[0].Complete || !strings.Contains(ev, "cloud:undetermined (eni-1: route tables not read") || !strings.Contains(ev, "UnauthorizedOperation") {
		t.Fatalf("%+v", vs[0])
	}
}

func TestHostIdentityValidated(t *testing.T) {
	p := NewWithClients(func(string) Clients { return Clients{} }, Options{Regions: []string{"eu-west-1"}})
	for _, h := range []cloud.Host{{InstanceID: "i-0abc", Region: "eu-west-2"}, {InstanceID: "i-0abc", Region: "../x"},
		{InstanceID: "sg-123", Region: "eu-west-1"}} {
		if _, err := p.Evaluate(context.Background(), h, nil); err == nil {
			t.Errorf("%+v accepted", h)
		}
	}
}

// A prefix list that cannot be read (customer- or AWS-managed) does not fail the host: the
// rule naming it is undetermined, the others are judged as usual.
func TestPrefixListUnreadableIsUndetermined(t *testing.T) {
	fake := &fakeAWS{failPrefixLists: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := awssdk.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "x", ""),
		Retryer: func() awssdk.Retryer { return awssdk.NopRetryer{} }}
	p := NewWithConfig(cfg, Options{Endpoint: srv.URL})
	vs, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: "i-0abc", Region: "eu-west-1"},
		[]cloud.Port{{Key: "e", Proto: "tcp", Addr: "0.0.0.0", Port: 3389, AgentLevel: 3}, {Key: "a", Proto: "tcp", Addr: "0.0.0.0", Port: 443, AgentLevel: 3}})
	if err != nil {
		t.Fatal(err)
	}
	ev := strings.Join(vs[0].Evidence, "\n")
	if vs[0].Open || vs[0].Complete || !strings.Contains(ev, "prefix list pl-office not read") || !strings.Contains(ev, "UnauthorizedOperation") {
		t.Fatalf("%+v", vs[0])
	}
	if !vs[1].Open || !vs[1].Complete {
		t.Fatalf("other rules: %+v", vs[1])
	}
}
