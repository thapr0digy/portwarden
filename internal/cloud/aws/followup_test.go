package aws

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// Tests for the M10 follow-up review (2026-11-05), named after its five items.

const (
	plRead    = "ec2:GetManagedPrefixListEntries"
	rtRead    = "ec2:DescribeRouteTables"
	euWest1   = "eu-west-1"
	rdpPortNo = 3389
)

func fakeProvider(t *testing.T, fake *fakeAWS, opts Options) *Provider {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	cfg := awssdk.Config{Region: euWest1, Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "x", ""),
		Retryer: func() awssdk.Retryer { return awssdk.NopRetryer{} }, RetryMaxAttempts: 1}
	opts.Endpoint = srv.URL
	return NewWithConfig(cfg, opts)
}

func evalRDP(t *testing.T, p *Provider) cloud.Verdict {
	t.Helper()
	vs, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: instanceID, Region: euWest1},
		[]cloud.Port{{Key: "e", Proto: "tcp", Addr: "0.0.0.0", Port: rdpPortNo, AgentLevel: 3}})
	if err != nil {
		t.Fatal(err)
	}
	return vs[0]
}

func undeterminedVerdict(v cloud.Verdict) bool { return !v.Open && !v.Complete }

// Item 1: a prefix list is read at most once per region per TTL, by every host.
func TestItem1PrefixListCachedPerRegion(t *testing.T) {
	fake := &fakeAWS{}
	p := fakeProvider(t, fake, Options{})
	for range 3 {
		if v := evalRDP(t, p); !v.Open {
			t.Fatalf("%+v", v)
		}
	}
	if n := fake.count(plRead); n != 1 {
		t.Fatalf("prefix list read %d times within the TTL, want 1", n)
	}
	p.now = func() time.Time { return time.Now().Add(time.Hour) }
	evalRDP(t, p)
	if n := fake.count(plRead); n != 2 {
		t.Fatalf("prefix list read %d times after the TTL, want 2", n)
	}
}

// Item 1: a throttled read is cached as an error: undetermined, and not retried by the
// next host within the TTL.
func TestItem1PrefixListErrorCached(t *testing.T) {
	fake := &fakeAWS{throttlePrefixLists: true}
	p := fakeProvider(t, fake, Options{})
	for range 2 {
		v := evalRDP(t, p)
		ev := strings.Join(v.Evidence, "\n")
		if !undeterminedVerdict(v) || !strings.Contains(ev, "prefix list pl-office not read") || !strings.Contains(ev, "RequestLimitExceeded") {
			t.Fatalf("%+v", v)
		}
	}
	if n := fake.count(plRead); n != 1 {
		t.Fatalf("throttled prefix list read %d times, want 1 (cached)", n)
	}
}

// Item 1: more pages than MaxPages: the list is truncated, so undetermined, and cached.
func TestItem1PrefixListTruncatedPages(t *testing.T) {
	fake := &fakeAWS{pagePrefixLists: true}
	p := fakeProvider(t, fake, Options{MaxPages: 2})
	for range 2 {
		v := evalRDP(t, p)
		if !undeterminedVerdict(v) || !strings.Contains(strings.Join(v.Evidence, "\n"), "pl-office not read: entries truncated") {
			t.Fatalf("%+v", v)
		}
	}
	if n := fake.count(plRead); n != 2 {
		t.Fatalf("pages read %d, want 2 (one truncated read of 2 pages, then cached)", n)
	}
}

// Item 1: a read cut short by this host's deadline is undetermined for this host and not
// cached: the next host reads the list again. Route tables are read before it.
func TestItem1DeadlineNotCached(t *testing.T) {
	fake := &fakeAWS{blockPrefixLists: true}
	p := fakeProvider(t, fake, Options{Timeout: 500 * time.Millisecond})
	v := evalRDP(t, p)
	ev := strings.Join(v.Evidence, "\n")
	if !undeterminedVerdict(v) || !strings.Contains(ev, "prefix list pl-office not read") {
		t.Fatalf("%+v", v)
	}
	if strings.Contains(ev, "route tables not read") {
		t.Fatalf("route tables starved by the prefix-list read: %s", ev)
	}
	fake.mu.Lock()
	fake.blockPrefixLists = false
	fake.mu.Unlock()
	if v := evalRDP(t, p); !v.Open {
		t.Fatalf("second host: %+v", v)
	}
	if n := fake.count(plRead); n != 2 {
		t.Fatalf("prefix list read %d times, want 2 (the timed-out read is not cached)", n)
	}
}

// Item 1: route tables are read before any prefix list.
func TestItem1RouteTablesBeforePrefixLists(t *testing.T) {
	fake := &fakeAWS{}
	p := fakeProvider(t, fake, Options{})
	evalRDP(t, p)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	rt, pl := -1, -1
	for i, c := range fake.calls {
		if c == rtRead && rt < 0 {
			rt = i
		}
		if c == plRead && pl < 0 {
			pl = i
		}
	}
	if rt < 0 || pl < 0 || rt > pl {
		t.Fatalf("route tables at %d, first prefix list at %d: %v", rt, pl, fake.calls)
	}
}

// Item 2: the instance's own lists are read before the load balancers' and the cap
// applies after that order, so 150 lists on an LB group (sorting first) cannot crowd out
// the instance's pl-office.
func TestItem2InstanceListsBeforeLBLists(t *testing.T) {
	var lbLists strings.Builder
	for i := range 150 {
		fmt.Fprintf(&lbLists, "<item><prefixListId>pl-a%03d</prefixListId></item>", i)
	}
	sgs := strings.Replace(responses["ec2:DescribeSecurityGroups"],
		`<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions>
  </item>
</securityGroupInfo>`,
		`<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>
      <item><ipProtocol>tcp</ipProtocol><fromPort>81</fromPort><toPort>81</toPort><prefixListIds>`+lbLists.String()+`</prefixListIds></item>
    </ipPermissions>
  </item>
</securityGroupInfo>`, 1)
	if sgs == responses["ec2:DescribeSecurityGroups"] {
		t.Fatal("fixture not changed")
	}
	fake := &fakeAWS{overrides: map[string]string{"ec2:DescribeSecurityGroups": sgs}}
	p := fakeProvider(t, fake, Options{})
	v := evalRDP(t, p)
	if !v.Open || !v.Complete || !strings.Contains(strings.Join(v.Evidence, "\n"), "allows tcp/3389 from 81.2.69.160/28") {
		t.Fatalf("instance's own list crowded out: %+v", v)
	}
	if n := fake.count(plRead); n != maxPrefixLists {
		t.Fatalf("prefix lists read %d, want the cap %d", n, maxPrefixLists)
	}
}

func s3GatewayRoutes(target string) []ec2types.RouteTable {
	return []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("10.0.0.0/16", "local"), route("0.0.0.0/0", "nat-1"),
		ec2types.Route{DestinationPrefixListId: awssdk.String("pl-s3"), GatewayId: awssdk.String(target), State: ec2types.RouteStateActive})}
}

func openSGData() HostData {
	return HostData{Instance: instance(true), SecurityGroups: map[string]ec2types.SecurityGroup{
		"sg-web": sg("sg-web", perm("tcp", 443, 443, "0.0.0.0/0"))}, NACLs: defaultNACL()}
}

// Item 3: a prefix-list route to a confirmed gateway endpoint (S3/DynamoDB) is not the
// internet; a Gateway Load Balancer endpoint, or an endpoint set that was not read, keeps
// the path undetermined.
func TestItem3GatewayEndpointRouteIsNone(t *testing.T) {
	d := openSGData()
	d.RouteTables = s3GatewayRoutes("vpce-gw")
	d.GatewayEndpoints = map[string]bool{"vpce-gw": true}
	v := Evaluate(withAWSDefaults(d), []cloud.Port{port(443, 3)})[0]
	if v.Open || !v.Complete || !strings.Contains(strings.Join(v.Evidence, "\n"), "has no route to an internet gateway") {
		t.Fatalf("gateway endpoint: %+v", v)
	}

	d = openSGData()
	d.RouteTables = s3GatewayRoutes("vpce-gwlb")
	d.GatewayEndpoints = map[string]bool{"vpce-gw": true}
	if v := Evaluate(withAWSDefaults(d), []cloud.Port{port(443, 3)})[0]; !undeterminedVerdict(v) ||
		!strings.Contains(strings.Join(v.Evidence, "\n"), "prefix list pl-s3 to vpce-gwlb") {
		t.Fatalf("gateway load balancer endpoint: %+v", v)
	}

	d = openSGData()
	d.RouteTables = s3GatewayRoutes("vpce-gw")
	d.GatewayEndpointsErr = "UnauthorizedOperation"
	if v := Evaluate(withAWSDefaults(d), []cloud.Port{port(443, 3)})[0]; !undeterminedVerdict(v) ||
		!strings.Contains(strings.Join(v.Evidence, "\n"), "gateway endpoints not read: UnauthorizedOperation") {
		t.Fatalf("endpoints unread: %+v", v)
	}
}

// Item 3: beside a CIDR route to an internet gateway, the path is open as before.
func TestItem3GatewayEndpointWithIGW(t *testing.T) {
	d := openSGData()
	d.RouteTables = []ec2types.RouteTable{routeTable("rtb-1", "subnet-1", route("0.0.0.0/0", "igw-1"),
		ec2types.Route{DestinationPrefixListId: awssdk.String("pl-s3"), GatewayId: awssdk.String("vpce-gw"), State: ec2types.RouteStateActive})}
	d.GatewayEndpoints = map[string]bool{"vpce-gw": true}
	if v := Evaluate(withAWSDefaults(d), []cloud.Port{port(443, 3)})[0]; !v.Open || !v.Complete {
		t.Fatalf("%+v", v)
	}
}

const s3EndpointRoutes = `<DescribeRouteTablesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r3b</requestId>
<routeTableSet>
  <item><routeTableId>rtb-main</routeTableId><vpcId>vpc-1</vpcId>
    <routeSet>
      <item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId><state>active</state></item>
      <item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><natGatewayId>nat-1</natGatewayId><state>active</state></item>
      <item><destinationPrefixListId>pl-s3</destinationPrefixListId><gatewayId>vpce-gw</gatewayId><state>active</state></item>
    </routeSet>
    <associationSet><item><routeTableAssociationId>rtbassoc-1</routeTableAssociationId><routeTableId>rtb-main</routeTableId><main>true</main></item></associationSet>
  </item>
</routeTableSet>
</DescribeRouteTablesResponse>`

// Item 3, end to end: the region's gateway endpoints are read (gateways only, type
// checked) with the load balancers and cached; without the permission the path stays
// undetermined and says why.
func TestItem3GatewayEndpointsReadAndCached(t *testing.T) {
	https := []cloud.Port{{Key: "a", Proto: "tcp", Addr: "0.0.0.0", Port: 443, AgentLevel: 3}}
	fake := &fakeAWS{overrides: map[string]string{rtRead: s3EndpointRoutes}}
	p := fakeProvider(t, fake, Options{})
	for range 2 {
		vs, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: instanceID, Region: euWest1}, https)
		if err != nil {
			t.Fatal(err)
		}
		if vs[0].Open || !vs[0].Complete {
			t.Fatalf("%+v", vs[0])
		}
	}
	if n := fake.count("ec2:DescribeVpcEndpoints"); n != 1 {
		t.Fatalf("endpoints read %d times, want 1 (cached with the load balancers)", n)
	}
	if fake.endpointsFilter != "vpc-endpoint-type=Gateway" {
		t.Fatalf("endpoint filter %q", fake.endpointsFilter)
	}

	fake = &fakeAWS{failEndpoints: true, overrides: map[string]string{rtRead: s3EndpointRoutes}}
	p = fakeProvider(t, fake, Options{})
	vs, err := p.Evaluate(context.Background(), cloud.Host{InstanceID: instanceID, Region: euWest1}, https)
	if err != nil {
		t.Fatal(err)
	}
	if ev := strings.Join(vs[0].Evidence, "\n"); !undeterminedVerdict(vs[0]) || !strings.Contains(ev, "gateway endpoints not read") ||
		!strings.Contains(ev, "UnauthorizedOperation") {
		t.Fatalf("%+v", vs[0])
	}
}

// Assumption: the SDK names the S3/DynamoDB kind "Gateway", and an endpoint of another
// type in the response (the filter notwithstanding) is never taken for one.
func TestAssumptionGatewayEndpointType(t *testing.T) {
	if ec2types.VpcEndpointTypeGateway != "Gateway" {
		t.Fatalf("SDK gateway endpoint type is %q", ec2types.VpcEndpointTypeGateway)
	}
	fake := &fakeAWS{}
	p := fakeProvider(t, fake, Options{})
	c, err := p.regionClients(euWest1)
	if err != nil {
		t.Fatal(err)
	}
	gw, truncated, err := p.fetchGatewayEndpoints(context.Background(), c)
	if err != nil || truncated || !gw["vpce-gw"] || gw["vpce-gwlb"] || len(gw) != 1 {
		t.Fatalf("gateways %v truncated %v err %v", gw, truncated, err)
	}
}

// Item 4: an entry without a CIDR makes its list unparseable: the rule is undetermined,
// and the entry's text is never quoted.
func TestItem4NilCidrEntryUndetermined(t *testing.T) {
	fake := &fakeAWS{overrides: map[string]string{plRead: `<GetManagedPrefixListEntriesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>r3c</requestId>
<entrySet>
  <item><cidr>81.2.69.160/28</cidr></item>
  <item><description>secret-office-note</description></item>
</entrySet>
</GetManagedPrefixListEntriesResponse>`}}
	p := fakeProvider(t, fake, Options{})
	v := evalRDP(t, p)
	ev := strings.Join(v.Evidence, "\n")
	if v.Open || v.Complete || !strings.Contains(ev, "pl-office not read: an entry has no CIDR") || strings.Contains(ev, "secret-office-note") {
		t.Fatalf("%+v", v)
	}
	// The pure judgement agrees: a list holding "" is not silently ignored.
	got := sgAllowed(HostData{SecurityGroups: map[string]ec2types.SecurityGroup{"sg-web": sg("sg-web", ec2types.IpPermission{
		IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(rdpPortNo), ToPort: awssdk.Int32(rdpPortNo),
		PrefixListIds: []ec2types.PrefixListId{{PrefixListId: awssdk.String("pl-x")}}})},
		PrefixLists: map[string]PrefixList{"pl-x": {CIDRs: []string{""}}}}, []string{"sg-web"}, "tcp", rdpPortNo, reach.V4)
	if got.maybe.IsEmpty() {
		t.Fatalf("an empty CIDR in a list was ignored: %+v", got)
	}
}
