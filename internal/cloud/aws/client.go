package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// EC2API is the read-only EC2 subset the look-up calls.
type EC2API interface {
	ec2.DescribeInstancesAPIClient
	ec2.DescribeSecurityGroupsAPIClient
	ec2.DescribeNetworkAclsAPIClient
	ec2.DescribeRouteTablesAPIClient
	ec2.GetManagedPrefixListEntriesAPIClient
}

// ELBv2API is the read-only ELBv2 subset the look-up calls.
type ELBv2API interface {
	elbv2.DescribeLoadBalancersAPIClient
	elbv2.DescribeListenersAPIClient
	elbv2.DescribeRulesAPIClient
	elbv2.DescribeTargetGroupsAPIClient
	DescribeTargetHealth(context.Context, *elbv2.DescribeTargetHealthInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error)
}

// ELBAPI is the read-only Classic ELB subset the look-up calls.
type ELBAPI interface {
	elb.DescribeLoadBalancersAPIClient
}

// Clients are one region's API clients.
type Clients struct {
	EC2   EC2API
	ELBv2 ELBv2API
	ELB   ELBAPI
}

// Options tune the provider.
type Options struct {
	// Endpoint overrides every service's endpoint (tests, local stand-ins). Empty: AWS.
	Endpoint string
	// LBTTL is how long a region's load balancers are cached (default 5 minutes).
	LBTTL time.Duration
	// MaxPages bounds every paginated call (default 50 pages).
	MaxPages int
	// MaxLBs bounds the load balancers read per region (default 500).
	MaxLBs int
	// Timeout bounds one host's EC2 calls (default 60 s).
	Timeout time.Duration
	// LBTimeout bounds a region's load-balancer read, which runs outside any host's
	// budget (default 3 min).
	LBTimeout time.Duration
	// Regions, when set, are the only regions looked up (a host block naming another is an
	// error). At most 64 regions get clients either way.
	Regions []string
	// Policy is the reach rule: the operator's VPN ranges never count as the internet.
	Policy reach.Policy
}

const maxRegions = 64

// maxPrefixLists bounds the prefix lists read per host; rules naming one beyond it are
// undetermined.
const maxPrefixLists = 100

var (
	regionRe   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	instanceRe = regexp.MustCompile(`^i-[0-9a-f]{1,17}$`)
)

// Provider is the AWS cloud.Provider.
type Provider struct {
	newClients func(region string) Clients
	opts       Options

	mu      sync.Mutex
	clients map[string]Clients
	lbs     map[string]lbEntry
	now     func() time.Time
}

type lbEntry struct {
	at        time.Time
	data      RegionLBs
	truncated bool
}

// New loads the default AWS configuration (environment, shared config, an instance or
// task role; nothing is read from Portwarden's own config) once and builds per-region
// clients on demand. Every call is read-only (see deploy/aws-iam-policy.json).
func New(ctx context.Context, opts Options) (*Provider, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws: config: %w", err)
	}
	return NewWithConfig(cfg, opts), nil
}

// NewWithConfig builds a provider from an explicit SDK configuration (tests).
func NewWithConfig(cfg awssdk.Config, opts Options) *Provider {
	return NewWithClients(func(region string) Clients {
		c := cfg.Copy()
		c.Region = region
		var ep *string
		if opts.Endpoint != "" {
			ep = awssdk.String(opts.Endpoint)
		}
		return Clients{
			EC2:   ec2.NewFromConfig(c, func(o *ec2.Options) { o.BaseEndpoint = ep }),
			ELBv2: elbv2.NewFromConfig(c, func(o *elbv2.Options) { o.BaseEndpoint = ep }),
			ELB:   elb.NewFromConfig(c, func(o *elb.Options) { o.BaseEndpoint = ep }),
		}
	}, opts)
}

// NewWithClients builds a provider over given clients (tests with stubs).
func NewWithClients(newClients func(region string) Clients, opts Options) *Provider {
	if opts.LBTTL <= 0 {
		opts.LBTTL = 5 * time.Minute
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 50
	}
	if opts.MaxLBs <= 0 {
		opts.MaxLBs = 500
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	if opts.LBTimeout <= 0 {
		opts.LBTimeout = 3 * time.Minute
	}
	return &Provider{newClients: newClients, opts: opts, clients: map[string]Clients{}, lbs: map[string]lbEntry{}, now: time.Now}
}

func (p *Provider) regionClients(region string) (Clients, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.clients[region]
	if !ok {
		if len(p.clients) >= maxRegions {
			return Clients{}, fmt.Errorf("aws: more than %d regions", maxRegions)
		}
		c = p.newClients(region)
		p.clients[region] = c
	}
	return c, nil
}

// validHost checks the host-supplied identity before any call is made with it.
func (p *Provider) validHost(h cloud.Host) error {
	if h.InstanceID == "" || h.Region == "" {
		return errors.New("aws: the host block has no instance id or region (agent older than M5, or IMDS unreachable)")
	}
	if !regionRe.MatchString(h.Region) || (len(p.opts.Regions) > 0 && !slices.Contains(p.opts.Regions, h.Region)) {
		return fmt.Errorf("aws: region %q is not valid or not allowed", h.Region)
	}
	if !instanceRe.MatchString(h.InstanceID) {
		return fmt.Errorf("aws: instance id %q is not valid", h.InstanceID)
	}
	return nil
}

// Evaluate fetches the instance, its security groups and subnet NACLs, and the region's
// load balancers (cached), then judges ports.
func (p *Provider) Evaluate(ctx context.Context, h cloud.Host, ports []cloud.Port) ([]cloud.Verdict, error) {
	if err := p.validHost(h); err != nil {
		return nil, err
	}
	c, err := p.regionClients(h.Region)
	if err != nil {
		return nil, err
	}
	// The region's load balancers are read (or taken from the cache) outside this host's
	// budget; a failure leaves them incomplete, never fails the host.
	lbs, incomplete := p.regionLBs(ctx, h.Region, c)
	hctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	ctx = hctx
	inst, err := p.instance(ctx, c, h.InstanceID)
	if err != nil {
		return nil, err
	}
	groups := instanceGroups(inst)
	for _, lb := range lbs.V2 {
		groups = append(groups, lb.LB.SecurityGroups...)
	}
	for _, lb := range lbs.Classic {
		groups = append(groups, lb.SecurityGroups...)
	}
	sort.Strings(groups)
	sgs, sgTrunc, err := p.securityGroups(ctx, c, slices.Compact(groups))
	if err != nil {
		return nil, err
	}
	if sgTrunc {
		incomplete = append(incomplete, "security groups truncated")
	}
	nacls, aclTrunc, err := p.nacls(ctx, c, instanceSubnets(inst))
	if err != nil {
		return nil, err
	}
	if aclTrunc {
		incomplete = append(incomplete, "network ACLs truncated")
	}
	data := HostData{Instance: inst, SecurityGroups: sgs, NACLs: nacls, LBs: lbs, Policy: p.opts.Policy,
		PrefixLists: p.prefixLists(ctx, c, sgs)}
	// Route tables are read after the M5 permissions: one that fails (an IAM policy without
	// ec2:DescribeRouteTables) leaves the direct paths undetermined, never fails the host.
	rts, rtTrunc, err := p.routeTables(ctx, c, instanceVPCs(inst))
	switch {
	case err != nil:
		data.RoutesErr = err.Error()
	case rtTrunc:
		incomplete = append(incomplete, "route tables truncated")
	}
	data.RouteTables = rts
	verdicts := Evaluate(data, ports)
	if len(incomplete) > 0 {
		for i := range verdicts {
			verdicts[i].Complete = false
			verdicts[i].Evidence = append(verdicts[i].Evidence, cloud.IncompleteEvidence+" ("+strings.Join(incomplete, "; ")+")")
		}
	}
	return verdicts, nil
}

func (p *Provider) instance(ctx context.Context, c Clients, id string) (ec2types.Instance, error) {
	pg := ec2.NewDescribeInstancesPaginator(c.EC2, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
		out, err := pg.NextPage(ctx)
		if err != nil {
			return ec2types.Instance{}, fmt.Errorf("aws: DescribeInstances: %w", err)
		}
		for _, r := range out.Reservations {
			for _, i := range r.Instances {
				if deref(i.InstanceId) == id {
					return i, nil
				}
			}
		}
	}
	return ec2types.Instance{}, fmt.Errorf("aws: instance %s not found", id)
}

func (p *Provider) securityGroups(ctx context.Context, c Clients, ids []string) (map[string]ec2types.SecurityGroup, bool, error) {
	out := map[string]ec2types.SecurityGroup{}
	truncated := false
	for chunk := range slices.Chunk(ids, 100) {
		pg := ec2.NewDescribeSecurityGroupsPaginator(c.EC2, &ec2.DescribeSecurityGroupsInput{GroupIds: chunk})
		for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
			res, err := pg.NextPage(ctx)
			if err != nil {
				return nil, false, fmt.Errorf("aws: DescribeSecurityGroups: %w", err)
			}
			for _, g := range res.SecurityGroups {
				out[deref(g.GroupId)] = g
			}
		}
		truncated = truncated || pg.HasMorePages()
	}
	return out, truncated, nil
}

func (p *Provider) nacls(ctx context.Context, c Clients, subnets []string) (map[string]ec2types.NetworkAcl, bool, error) {
	out := map[string]ec2types.NetworkAcl{}
	if len(subnets) == 0 {
		return out, false, nil
	}
	pg := ec2.NewDescribeNetworkAclsPaginator(c.EC2, &ec2.DescribeNetworkAclsInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("association.subnet-id"), Values: subnets}},
	})
	for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := pg.NextPage(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("aws: DescribeNetworkAcls: %w", err)
		}
		for _, acl := range res.NetworkAcls {
			for _, a := range acl.Associations {
				if s := deref(a.SubnetId); slices.Contains(subnets, s) {
					out[s] = acl
				}
			}
		}
	}
	return out, pg.HasMorePages(), nil
}

func (p *Provider) routeTables(ctx context.Context, c Clients, vpcs []string) ([]ec2types.RouteTable, bool, error) {
	if len(vpcs) == 0 {
		return nil, false, nil
	}
	var out []ec2types.RouteTable
	pg := ec2.NewDescribeRouteTablesPaginator(c.EC2, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("vpc-id"), Values: vpcs}},
	})
	for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := pg.NextPage(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("aws: DescribeRouteTables: %w", err)
		}
		out = append(out, res.RouteTables...)
	}
	return out, pg.HasMorePages(), nil
}

// prefixLists reads the entries of the managed prefix lists the groups' rules name (both
// customer- and AWS-managed). A list that fails or is truncated is kept with its error, so
// the rules naming it are undetermined; the host is never failed for it.
func (p *Provider) prefixLists(ctx context.Context, c Clients, sgs map[string]ec2types.SecurityGroup) map[string]PrefixList {
	var ids []string
	for _, g := range sgs {
		for _, perm := range g.IpPermissions {
			for _, ref := range perm.PrefixListIds {
				if id := deref(ref.PrefixListId); id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	sort.Strings(ids)
	ids = slices.Compact(ids)
	out := map[string]PrefixList{}
	for i, id := range ids {
		if i == maxPrefixLists {
			break // the rest stay unread: undetermined
		}
		out[id] = p.prefixList(ctx, c, id)
	}
	return out
}

func (p *Provider) prefixList(ctx context.Context, c Clients, id string) PrefixList {
	var pl PrefixList
	pg := ec2.NewGetManagedPrefixListEntriesPaginator(c.EC2, &ec2.GetManagedPrefixListEntriesInput{PrefixListId: awssdk.String(id)})
	for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := pg.NextPage(ctx)
		if err != nil {
			return PrefixList{Err: fmt.Sprintf("GetManagedPrefixListEntries: %v", err)}
		}
		for _, e := range res.Entries {
			pl.CIDRs = append(pl.CIDRs, deref(e.Cidr))
		}
	}
	if pg.HasMorePages() {
		return PrefixList{Err: "entries truncated"}
	}
	return pl
}

// regionLBs returns the region's internet-facing load balancers, cached for LBTTL and read
// with their own deadline (LBTimeout), not the host's. What could not be read in full is
// returned as reasons: a failed refresh keeps the last good data (stale) or none.
func (p *Provider) regionLBs(ctx context.Context, region string, c Clients) (RegionLBs, []string) {
	p.mu.Lock()
	e, ok := p.lbs[region]
	p.mu.Unlock()
	if ok && p.now().Sub(e.at) < p.opts.LBTTL {
		return e.data, e.reasons()
	}
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.opts.LBTimeout)
	defer cancel()
	data, truncated, err := p.fetchLBs(lctx, c)
	if err != nil {
		if ok {
			return e.data, append(e.reasons(), "load balancers stale ("+err.Error()+")")
		}
		return RegionLBs{}, []string{"load balancers unreadable (" + err.Error() + ")"}
	}
	p.mu.Lock()
	p.lbs[region] = lbEntry{at: p.now(), data: data, truncated: truncated}
	p.mu.Unlock()
	return data, p.lbs[region].reasons()
}

func (e lbEntry) reasons() []string {
	if e.truncated {
		return []string{"load balancers truncated"}
	}
	return nil
}

func (p *Provider) fetchLBs(ctx context.Context, c Clients) (RegionLBs, bool, error) {
	var out RegionLBs
	truncated := false
	count := 0
	pg := elbv2.NewDescribeLoadBalancersPaginator(c.ELBv2, &elbv2.DescribeLoadBalancersInput{})
	for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := pg.NextPage(ctx)
		if err != nil {
			return out, false, fmt.Errorf("aws: elbv2 DescribeLoadBalancers: %w", err)
		}
		for _, lb := range res.LoadBalancers {
			if lb.Scheme != elbv2types.LoadBalancerSchemeEnumInternetFacing {
				continue
			}
			if count++; count > p.opts.MaxLBs {
				truncated = true
				break
			}
			v, err := p.fetchV2(ctx, c, lb)
			if err != nil {
				return out, false, err
			}
			out.V2 = append(out.V2, v)
		}
	}
	truncated = truncated || pg.HasMorePages()
	cpg := elb.NewDescribeLoadBalancersPaginator(c.ELB, &elb.DescribeLoadBalancersInput{})
	for page := 0; cpg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := cpg.NextPage(ctx)
		if err != nil {
			return out, false, fmt.Errorf("aws: elb DescribeLoadBalancers: %w", err)
		}
		for _, lb := range res.LoadBalancerDescriptions {
			if deref(lb.Scheme) != "internet-facing" {
				continue
			}
			if count++; count > p.opts.MaxLBs {
				truncated = true
				break
			}
			out.Classic = append(out.Classic, lb)
		}
	}
	truncated = truncated || cpg.HasMorePages()
	for _, v := range out.V2 {
		truncated = truncated || v.truncated
	}
	return out, truncated, nil
}

func (p *Provider) fetchV2(ctx context.Context, c Clients, lb elbv2types.LoadBalancer) (V2LB, error) {
	v := V2LB{LB: lb, TargetGroups: map[string]V2TargetGroup{}}
	lpg := elbv2.NewDescribeListenersPaginator(c.ELBv2, &elbv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
	for page := 0; lpg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := lpg.NextPage(ctx)
		if err != nil {
			return v, fmt.Errorf("aws: DescribeListeners: %w", err)
		}
		for _, l := range res.Listeners {
			vl := V2Listener{Listener: l}
			rpg := elbv2.NewDescribeRulesPaginator(c.ELBv2, &elbv2.DescribeRulesInput{ListenerArn: l.ListenerArn})
			for rp := 0; rpg.HasMorePages() && rp < p.opts.MaxPages; rp++ {
				rr, err := rpg.NextPage(ctx)
				if err != nil {
					return v, fmt.Errorf("aws: DescribeRules: %w", err)
				}
				for _, r := range rr.Rules {
					if r.IsDefault != nil && *r.IsDefault {
						continue // the listener's DefaultActions already
					}
					vl.RuleActions = append(vl.RuleActions, r.Actions...)
				}
			}
			v.Listeners = append(v.Listeners, vl)
			v.truncated = v.truncated || rpg.HasMorePages()
		}
	}
	v.truncated = v.truncated || lpg.HasMorePages()
	tpg := elbv2.NewDescribeTargetGroupsPaginator(c.ELBv2, &elbv2.DescribeTargetGroupsInput{LoadBalancerArn: lb.LoadBalancerArn})
	for page := 0; tpg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := tpg.NextPage(ctx)
		if err != nil {
			return v, fmt.Errorf("aws: DescribeTargetGroups: %w", err)
		}
		for _, tg := range res.TargetGroups {
			th, err := c.ELBv2.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
			if err != nil {
				return v, fmt.Errorf("aws: DescribeTargetHealth: %w", err)
			}
			v.TargetGroups[deref(tg.TargetGroupArn)] = V2TargetGroup{TG: tg, Targets: th.TargetHealthDescriptions}
		}
	}
	v.truncated = v.truncated || tpg.HasMorePages()
	return v, nil
}

var (
	_ cloud.Provider = (*Provider)(nil)
)
