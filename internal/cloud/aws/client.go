package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
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
)

// EC2API is the read-only EC2 subset the look-up calls.
type EC2API interface {
	ec2.DescribeInstancesAPIClient
	ec2.DescribeSecurityGroupsAPIClient
	ec2.DescribeNetworkAclsAPIClient
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
	// Timeout bounds one host's evaluation (default 60 s).
	Timeout time.Duration
}

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
	return &Provider{newClients: newClients, opts: opts, clients: map[string]Clients{}, lbs: map[string]lbEntry{}, now: time.Now}
}

func (p *Provider) regionClients(region string) Clients {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.clients[region]
	if !ok {
		c = p.newClients(region)
		p.clients[region] = c
	}
	return c
}

// Evaluate fetches the instance, its security groups and subnet NACLs, and the region's
// load balancers (cached), then judges ports.
func (p *Provider) Evaluate(ctx context.Context, h cloud.Host, ports []cloud.Port) ([]cloud.Verdict, error) {
	if h.InstanceID == "" || h.Region == "" {
		return nil, errors.New("aws: the host block has no instance id or region (agent older than M5, or IMDS unreachable)")
	}
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	c := p.regionClients(h.Region)
	inst, err := p.instance(ctx, c, h.InstanceID)
	if err != nil {
		return nil, err
	}
	lbs, truncated, err := p.regionLBs(ctx, h.Region, c)
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
	sgs, err := p.securityGroups(ctx, c, slices.Compact(groups))
	if err != nil {
		return nil, err
	}
	nacls, err := p.nacls(ctx, c, instanceSubnets(inst))
	if err != nil {
		return nil, err
	}
	verdicts := Evaluate(HostData{Instance: inst, SecurityGroups: sgs, NACLs: nacls, LBs: lbs}, ports)
	if truncated {
		for i := range verdicts {
			verdicts[i].Evidence = append(verdicts[i].Evidence, fmt.Sprintf("cloud: load balancers read only up to %d", p.opts.MaxLBs))
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

func (p *Provider) securityGroups(ctx context.Context, c Clients, ids []string) (map[string]ec2types.SecurityGroup, error) {
	out := map[string]ec2types.SecurityGroup{}
	for chunk := range slices.Chunk(ids, 100) {
		pg := ec2.NewDescribeSecurityGroupsPaginator(c.EC2, &ec2.DescribeSecurityGroupsInput{GroupIds: chunk})
		for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
			res, err := pg.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("aws: DescribeSecurityGroups: %w", err)
			}
			for _, g := range res.SecurityGroups {
				out[deref(g.GroupId)] = g
			}
		}
	}
	return out, nil
}

func (p *Provider) nacls(ctx context.Context, c Clients, subnets []string) (map[string]ec2types.NetworkAcl, error) {
	out := map[string]ec2types.NetworkAcl{}
	if len(subnets) == 0 {
		return out, nil
	}
	pg := ec2.NewDescribeNetworkAclsPaginator(c.EC2, &ec2.DescribeNetworkAclsInput{
		Filters: []ec2types.Filter{{Name: awssdk.String("association.subnet-id"), Values: subnets}},
	})
	for page := 0; pg.HasMorePages() && page < p.opts.MaxPages; page++ {
		res, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws: DescribeNetworkAcls: %w", err)
		}
		for _, acl := range res.NetworkAcls {
			for _, a := range acl.Associations {
				if s := deref(a.SubnetId); slices.Contains(subnets, s) {
					out[s] = acl
				}
			}
		}
	}
	return out, nil
}

// regionLBs returns the region's internet-facing load balancers, cached for LBTTL.
func (p *Provider) regionLBs(ctx context.Context, region string, c Clients) (RegionLBs, bool, error) {
	p.mu.Lock()
	e, ok := p.lbs[region]
	p.mu.Unlock()
	if ok && p.now().Sub(e.at) < p.opts.LBTTL {
		return e.data, e.truncated, nil
	}
	data, truncated, err := p.fetchLBs(ctx, c)
	if err != nil {
		return RegionLBs{}, false, err
	}
	p.mu.Lock()
	p.lbs[region] = lbEntry{at: p.now(), data: data, truncated: truncated}
	p.mu.Unlock()
	return data, truncated, nil
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
		}
	}
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
	return v, nil
}

var (
	_ cloud.Provider = (*Provider)(nil)
)
