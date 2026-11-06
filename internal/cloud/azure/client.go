package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// armURL is the fixed Azure Resource Manager host (public Azure).
const armURL = "https://management.azure.com"

// Pinned api-versions (the REST reference lists newer ones; these stay supported).
const (
	computeAPI = "2024-07-01"
	networkAPI = "2024-05-01"
)

// Body caps.
const (
	maxSmallBody = 1 << 20
	maxNSGBody   = 4 << 20
	maxTagsBody  = 32 << 20
)

const (
	// maxNICs bounds the NICs read per VM; more is undetermined, never cut.
	maxNICs = 16
	// maxIPConfigs bounds the IP configurations judged per VM.
	maxIPConfigs = 256
)

var vmIDRe = regexp.MustCompile(`^` + uuidPattern + `$`)

// Options tune the provider.
type Options struct {
	// TenantID and ClientID name the app registration (client secret, federated token)
	// or, for a managed identity, ClientID selects a user-assigned one.
	TenantID, ClientID string
	// ClientSecretFile holds the app's client secret (a systemd credential), read once.
	ClientSecretFile string
	// FederatedTokenFile holds a federated (OIDC) token, read at every exchange.
	FederatedTokenFile string
	// Subscriptions are the only subscriptions looked up (required).
	Subscriptions []string
	// Policy is the reach rule.
	Policy reach.Policy
	// Timeout bounds one host's look-up (default 60 s); RequestTimeout one request
	// (default 20 s).
	Timeout, RequestTimeout time.Duration

	// Tests only (not reachable from the inventory's config): stand-ins for Microsoft's
	// fixed endpoints, the HTTP client and the clock.
	BaseURL, LoginURL, IMDSURL string
	HTTP                       *http.Client
	Now                        func() time.Time
}

// Provider is the Azure cloud.Provider.
type Provider struct {
	opts   Options
	base   *url.URL
	http   *http.Client
	tokens *tokens
	tags   *tagCache
	subs   []string
	// Credential names the credential kind for the start-up log (never the secret).
	Credential string
}

// New checks the options, reads the client secret (when set) once and builds the
// provider.
func New(opts Options) (*Provider, error) {
	if len(opts.Subscriptions) == 0 {
		return nil, errors.New("azure: subscriptions is required (the only subscriptions looked up)")
	}
	subs := make([]string, 0, len(opts.Subscriptions))
	for _, s := range opts.Subscriptions {
		if !vmIDRe.MatchString(s) {
			return nil, fmt.Errorf("azure: subscription %q is not a subscription id (UUID)", s)
		}
		subs = append(subs, strings.ToLower(s))
	}
	if opts.ClientSecretFile != "" && opts.FederatedTokenFile != "" {
		return nil, errors.New("azure: set client_secret_file or federated_token_file, not both")
	}
	if opts.ClientID != "" && !vmIDRe.MatchString(opts.ClientID) {
		return nil, errors.New("azure: client_id is not an application (client) id (UUID)")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 20 * time.Second
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	base := armURL
	if opts.BaseURL != "" {
		base = strings.TrimSuffix(opts.BaseURL, "/")
	}
	bu, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("azure: base URL: %w", err)
	}
	p := &Provider{opts: opts, base: bu, subs: subs, http: opts.HTTP}
	if p.http == nil {
		p.http = &http.Client{Timeout: opts.RequestTimeout}
	}
	login := loginURL
	if opts.LoginURL != "" {
		login = opts.LoginURL
	}
	switch {
	case opts.ClientSecretFile != "" || opts.FederatedTokenFile != "":
		if !tenantRe.MatchString(opts.TenantID) {
			return nil, errors.New("azure: tenant_id is required (a UUID or a domain name) with a client secret or federated token")
		}
		if opts.ClientID == "" {
			return nil, errors.New("azure: client_id is required with a client secret or federated token")
		}
		endpoint := tokenEndpoint(login, opts.TenantID)
		if opts.ClientSecretFile != "" {
			secret, err := readSmall(opts.ClientSecretFile, maxAssertion)
			if err != nil {
				return nil, fmt.Errorf("azure: client secret file: %w", err)
			}
			secret = strings.TrimSpace(secret)
			if secret == "" {
				return nil, errors.New("azure: client secret file is empty")
			}
			p.tokens = &tokens{fetch: clientCredentials(p.http, endpoint, secretForm(opts.ClientID, secret)), now: now}
			p.Credential = "client secret (app " + opts.ClientID + ")"
		} else {
			if _, err := os.Stat(opts.FederatedTokenFile); err != nil {
				return nil, fmt.Errorf("azure: federated token file: %w", err)
			}
			p.tokens = &tokens{fetch: clientCredentials(p.http, endpoint, federatedForm(opts.ClientID, opts.FederatedTokenFile)), now: now}
			p.Credential = "federated token (app " + opts.ClientID + ")"
		}
	default:
		endpoint := imdsURL
		if opts.IMDSURL != "" {
			endpoint = opts.IMDSURL
		}
		md := opts.HTTP
		if md == nil {
			// The metadata service is link-local: never through a proxy.
			md = &http.Client{Timeout: opts.RequestTimeout, Transport: &http.Transport{Proxy: nil}}
		}
		p.tokens = &tokens{fetch: imdsFetch(md, endpoint, opts.ClientID), now: now}
		p.Credential = "managed identity"
		if opts.ClientID != "" {
			p.Credential += " (user-assigned " + opts.ClientID + ")"
		}
	}
	p.tags = newTagCache(p.readTags, now)
	return p, nil
}

// vmTarget is a host's validated VM.
type vmTarget struct{ subscription, group, vm string }

// check validates a host before any API call (phase 1 requirements): the resource's
// shape, its subscription allow-listed, the host block's instance id a vmId.
func (p *Provider) check(h cloud.Host) (vmTarget, error) {
	if h.Resource == "" {
		return vmTarget{}, errors.New("azure: host sends no cloud_resource (agent older than M10, or not a VM resource id)")
	}
	sub, group, vm, err := cloud.ParseAzureResource(h.Resource)
	if err != nil {
		return vmTarget{}, fmt.Errorf("azure: %w", err)
	}
	if !slices.Contains(p.subs, sub) {
		return vmTarget{}, fmt.Errorf("azure: subscription %s is not in cloud.azure.subscriptions", sub)
	}
	if !vmIDRe.MatchString(h.InstanceID) {
		return vmTarget{}, errors.New("azure: the host block's instance id is not a vmId (UUID)")
	}
	return vmTarget{sub, group, vm}, nil
}

// Evaluate reads the VM, its NICs, their public IPs, subnets and NSGs (and, when a rule
// names one, the location's service tags), then judges every port.
func (p *Provider) Evaluate(ctx context.Context, h cloud.Host, ports []cloud.Port) ([]cloud.Verdict, error) {
	t, err := p.check(h)
	if err != nil {
		return nil, err
	}
	hostCtx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	ctx = hostCtx
	tok, err := p.tokens.token(ctx)
	if err != nil {
		return nil, err
	}
	var vm VM
	vmPath := "/subscriptions/" + url.PathEscape(t.subscription) + "/resourceGroups/" + url.PathEscape(t.group) +
		"/providers/Microsoft.Compute/virtualMachines/" + url.PathEscape(t.vm)
	if err := p.get(ctx, tok, vmPath, computeAPI, maxSmallBody, &vm); err != nil {
		return nil, fmt.Errorf("azure: virtualMachines/get %s: %w", t.vm, err)
	}
	if !strings.EqualFold(vm.Properties.VMID, h.InstanceID) {
		return nil, fmt.Errorf("azure: cloud_resource names VM %s whose vmId is %q, not the host block's %s", t.vm, truncate(vm.Properties.VMID, 40), h.InstanceID)
	}
	if h.Region != "" && !strings.EqualFold(vm.Location, h.Region) {
		return nil, fmt.Errorf("azure: VM %s is in %q, not the host's region %q", t.vm, truncate(vm.Location, 40), truncate(h.Region, 40))
	}
	d := HostData{VM: vm, PublicIPs: map[string]PublicIP{}, Subnets: map[string]Subnet{}, NSGs: map[string]NSG{},
		Errs: map[string]string{}, Policy: p.opts.Policy}
	refs := vm.Properties.NetworkProfile.NetworkInterfaces
	if len(refs) == 0 || len(refs) > maxNICs {
		return Evaluate(d, ports), nil // undetermined: never judged on a cut list
	}
	configs := 0
	for _, ref := range refs {
		var nic NIC
		if err := p.follow(ctx, tok, ref.ID, kindNIC, maxSmallBody, &nic); err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("azure: NIC %s: %w", truncate(ref.ID, 200), err)
			}
			d.NICs = append(d.NICs, NICData{ID: ref.ID, Err: err.Error()})
			continue
		}
		d.NICs = append(d.NICs, NICData{ID: ref.ID, NIC: &nic})
		configs += len(nic.Properties.IPConfigurations)
		if configs > maxIPConfigs {
			d.TooManyConfigs = true
			return Evaluate(d, ports), nil
		}
		var wanted []struct{ id, kind string }
		if nic.Properties.NetworkSecurityGroup != nil {
			wanted = append(wanted, struct{ id, kind string }{nic.Properties.NetworkSecurityGroup.ID, kindNSG})
		}
		for _, c := range nic.Properties.IPConfigurations {
			if c.Properties.PublicIPAddress != nil {
				wanted = append(wanted, struct{ id, kind string }{c.Properties.PublicIPAddress.ID, kindPublicIP})
			}
			if c.Properties.Subnet != nil {
				wanted = append(wanted, struct{ id, kind string }{c.Properties.Subnet.ID, kindSubnet})
			}
		}
		for _, w := range wanted {
			if err := p.read(ctx, tok, &d, w.id, w.kind); err != nil {
				return nil, err
			}
		}
	}
	// Subnet NSGs, once the subnets are read.
	for _, s := range d.Subnets {
		if s.Properties.NetworkSecurityGroup != nil {
			if err := p.read(ctx, tok, &d, s.Properties.NetworkSecurityGroup.ID, kindNSG); err != nil {
				return nil, err
			}
		}
	}
	if names := tagNames(d.NSGs); len(names) > 0 {
		d.Tags, d.TagsErr = p.tags.get(ctx, t.subscription, strings.ToLower(vm.Location))
		d.Location = strings.ToLower(vm.Location)
	}
	return Evaluate(d, ports), nil
}

// read fetches one followed resource into d, once per id. A failure is recorded against
// the id (that layer is undetermined); only the host's own deadline is an error.
func (p *Provider) read(ctx context.Context, tok string, d *HostData, id, kind string) error {
	k := key(id)
	if _, failed := d.Errs[k]; failed {
		return nil
	}
	var err error
	switch kind {
	case kindPublicIP:
		if _, ok := d.PublicIPs[k]; ok {
			return nil
		}
		var v PublicIP
		if err = p.follow(ctx, tok, id, kind, maxSmallBody, &v); err == nil {
			d.PublicIPs[k] = v
		}
	case kindSubnet:
		if _, ok := d.Subnets[k]; ok {
			return nil
		}
		var v Subnet
		if err = p.follow(ctx, tok, id, kind, maxSmallBody, &v); err == nil {
			d.Subnets[k] = v
		}
	case kindNSG:
		if _, ok := d.NSGs[k]; ok {
			return nil
		}
		var v NSG
		if err = p.follow(ctx, tok, id, kind, maxNSGBody, &v); err == nil {
			d.NSGs[k] = v
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("azure: %s %s: %w", kind, truncate(id, 200), err)
		}
		d.Errs[k] = err.Error()
	}
	return nil
}

// follow reads a resource whose id came from an ARM response: parsed, allow-listed and
// rebuilt, never pasted.
func (p *Provider) follow(ctx context.Context, tok, id, kind string, limit int64, v any) error {
	a, err := parseID(id, kind)
	if err != nil {
		return fmt.Errorf("refused: %w", err)
	}
	if !slices.Contains(p.subs, a.subscription) {
		return fmt.Errorf("refused: subscription %s is not in cloud.azure.subscriptions", a.subscription)
	}
	return p.get(ctx, tok, a.path(), networkAPI, limit, v)
}

// readTags reads a location's service-tag list, following nextLink on the ARM host.
func (p *Provider) readTags(ctx context.Context, subscription, location string) (TagSet, error) {
	tok, err := p.tokens.token(ctx)
	if err != nil {
		return nil, err
	}
	u := p.base.JoinPath("/subscriptions/"+subscription+"/providers/Microsoft.Network/locations/"+location+"/serviceTags").String() +
		"?" + url.Values{"api-version": {networkAPI}}.Encode()
	tags := TagSet{}
	for page := 0; u != ""; page++ {
		if page == maxTagPages {
			return nil, fmt.Errorf("service tags: more than %d pages", maxTagPages)
		}
		var pg serviceTagsPage
		if err := p.getURL(ctx, tok, u, maxTagsBody, &pg); err != nil {
			return nil, fmt.Errorf("service tags: %w", err)
		}
		for _, v := range pg.Values {
			if v.Name != "" {
				k := strings.ToLower(v.Name)
				tags[k] = append(tags[k], v.Properties.AddressPrefixes...)
			}
		}
		u = ""
		if pg.NextLink != "" {
			next, err := url.Parse(pg.NextLink)
			if err != nil || next.Scheme != p.base.Scheme || next.Host != p.base.Host {
				return nil, fmt.Errorf("service tags: nextLink %q is not on %s", truncate(pg.NextLink, 200), p.base.Host)
			}
			u = next.String()
		}
	}
	return tags, nil
}

// get GETs base+path?api-version=v.
func (p *Provider) get(ctx context.Context, tok, path, apiVersion string, limit int64, v any) error {
	u := p.base.String() + path + "?" + url.Values{"api-version": {apiVersion}}.Encode()
	return p.getURL(ctx, tok, u, limit, v)
}

// getURL GETs u and decodes the JSON body (at most limit bytes) into v.
func (p *Provider) getURL(ctx context.Context, tok, u string, limit int64, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("response over %d bytes", limit)
	}
	if resp.StatusCode != http.StatusOK {
		var e armError
		if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
			msg := fmt.Sprintf("%s: %s: %s", resp.Status, truncate(e.Error.Code, 60), truncate(e.Error.Message, 200))
			if e.Error.Code == "AuthorizationFailed" {
				msg += " (see deploy/azure-role.json for the read actions the role needs)"
			}
			return errors.New(msg)
		}
		return errors.New(resp.Status)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("response is not the expected JSON: %w", err)
	}
	return nil
}

// tagNames lists the service tags (other than the ones judged without the list) that
// inbound rules name as sources.
func tagNames(nsgs map[string]NSG) []string {
	var out []string
	for _, n := range nsgs {
		for _, r := range slices.Concat(n.Properties.SecurityRules, n.Properties.DefaultSecurityRules) {
			if strings.EqualFold(r.Properties.Direction, "Outbound") {
				continue // an unknown direction is judged (as maybe), so its tags are needed
			}
			for _, s := range sources(r) {
				if isTag(s) {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// isTag: a source shaped like a service-tag name, other than the ones judged without the
// list.
func isTag(s string) bool {
	s = strings.TrimSpace(s)
	_, builtin := builtinSource(s)
	return !builtin && tagRe.MatchString(s)
}
