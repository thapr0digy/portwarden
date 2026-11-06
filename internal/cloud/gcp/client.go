package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

// computeURL is the fixed Compute Engine v1 API root.
const computeURL = "https://compute.googleapis.com/compute/v1"

const (
	maxInstanceBody  = 1 << 20
	maxEffectiveBody = 16 << 20
)

// Options tune the provider.
type Options struct {
	// KeyFile is a service-account JSON key; empty: the metadata server of the GCE
	// machine the backend runs on.
	KeyFile string
	// Projects are the only projects looked up (required): a host naming another is an
	// error.
	Projects []string
	// Policy is the reach rule.
	Policy reach.Policy
	// HierarchyConfirmed: a response without hierarchical policies means there are none
	// (cloud.gcp.hierarchy_confirmed). Otherwise closed interfaces without one are
	// undetermined.
	HierarchyConfirmed bool
	// Timeout bounds one host's look-up (default 60 s); RequestTimeout one request
	// (default 20 s).
	Timeout, RequestTimeout time.Duration

	// Tests only (not reachable from the inventory's config): stand-ins for Google's
	// fixed endpoints and HTTP client.
	BaseURL, TokenURL, MetadataURL string
	HTTP                           *http.Client
}

// Provider is the GCP cloud.Provider.
type Provider struct {
	opts     Options
	base     string
	http     *http.Client
	tokens   *tokens
	projects []string
	// Credential names the credential kind for the start-up log (never the key).
	Credential string
}

// New reads the key file (when set) once and builds the provider.
func New(opts Options) (*Provider, error) {
	if len(opts.Projects) == 0 {
		return nil, errors.New("gcp: projects is required (the only projects looked up)")
	}
	for _, p := range opts.Projects {
		if p == "" {
			return nil, errors.New("gcp: projects holds an empty name")
		}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 20 * time.Second
	}
	p := &Provider{opts: opts, base: computeURL, projects: slices.Clone(opts.Projects)}
	if opts.BaseURL != "" {
		p.base = strings.TrimSuffix(opts.BaseURL, "/")
	}
	p.http = opts.HTTP
	if p.http == nil {
		p.http = &http.Client{Timeout: opts.RequestTimeout}
	}
	now := time.Now
	if opts.KeyFile != "" {
		b, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("gcp: key file: %w", err)
		}
		s, err := parseKey(b)
		if err != nil {
			return nil, fmt.Errorf("gcp: %s: %w", opts.KeyFile, err)
		}
		endpoint := tokenURL
		if opts.TokenURL != "" {
			endpoint = opts.TokenURL
		}
		p.tokens = &tokens{fetch: jwtFetch(p.http, endpoint, s, now), now: now}
		p.Credential = "service account " + s.email
		return p, nil
	}
	endpoint := metadataURL
	if opts.MetadataURL != "" {
		endpoint = opts.MetadataURL
	}
	md := opts.HTTP
	if md == nil {
		// The metadata server is link-local: never through a proxy.
		md = &http.Client{Timeout: opts.RequestTimeout, Transport: &http.Transport{Proxy: nil}}
	}
	p.tokens = &tokens{fetch: metadataFetch(md, endpoint), now: now}
	p.Credential = "metadata server"
	return p, nil
}

// target is a host's validated instance.
type target struct{ project, zone, instance string }

// check validates a host before any API call (phase 1 requirements): the resource's
// shape, its instance number equal to the host block's, the project allow-listed, the
// zone inside the host's region.
func (p *Provider) check(h cloud.Host) (target, error) {
	if h.Resource == "" {
		return target{}, errors.New("gcp: host sends no cloud_resource (agent older than M10)")
	}
	project, zone, inst, err := cloud.ParseGCPResource(h.Resource)
	if err != nil {
		return target{}, fmt.Errorf("gcp: %w", err)
	}
	if inst != h.InstanceID {
		return target{}, fmt.Errorf("gcp: cloud_resource names instance %s, the host block %q", inst, h.InstanceID)
	}
	if !slices.Contains(p.projects, project) {
		return target{}, fmt.Errorf("gcp: project %s is not in cloud.gcp.projects", project)
	}
	if h.Region != "" && !strings.HasPrefix(zone, h.Region+"-") {
		return target{}, fmt.Errorf("gcp: zone %s is not in the host's region %s", zone, h.Region)
	}
	return target{project, zone, inst}, nil
}

// Evaluate reads the instance and the effective firewalls of each interface with an
// external address, then judges every port.
func (p *Provider) Evaluate(ctx context.Context, h cloud.Host, ports []cloud.Port) ([]cloud.Verdict, error) {
	t, err := p.check(h)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	tok, err := p.tokens.token(ctx)
	if err != nil {
		return nil, err
	}
	instPath := "/projects/" + url.PathEscape(t.project) + "/zones/" + url.PathEscape(t.zone) + "/instances/"
	var inst Instance
	if err := p.getJSON(ctx, tok, instPath+url.PathEscape(t.instance), nil, maxInstanceBody, &inst); err != nil {
		return nil, fmt.Errorf("gcp: instances.get %s: %w", t.instance, err)
	}
	if inst.ID != t.instance {
		return nil, fmt.Errorf("gcp: instances.get returned instance %q, not %s", inst.ID, t.instance)
	}
	if inst.Name == "" {
		return nil, errors.New("gcp: instances.get returned no instance name")
	}
	d := HostData{Instance: inst, Effective: map[string]Effective{}, EffectiveErr: map[string]string{},
		Policy: p.opts.Policy, HierarchyConfirmed: p.opts.HierarchyConfirmed}
	if len(inst.Interfaces) > maxInterfaces {
		return Evaluate(d, ports), nil // undetermined: never judged on a cut list
	}
	// Every interface, with or without an external address: a load balancer or forwarding
	// rule can bring internet traffic to one without.
	for _, nic := range inst.Interfaces {
		var eff Effective
		// The second call names the instance as the first returned it, so it does not rely
		// on the number being accepted in place of the name a second time.
		err := p.getJSON(ctx, tok, instPath+url.PathEscape(inst.Name)+"/getEffectiveFirewalls",
			url.Values{"networkInterface": {nic.Name}}, maxEffectiveBody, &eff)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("gcp: getEffectiveFirewalls %s: %w", nic.Name, err)
			}
			d.EffectiveErr[nic.Name] = err.Error()
			continue
		}
		if !eff.present {
			d.EffectiveErr[nic.Name] = "the response holds neither firewalls nor firewallPolicys"
			continue
		}
		d.Effective[nic.Name] = eff
	}
	return Evaluate(d, ports), nil
}

// getJSON GETs base+path and decodes the JSON body (at most limit bytes) into v.
func (p *Provider) getJSON(ctx context.Context, tok, path string, q url.Values, limit int64, v any) error {
	u := p.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
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
		var e apiError
		if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
			msg := fmt.Sprintf("%s: %s", resp.Status, truncate(e.Error.Message, 200))
			if resp.StatusCode == http.StatusForbidden {
				msg += " (the role needs compute.instances.get and compute.instances.getEffectiveFirewalls)"
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
