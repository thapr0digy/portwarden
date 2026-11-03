// Package publicip collects candidates for the server's public address (design §5):
// interface addresses (netlink), cloud metadata (AWS IMDSv2, GCP, Azure) and the local
// address of the agent's own NATS connection. It never asks a third-party service.
package publicip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cloud providers.
const (
	AWS   = "aws"
	GCP   = "gcp"
	Azure = "azure"
)

// azureAssetTag is the chassis asset tag every Azure VM carries.
const azureAssetTag = "7783-7084-3265-9085-8269-3286-77"

// Detect names the cloud the host runs on from its DMI data (dmiDir is normally
// /sys/class/dmi/id), or "" when it is none of AWS, GCP or Azure. It reads a few small
// files and never touches the network.
func Detect(dmiDir string) string {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dmiDir, name))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	vendor, product := read("sys_vendor"), read("product_name")
	switch {
	case vendor == "Amazon EC2" || strings.Contains(strings.ToLower(read("bios_version")), "amazon"):
		return AWS
	case product == "Google Compute Engine" || vendor == "Google":
		return GCP
	case vendor == "Microsoft Corporation" && read("chassis_asset_tag") == azureAssetTag:
		return Azure
	}
	return ""
}

// Info is what cloud metadata says about the instance.
type Info struct {
	Cloud      string
	InstanceID string
	PublicIPs  []netip.Addr
}

// Client queries the instance metadata service. Each request is bounded by Timeout.
type Client struct {
	// Base is the metadata endpoint, http://169.254.169.254 by default.
	Base    string
	Timeout time.Duration
	http    *http.Client
}

const (
	defaultBase    = "http://169.254.169.254"
	defaultTimeout = 2 * time.Second
	maxBody        = 1 << 20
)

// NewClient returns a client that never uses a proxy (the metadata address is
// link-local), never follows redirects, and gives each request timeout.
func NewClient(base string, timeout time.Duration) *Client {
	if base == "" {
		base = defaultBase
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          1,
	}
	return &Client{Base: strings.TrimRight(base, "/"), Timeout: timeout, http: &http.Client{
		Transport: tr, Timeout: timeout,
		// Never follow a redirect: it would carry the metadata headers (the IMDSv2
		// token) to another host. A 3xx is an error.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// errNotFound is a 404: the instance has no such value (no public IPv4, for one).
var errNotFound = errors.New("not found")

func (c *Client) do(ctx context.Context, method, path string, header map[string]string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, nil)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, resp.Header, errNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, resp.Header, fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	return body, resp.Header, nil
}

// Fetch asks the provider's metadata service for the instance id and public addresses.
func (c *Client) Fetch(ctx context.Context, provider string) (Info, error) {
	switch provider {
	case AWS:
		return c.aws(ctx)
	case GCP:
		return c.gcp(ctx)
	case Azure:
		return c.azure(ctx)
	}
	return Info{}, fmt.Errorf("unknown cloud %q", provider)
}

// aws uses IMDSv2: a session token first, then token-authenticated reads.
func (c *Client) aws(ctx context.Context) (Info, error) {
	token, _, err := c.do(ctx, http.MethodPut, "/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"})
	if err != nil {
		return Info{}, fmt.Errorf("aws: token: %w", err)
	}
	h := map[string]string{"X-aws-ec2-metadata-token": strings.TrimSpace(string(token))}
	id, _, err := c.do(ctx, http.MethodGet, "/latest/meta-data/instance-id", h)
	if err != nil {
		return Info{}, fmt.Errorf("aws: instance-id: %w", err)
	}
	info := Info{Cloud: AWS, InstanceID: strings.TrimSpace(string(id))}
	for _, path := range []string{"/latest/meta-data/public-ipv4", "/latest/meta-data/ipv6"} {
		body, _, err := c.do(ctx, http.MethodGet, path, h)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return Info{}, fmt.Errorf("aws: %s: %w", path, err)
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(string(body))); err == nil {
			info.PublicIPs = append(info.PublicIPs, a)
		}
	}
	return info, nil
}

func (c *Client) gcp(ctx context.Context) (Info, error) {
	h := map[string]string{"Metadata-Flavor": "Google"}
	id, hdr, err := c.do(ctx, http.MethodGet, "/computeMetadata/v1/instance/id", h)
	if err != nil {
		return Info{}, fmt.Errorf("gcp: id: %w", err)
	}
	if hdr.Get("Metadata-Flavor") != "Google" {
		return Info{}, errors.New("gcp: response lacks Metadata-Flavor: Google")
	}
	body, _, err := c.do(ctx, http.MethodGet, "/computeMetadata/v1/instance/network-interfaces/?recursive=true", h)
	if err != nil {
		return Info{}, fmt.Errorf("gcp: network-interfaces: %w", err)
	}
	var nics []struct {
		AccessConfigs []struct {
			ExternalIP string `json:"externalIp"`
		} `json:"accessConfigs"`
		IPv6AccessConfigs []struct {
			ExternalIPv6 string `json:"externalIpv6"`
		} `json:"ipv6AccessConfigs"`
	}
	if err := json.Unmarshal(body, &nics); err != nil {
		return Info{}, fmt.Errorf("gcp: network-interfaces: %w", err)
	}
	info := Info{Cloud: GCP, InstanceID: strings.TrimSpace(string(id))}
	for _, n := range nics {
		for _, ac := range n.AccessConfigs {
			if a, err := netip.ParseAddr(ac.ExternalIP); err == nil {
				info.PublicIPs = append(info.PublicIPs, a)
			}
		}
		for _, ac := range n.IPv6AccessConfigs {
			if a, err := netip.ParseAddr(ac.ExternalIPv6); err == nil {
				info.PublicIPs = append(info.PublicIPs, a)
			}
		}
	}
	return info, nil
}

func (c *Client) azure(ctx context.Context) (Info, error) {
	body, _, err := c.do(ctx, http.MethodGet, "/metadata/instance?api-version=2021-02-01", map[string]string{"Metadata": "true"})
	if err != nil {
		return Info{}, fmt.Errorf("azure: %w", err)
	}
	var doc struct {
		Compute struct {
			VMID string `json:"vmId"`
		} `json:"compute"`
		Network struct {
			Interface []struct {
				IPv4 struct {
					IPAddress []struct {
						PublicIPAddress string `json:"publicIpAddress"`
					} `json:"ipAddress"`
				} `json:"ipv4"`
				IPv6 struct {
					IPAddress []struct {
						PublicIPAddress string `json:"publicIpAddress"`
					} `json:"ipAddress"`
				} `json:"ipv6"`
			} `json:"interface"`
		} `json:"network"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Info{}, fmt.Errorf("azure: %w", err)
	}
	info := Info{Cloud: Azure, InstanceID: doc.Compute.VMID}
	for _, n := range doc.Network.Interface {
		for _, a := range append(n.IPv4.IPAddress, n.IPv6.IPAddress...) {
			if ip, err := netip.ParseAddr(a.PublicIPAddress); err == nil {
				info.PublicIPs = append(info.PublicIPs, ip)
			}
		}
	}
	return info, nil
}

// RunIMDS fetches the provider's metadata now and every refresh after, retrying a
// failure after retry, until ctx ends, handing each result to set. It runs in its own
// goroutine and never delays the agent's startup.
func RunIMDS(ctx context.Context, c *Client, provider string, refresh, retry time.Duration, set func(Info)) {
	failing := false
	for {
		info, err := c.Fetch(ctx, provider)
		wait := refresh
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			if !failing {
				slog.Warn("cloud metadata unavailable; will retry", "cloud", provider, "error", err.Error(), "retry", retry.String())
			}
			failing, wait = true, retry
		default:
			if failing {
				slog.Info("cloud metadata available again", "cloud", provider)
			}
			failing = false
			set(info)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
