package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

func TestCheckListen(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:8740": true, "[::1]:1": true, "localhost:1": true, "0.0.0.0:8740": false, "10.0.0.1:1": false} {
		if err := checkListen(addr, false); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if err := checkListen("0.0.0.0:8740", true); err != nil {
		t.Fatal(err)
	}
}

func TestCloudPolicyVPN(t *testing.T) {
	if _, err := (CloudConfig{VPNCIDRs: []string{"81.2.69.160/28", "2a00:1450::/32"}}).policy(); err != nil {
		t.Fatal(err)
	}
	if _, err := (CloudConfig{VPNCIDRs: []string{"81.2.69.300/28"}}).policy(); err == nil || !strings.Contains(err.Error(), "cloud.vpn_cidrs") {
		t.Fatalf("bad range accepted: %v", err)
	}
	if _, err := (CloudConfig{VPNCIDRs: []string{"0.0.0.0/0"}, AllowBroad: true}).policy(); err == nil {
		t.Fatal("/0 accepted")
	}
	if _, err := (CloudConfig{VPNCIDRs: []string{"80.0.0.0/4"}}).policy(); err == nil {
		t.Fatal("a /4 accepted without allow_broad")
	}
	if _, err := (CloudConfig{VPNCIDRs: []string{"80.0.0.0/4"}, AllowBroad: true}).policy(); err != nil {
		t.Fatalf("a /4 refused with allow_broad: %v", err)
	}
}

func TestGCPConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	g := GCPConfig{Enabled: true, Projects: []string{"acme-prod"}}
	if f := g.keyFile(env(nil)); f != "" {
		t.Errorf("no key, no env: %q (want the metadata server)", f)
	}
	if f := g.keyFile(env(map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/env/key.json"})); f != "/env/key.json" {
		t.Errorf("env key: %q", f)
	}
	g.KeyFile = "/cfg/key.json"
	if f := g.keyFile(env(map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/env/key.json"})); f != "/cfg/key.json" {
		t.Errorf("config key must win: %q", f)
	}
	// Enabled without projects is refused at start.
	_, _, err := (CloudConfig{GCP: GCPConfig{Enabled: true}}).providers(context.Background(), reach.Policy{}, env(nil))
	if err == nil || !strings.Contains(err.Error(), "cloud.gcp: projects is required") {
		t.Fatalf("no projects: %v", err)
	}
	// GCP alone starts the look-up (metadata server credential; nothing is fetched at start).
	provs, names, err := (CloudConfig{GCP: GCPConfig{Enabled: true, Projects: []string{"acme-prod"}}}).providers(context.Background(), reach.Policy{}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := provs["gcp"]; !ok || len(provs) != 1 || !strings.Contains(names[0], "metadata server") {
		t.Fatalf("providers %v %v", provs, names)
	}
	// Nothing enabled: no look-up.
	if provs, _, err := (CloudConfig{}).providers(context.Background(), reach.Policy{}, env(nil)); err != nil || len(provs) != 0 {
		t.Fatalf("nothing enabled: %v %v", provs, err)
	}
}

func TestAzureConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	const sub = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"
	const tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	const app = "a1b2c3d4-e5f6-4789-8abc-def012345678"
	// Enabled without subscriptions, or with one that is not a UUID, is refused at start.
	for _, a := range []AzureConfig{{Enabled: true}, {Enabled: true, Subscriptions: []string{"prod"}}} {
		if _, _, err := (CloudConfig{Azure: a}).providers(context.Background(), reach.Policy{}, env(nil)); err == nil || !strings.HasPrefix(err.Error(), "cloud.azure: ") {
			t.Fatalf("%+v: %v", a, err)
		}
	}
	// No credential configured: the managed identity; Azure alone starts the look-up.
	provs, names, err := (CloudConfig{Azure: AzureConfig{Enabled: true, Subscriptions: []string{sub}}}).providers(context.Background(), reach.Policy{}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := provs["azure"]; !ok || len(provs) != 1 || !strings.Contains(names[0], "managed identity") {
		t.Fatalf("providers %v %v", provs, names)
	}
	// AKS workload identity's environment selects the federated token.
	fed := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(fed, []byte("jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	wl := env(map[string]string{"AZURE_FEDERATED_TOKEN_FILE": fed, "AZURE_TENANT_ID": tenant, "AZURE_CLIENT_ID": app})
	_, names, err = (CloudConfig{Azure: AzureConfig{Enabled: true, Subscriptions: []string{sub}}}).providers(context.Background(), reach.Policy{}, wl)
	if err != nil || !strings.Contains(names[0], "federated token (app "+app+")") {
		t.Fatalf("%v %v", names, err)
	}
	// A configured secret file wins over the environment.
	sec := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(sec, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, names, err = (CloudConfig{Azure: AzureConfig{Enabled: true, Subscriptions: []string{sub}, ClientSecretFile: sec}}).providers(context.Background(), reach.Policy{}, wl)
	if err != nil || !strings.Contains(names[0], "client secret") || strings.Contains(names[0], "value") {
		t.Fatalf("%v %v", names, err)
	}
	// Secret and federated both configured: refused.
	_, _, err = (CloudConfig{Azure: AzureConfig{Enabled: true, Subscriptions: []string{sub}, TenantID: tenant, ClientID: app, ClientSecretFile: sec, FederatedTokenFile: fed}}).providers(context.Background(), reach.Policy{}, env(nil))
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("both: %v", err)
	}
}
