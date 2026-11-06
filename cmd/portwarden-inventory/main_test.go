package main

import (
	"context"
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
