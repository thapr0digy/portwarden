package main

import "testing"

func TestBuildScope(t *testing.T) {
	if _, err := buildScope(Config{}); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	s, err := buildScope(Config{AllowCIDRs: []string{"203.0.113.9/24"}, HostAddresses: map[string][]string{"h": {"::ffff:10.0.0.1"}}})
	if err != nil || s.Allow[0].String() != "203.0.113.0/24" || s.HostAddresses["h"][0].String() != "10.0.0.1" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := buildScope(Config{AllowCIDRs: []string{"nope"}}); err == nil {
		t.Fatal("bad cidr accepted")
	}
}
