package main

import (
	"strings"
	"testing"
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
}
