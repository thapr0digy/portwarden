//go:build linux

package main

import (
	"testing"
	"time"
)

func TestParseFlagsDefaults(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.natsURL != "nats://127.0.0.1:4222" || o.machineIDPath != "/etc/machine-id" || o.heartbeat != 30*time.Second {
		t.Fatalf("unexpected defaults: %+v", o)
	}
}

func TestParseFlagsRejectsNonPositiveHeartbeat(t *testing.T) {
	if _, err := parseFlags([]string{"--heartbeat", "0s"}); err == nil {
		t.Fatal("zero heartbeat must be rejected")
	}
}

func TestParseFlagsM2Defaults(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.spoolDir != "/var/lib/portwarden/spool" || o.spoolMax != 64<<20 ||
		o.closeGrace != 2*time.Second || o.recheck != 5*time.Minute {
		t.Fatalf("unexpected defaults: %+v", o)
	}
}

func TestParseFlagsSpoolMax(t *testing.T) {
	o, err := parseFlags([]string{"--spool-max", "1GiB"})
	if err != nil || o.spoolMax != 1<<30 {
		t.Fatalf("--spool-max 1GiB = %d, %v", o.spoolMax, err)
	}
	if _, err := parseFlags([]string{"--spool-max", "lots"}); err == nil {
		t.Fatal("invalid --spool-max must be rejected")
	}
}

func TestParseFlagsM3(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil || o.firewallPoll != 30*time.Second || o.imds != "auto" {
		t.Fatalf("defaults %+v %v", o, err)
	}
	if o, err := parseFlags([]string{"--imds", "off", "--firewall-poll", "5s"}); err != nil || o.imds != "off" || o.firewallPoll != 5*time.Second {
		t.Fatalf("parsed %+v %v", o, err)
	}
	for _, bad := range [][]string{{"--imds", "aws"}, {"--firewall-poll", "0s"}} {
		if _, err := parseFlags(bad); err == nil {
			t.Errorf("%v must be rejected", bad)
		}
	}
}

func TestParseFlagsProxy(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil || o.proxyMap != "auto" || o.proxyPoll != 2*time.Second {
		t.Fatalf("proxy defaults: %+v %v", o, err)
	}
	for _, args := range [][]string{{"--proxy-map", "maybe"}, {"--proxy-poll", "0s"}} {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("%v must be rejected", args)
		}
	}
}
