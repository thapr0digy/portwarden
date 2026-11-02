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
