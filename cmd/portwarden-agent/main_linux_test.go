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
	if err != nil || o.proxyMap != "auto" || o.proxyPoll != 2*time.Second || o.proxyAdminPoll != 30*time.Second ||
		!o.proxyAdmin["caddy"] || !o.proxyAdmin["haproxy"] {
		t.Fatalf("proxy defaults: %+v %v", o, err)
	}
	if o, err := parseFlags([]string{"--proxy-admin", "off", "--proxy-admin-poll", "0s"}); err != nil || len(o.proxyAdmin) != 0 || o.proxyAdminPoll != 0 {
		t.Fatalf("parsed %+v %v", o, err)
	}
	for _, args := range [][]string{{"--proxy-map", "maybe"}, {"--proxy-poll", "0s"}, {"--proxy-admin", "envoy"}, {"--proxy-admin-poll", "-1s"}} {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("%v must be rejected", args)
		}
	}
}

func TestParseFlagsTamper(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil || o.tamperInterval != 30*time.Second || len(o.tamperFiles) != 0 {
		t.Fatalf("tamper defaults: %+v %v", o, err)
	}
	o, err = parseFlags([]string{"--tamper-interval", "0s", "--tamper-files", "/etc/default/portwarden-agent,/etc/portwarden/agent/host.nk"})
	if err != nil || o.tamperInterval != 0 || len(o.tamperFiles) != 2 || o.tamperFiles[1] != "/etc/portwarden/agent/host.nk" {
		t.Fatalf("parsed %+v %v", o, err)
	}
	for _, args := range [][]string{{"--tamper-interval", "-1s"}, {"--tamper-files", "relative/path"}} {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("%v must be rejected", args)
		}
	}
}

func TestParseFlagsM6FixWave(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil || o.tamperDropRate != 1000 || o.natsNkeyDir != "" {
		t.Fatalf("defaults %+v %v", o, err)
	}
	if o, err := parseFlags([]string{"--nats-nkey-dir", "/etc/portwarden/nats", "--tamper-drop-rate", "0"}); err != nil || o.natsNkeyDir == "" || o.tamperDropRate != 0 {
		t.Fatalf("parsed %+v %v", o, err)
	}
	for _, args := range [][]string{{"--nats-nkey-dir", "/x", "--nats-nkey", "/y"}, {"--tamper-drop-rate", "-1"}} {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("%v must be rejected", args)
		}
	}
}

func TestParseFlagsIngestReplacesNATS(t *testing.T) {
	door := []string{"--ingest-url", "https://100.64.0.5:8443", "--ingest-pin", "sha256/pin"}
	o, err := parseFlags(door)
	if err != nil {
		t.Fatal(err)
	}
	if o.ingestKey != "/var/lib/portwarden/ingest/key.nk" {
		t.Fatalf("default key %q", o.ingestKey)
	}
	cfg := publisherConfig(o, "web-1")
	if cfg.URL != "" || cfg.Ingest == nil || cfg.Ingest.KeyIDFile != "/var/lib/portwarden/ingest/keyid" ||
		cfg.Ingest.Pin != "sha256/pin" || cfg.Ingest.Hostname != "web-1" {
		t.Fatalf("publisher config %+v %+v", cfg, cfg.Ingest)
	}
	o, err = parseFlags(append(door, "--ingest-key", "/etc/portwarden/agent/host.nk", "--ingest-key-id", "ak-1", "--ingest-dir", "/srv/pw"))
	if err != nil || o.ingestKey != "/etc/portwarden/agent/host.nk" || o.ingestKeyID != "ak-1" {
		t.Fatalf("parsed %+v %v", o, err)
	}
	if cfg := publisherConfig(o, ""); cfg.Ingest.KeyIDFile != "/srv/pw/keyid" || cfg.Ingest.KeyID != "ak-1" {
		t.Fatalf("publisher config %+v", cfg.Ingest)
	}
	if o, err := parseFlags(nil); err != nil || publisherConfig(o, "").Ingest != nil {
		t.Fatalf("NATS stays the default: %v", err)
	}
	for _, args := range [][]string{
		{"--ingest-url", "https://100.64.0.5:8443"},                        // no pin
		append(door[:4:4], "--nats-url", "nats://127.0.0.1:4222"),          // both destinations
		append(door[:4:4], "--nats-nkey", "/etc/portwarden/agent/host.nk"), // a NATS credential
		append(door[:4:4], "--tls-ca", "/etc/portwarden/ca.pem"),
		{"--ingest-pin", "sha256/pin"}, // ingest settings without the door
		{"--ingest-key-id", "ak-1"},
		{"--ingest-join-code-file", "/etc/portwarden/join"},
	} {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
