//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestParseFlagsSSHAccess(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil || o.sshAccess != "auto" || strings.Join(o.sshAccounts, ",") != "pants,root" || o.sharedKeys != "" {
		t.Fatalf("defaults %+v %v", o, err)
	}
	o, err = parseFlags([]string{"--ssh-access", "off", "--ssh-accounts", " deploy , pants ", "--shared-keys", "/etc/portwarden/shared-keys"})
	if err != nil || o.sshAccess != "off" || strings.Join(o.sshAccounts, ",") != "deploy,pants" {
		t.Fatalf("parsed %+v %v", o, err)
	}
	for _, args := range [][]string{{"--ssh-access", "on"}, {"--ssh-accounts", ""}, {"--ssh-accounts", "Admin"}, {"--ssh-accounts", "a b"}} {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// The identity facts exist only in Signal's schema: the reader runs only with the door,
// and a shared-key list that is not one fails the start.
func TestHostAccessConfig(t *testing.T) {
	door := []string{"--ingest-url", "https://100.64.0.5:8443", "--ingest-pin", "sha256/pin", "--ingest-dir", "/srv/pw"}
	for _, args := range [][]string{nil, append(door[:6:6], "--ssh-access", "off")} {
		o, err := parseFlags(args)
		if err != nil {
			t.Fatal(err)
		}
		if cfg, err := hostAccessConfig(o); cfg != nil || err != nil {
			t.Fatalf("%v: %+v %v", args, cfg, err)
		}
	}
	list := filepath.Join(t.TempDir(), "shared-keys")
	if err := os.WriteFile(list, []byte("underpants SHA256:I8mg+yasAvN5VKOREFoeN54OIuc1hm+LJL6KAGScwsI\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := parseFlags(append(door[:6:6], "--shared-keys", list))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := hostAccessConfig(o)
	if err != nil || cfg == nil || cfg.SharedKeys["SHA256:I8mg+yasAvN5VKOREFoeN54OIuc1hm+LJL6KAGScwsI"] != "underpants" ||
		cfg.CursorFile != "/srv/pw/journal-cursor" || cfg.Recheck != 5*time.Minute || cfg.Journal == nil {
		t.Fatalf("config %+v %v", cfg, err)
	}
	if err := os.WriteFile(list, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hostAccessConfig(o); err == nil || strings.Contains(err.Error(), "BEGIN") {
		t.Fatalf("a list that is not one: %v", err)
	}
}

// The package list exists only in Signal's schema: the reader runs only with the door,
// unless --host-packages off; it reads at start, on a settled dpkg change and daily.
// Assumption: in a container the dpkg database is the image's (deploy/Dockerfile is
// ubuntu:24.04), so the reader does not run there rather than report it as the host's.
func TestHostPackagesConfig(t *testing.T) {
	door := []string{"--ingest-url", "https://100.64.0.5:8443", "--ingest-pin", "sha256/pin"}
	for _, args := range [][]string{nil, append(door[:4:4], "--host-packages", "off")} {
		o, err := parseFlags(args)
		if err != nil {
			t.Fatal(err)
		}
		if cfg := hostPackagesConfig(o, false); cfg != nil {
			t.Fatalf("%v: %+v", args, cfg)
		}
	}
	o, err := parseFlags(door)
	if err != nil || o.hostPackages != "auto" {
		t.Fatalf("defaults %+v %v", o, err)
	}
	if cfg := hostPackagesConfig(o, false); cfg == nil || cfg.Recheck != 24*time.Hour || cfg.Settle != 30*time.Second || cfg.Root == nil {
		t.Fatalf("config %+v", cfg)
	}
	if cfg := hostPackagesConfig(o, true); cfg != nil {
		t.Fatalf("in a container: %+v", cfg)
	}
	if _, err := parseFlags([]string{"--host-packages", "on"}); err == nil || !strings.Contains(err.Error(), "--host-packages") {
		t.Fatalf("--host-packages on: %v", err)
	}
}

// Assumption: the kernel names the initial PID namespace pid:[4026531836] (PROC_PID_INIT_INO),
// and a container's "/" is not the host init's root directory. "/" counts as the host's only
// when both are shown; a read that fails, as without CAP_SYS_PTRACE or /proc, fails closed.
func TestCheckHostRootFailsClosed(t *testing.T) {
	fakeProc := func(pidNS, initRoot string) string {
		proc := t.TempDir()
		for dir, link := range map[string]string{"self/ns/pid": pidNS, "1/root": initRoot} {
			if link == "" {
				continue
			}
			if err := os.MkdirAll(filepath.Join(proc, filepath.Dir(dir)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(link, filepath.Join(proc, dir)); err != nil {
				t.Fatal(err)
			}
		}
		return proc
	}
	hostRoot, imageRoot := t.TempDir(), t.TempDir()
	if err := checkHostRoot(fakeProc(initPIDNamespace, hostRoot), hostRoot); err != nil {
		t.Fatalf("the host's root: %v", err)
	}
	for name, proc := range map[string]string{
		"no /proc":               t.TempDir(),
		"own PID namespace":      fakeProc("pid:[4026532300]", hostRoot),
		"init's root unreadable": fakeProc(initPIDNamespace, ""),
		"an image's root":        fakeProc(initPIDNamespace, imageRoot),
	} {
		if err := checkHostRoot(proc, hostRoot); err == nil {
			t.Errorf("%s: / taken as the host's", name)
		}
	}
}
