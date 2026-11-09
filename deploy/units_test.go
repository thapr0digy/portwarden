// Package deploy holds no Go code: this test pins the hardening of the systemd units so a
// later edit cannot quietly widen the agent's privileges (design §9).
package deploy

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"
)

// directives reads a unit file into key -> values (a key may repeat).
func directives(t *testing.T, path string) map[string][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: bad line %q", path, line)
		}
		out[k] = append(out[k], v)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func words(vs []string) []string {
	var out []string
	for _, v := range vs {
		out = append(out, strings.Fields(v)...)
	}
	slices.Sort(out)
	return out
}

func want(t *testing.T, unit string, d map[string][]string, key string, values ...string) {
	t.Helper()
	got := words(d[key])
	exp := slices.Clone(values)
	slices.Sort(exp)
	if !slices.Equal(got, exp) {
		t.Errorf("%s: %s = %v, want %v", unit, key, got, exp)
	}
}

var common = map[string]string{
	"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
	"PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
	"ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectHostname": "yes", "UMask": "0077",
	"RestrictNamespaces": "yes", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
	"MemoryDenyWriteExecute": "yes", "RemoveIPC": "yes", "PrivateIPC": "yes", "SystemCallArchitectures": "native",
	"SystemCallErrorNumber": "EPERM",
}

func TestAgentUnit(t *testing.T) {
	const unit = "portwarden-agent.service"
	d := directives(t, unit)
	caps := []string{"CAP_BPF", "CAP_PERFMON", "CAP_SYS_PTRACE", "CAP_NET_ADMIN"}
	want(t, unit, d, "CapabilityBoundingSet", caps...)
	want(t, unit, d, "AmbientCapabilities", caps...)
	want(t, unit, d, "RestrictAddressFamilies", "AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6")
	want(t, unit, d, "SystemCallFilter", "@system-service", "bpf", "perf_event_open")
	want(t, unit, d, "User", "portwarden-agent")
	for k, v := range common {
		want(t, unit, d, k, v)
	}
	if exec := strings.Join(d["ExecStart"], ""); !strings.HasPrefix(exec, "/usr/bin/portwarden-agent ") {
		t.Errorf("ExecStart %q is not the packaged /usr/bin path", exec)
	}
	// Early in boot (design §2), before the network.
	want(t, unit, d, "DefaultDependencies", "no")
	want(t, unit, d, "WantedBy", "sysinit.target")
	if !slices.Contains(words(d["Before"]), "network-pre.target") {
		t.Errorf("%s must start before network-pre.target", unit)
	}
}

// The iptables-legacy example drop-in adds exactly CAP_NET_RAW and nothing else; the
// unit itself keeps its four capabilities (TestAgentUnit).
func TestAgentIptablesLegacyExample(t *testing.T) {
	const dropIn = "portwarden-agent-iptables-legacy.example.conf"
	d := directives(t, dropIn)
	want(t, dropIn, d, "AmbientCapabilities", "CAP_NET_RAW")
	want(t, dropIn, d, "CapabilityBoundingSet", "CAP_NET_RAW")
	if len(d) != 2 {
		t.Errorf("%s sets %d directives, want only the two capability lists: %v", dropIn, len(d), d)
	}
}

func TestBackendUnits(t *testing.T) {
	for _, svc := range []string{"inventory", "alerter", "verifier"} {
		unit := "portwarden-" + svc + ".service"
		d := directives(t, unit)
		want(t, unit, d, "CapabilityBoundingSet")
		want(t, unit, d, "AmbientCapabilities")
		want(t, unit, d, "DynamicUser", "yes")
		want(t, unit, d, "RestrictAddressFamilies", "AF_INET", "AF_INET6", "AF_UNIX")
		want(t, unit, d, "SystemCallFilter", "@system-service", "~@privileged")
		for k, v := range common {
			want(t, unit, d, k, v)
		}
		if exec := strings.Join(d["ExecStart"], ""); !strings.HasPrefix(exec, "/usr/bin/portwarden-"+svc+" ") {
			t.Errorf("%s: ExecStart %q is not the packaged /usr/bin path", unit, exec)
		}
	}
}
