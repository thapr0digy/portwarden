package main

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/thapr0digy/portwarden"

// sharedWithAgent are the module's packages the agent and the backend both use: plain
// data and helpers that need no privilege. A package the agent imports may join the
// backend only by being listed here, deliberately.
var sharedWithAgent = []string{
	module + "/gen/asm/v1",
	module + "/internal/backend/bus",
	module + "/internal/model",
	module + "/internal/natsauth",
	module + "/internal/netif",
	module + "/internal/version",
}

// goListDeps is `go list -deps` of pkg as built for Linux (the agent's main is Linux only).
func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain in PATH (a cross-compiled test binary); go test runs this check")
	}
	cmd := exec.Command(gobin, "list", "-deps", pkg)
	cmd.Env = append(cmd.Environ(), "GOOS=linux", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, stderr)
	}
	return strings.Fields(string(out))
}

// The backend binary links neither the eBPF agent nor cilium/ebpf nor any package of the
// agent's (its probes, tamper checks, proxy readers, spool...): one binary for the
// backend must not carry code that needs CAP_BPF or CAP_PERFMON.
func TestNoAgentDependencies(t *testing.T) {
	backend := goListDeps(t, "./")
	if !slices.Contains(backend, module+"/internal/cmd/alerter") {
		t.Fatalf("go list -deps ./ does not list the subcommands: %v", backend)
	}
	agent := goListDeps(t, "../portwarden-agent")
	if !slices.Contains(agent, "github.com/cilium/ebpf") {
		t.Fatalf("the agent's dependencies lack cilium/ebpf; is ../portwarden-agent the agent? %v", agent)
	}
	agentOnly := map[string]bool{}
	for _, p := range agent {
		if strings.HasPrefix(p, module+"/") && !slices.Contains(sharedWithAgent, p) {
			agentOnly[p] = true
		}
	}
	if !agentOnly[module+"/internal/agent"] || !agentOnly[module+"/internal/probes"] {
		t.Fatalf("the agent's own packages were not found: %v", agentOnly)
	}
	for _, p := range backend {
		switch {
		case p == "github.com/cilium/ebpf" || strings.HasPrefix(p, "github.com/cilium/ebpf/"):
			t.Errorf("the backend binary links %s", p)
		case strings.HasPrefix(p, module+"/cmd/portwarden-agent"):
			t.Errorf("the backend binary links the agent's main %s", p)
		case agentOnly[p]:
			t.Errorf("the backend binary links the agent's package %s (list it in sharedWithAgent only if it needs no privilege)", p)
		}
	}
}
