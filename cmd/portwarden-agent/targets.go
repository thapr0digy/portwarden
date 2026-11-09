package main

import (
	"fmt"

	"github.com/thapr0digy/portwarden/internal/baseline"
	"github.com/thapr0digy/portwarden/internal/bpftarget"
	"github.com/thapr0digy/portwarden/internal/probes"
)

// agentTargets lists every kernel function the agent's BPF programs attach to, read from
// the compiled objects, for the startup preflight.
func agentTargets() ([]bpftarget.Target, error) {
	var out []bpftarget.Target
	for _, src := range []struct {
		pkg  string
		list func() ([]bpftarget.Target, error)
	}{{"probes", probes.AttachTargets}, {"baseline", baseline.AttachTargets}} {
		t, err := src.list()
		if err != nil {
			return nil, fmt.Errorf("attach targets of %s: %w", src.pkg, err)
		}
		out = append(out, t...)
	}
	return out, nil
}
