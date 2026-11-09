package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
)

// Every program with a kernel target, in every compiled object in the repo, is in the
// list preflight checks: a new object or package that is not wired into agentTargets
// fails here instead of failing at attach on some future kernel.
func TestAgentTargetsCoverEveryObject(t *testing.T) {
	objects, err := filepath.Glob("../../internal/*/*_bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) == 0 {
		t.Fatal("no compiled BPF objects found under internal/")
	}
	got, err := agentTargets()
	if err != nil {
		t.Fatal(err)
	}
	have := map[bpftarget.Target]bool{}
	for _, tg := range got {
		have[tg] = true
	}
	total := 0
	for _, obj := range objects {
		raw, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		want, err := bpftarget.FromObject(obj, raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, tg := range want {
			total++
			if !have[tg] {
				t.Errorf("%s: %v is not in agentTargets (wire its package's AttachTargets in)", obj, tg)
			}
		}
	}
	if total != len(got) {
		t.Errorf("agentTargets has %d targets, the objects %d", len(got), total)
	}
}
