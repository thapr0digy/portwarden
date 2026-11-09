//go:build linux && integration

package main

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
	"github.com/thapr0digy/portwarden/internal/preflight"
)

// The real kernel of each matrix leg has every function the agent traces.
func TestPreflightPassesOnThisKernel(t *testing.T) {
	targets, err := agentTargets()
	if err != nil {
		t.Fatal(err)
	}
	if err := preflight.Check(kernelRelease(), targets); err != nil {
		t.Fatalf("preflight on %s: %v", kernelRelease(), err)
	}
}

// Against the real kernel BTF the lookup tells a missing function from a present one, so
// the check above passes because the functions are there, not because lookups pass.
func TestPreflightNamesAFunctionThisKernelLacks(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	targets, err := agentTargets()
	if err != nil {
		t.Fatal(err)
	}
	bogus := bpftarget.Target{Program: "on_nothing", Kind: bpftarget.KindFentry, Func: "portwarden_no_such_function"}
	err = preflight.CheckAttachTargets(spec, append(targets, bogus), kernelRelease())
	var mt *preflight.MissingTargetsError
	if !errors.As(err, &mt) || len(mt.Missing) != 1 || mt.Missing[0] != bogus || len(mt.Ambiguous) != 0 {
		t.Fatalf("want only %v missing, got %v", bogus, err)
	}
	t.Logf("message: %v", err)
}
