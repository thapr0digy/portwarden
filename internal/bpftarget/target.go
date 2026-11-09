// Package bpftarget lists the kernel functions and types a compiled BPF collection
// attaches to, read from the collection itself so that the list cannot fall behind the
// programs (preflight checks every entry against the kernel's BTF before the agent
// attaches anything).
package bpftarget

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
)

// Kinds of attach target, named like the programs' ELF section prefixes.
const (
	KindFentry  = "fentry"
	KindFexit   = "fexit"
	KindFmodRet = "fmod_ret"
	KindIter    = "iter"
	KindTpBTF   = "tp_btf"
	KindLSM     = "lsm"
)

// Target is one kernel symbol a program attaches to.
type Target struct {
	// Program is the program's name in its .bpf.c file.
	Program string
	// Kind is the attach kind (KindFentry, …).
	Kind string
	// Func is the name the loader looks up in the kernel's BTF: the function itself for
	// fentry, fexit and fmod_ret, "bpf_iter_<name>" for an iterator, "bpf_lsm_<hook>" for
	// an LSM hook and "btf_trace_<tracepoint>" (a typedef) for tp_btf, as cilium/ebpf does.
	Func string
}

// IsTypedef reports whether the target is looked up as a BTF typedef (tp_btf) rather
// than a function.
func (t Target) IsTypedef() bool { return t.Kind == KindTpBTF }

func (t Target) String() string {
	return fmt.Sprintf("%s %s (program %s)", t.Kind, t.Func, t.Program)
}

// FromCollectionSpec returns the kernel targets of every program in spec, sorted by
// program name. Programs with no kernel-symbol target (cgroup, socket filter, …) are
// left out; a tracing program of an attach type this package does not know is an error,
// so a new kind of hook is never skipped silently.
func FromCollectionSpec(spec *ebpf.CollectionSpec) ([]Target, error) {
	var out []Target
	for name, prog := range spec.Programs {
		t, ok, err := fromProgram(name, prog)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Program < out[j].Program })
	return out, nil
}

func fromProgram(name string, prog *ebpf.ProgramSpec) (Target, bool, error) {
	switch prog.Type {
	case ebpf.LSM:
		return Target{Program: name, Kind: KindLSM, Func: "bpf_lsm_" + prog.AttachTo}, true, nil
	case ebpf.Tracing:
	default:
		return Target{}, false, nil
	}
	if prog.AttachTo == "" {
		return Target{}, false, fmt.Errorf("tracing program %s has no attach target", name)
	}
	t := Target{Program: name, Func: prog.AttachTo}
	switch prog.AttachType {
	case ebpf.AttachTraceFEntry:
		t.Kind = KindFentry
	case ebpf.AttachTraceFExit:
		t.Kind = KindFexit
	case ebpf.AttachModifyReturn:
		t.Kind = KindFmodRet
	case ebpf.AttachTraceIter:
		t.Kind, t.Func = KindIter, "bpf_iter_"+prog.AttachTo
	case ebpf.AttachTraceRawTp:
		t.Kind, t.Func = KindTpBTF, "btf_trace_"+prog.AttachTo
	default:
		return Target{}, false, fmt.Errorf("tracing program %s has attach type %s, which preflight cannot check", name, prog.AttachType)
	}
	return t, true, nil
}

// FromObject parses a compiled BPF object (a bpf2go *_bpfel.o) and returns its targets.
func FromObject(name string, object []byte) ([]Target, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	targets, err := FromCollectionSpec(spec)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return targets, nil
}
