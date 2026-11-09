package preflight

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
)

const release = "7.4.0-5-generic"

var listenTargets = []bpftarget.Target{
	{Program: "on_listen", Kind: bpftarget.KindFexit, Func: "inet_csk_listen_start"},
	{Program: "on_stop", Kind: bpftarget.KindFentry, Func: "inet_csk_listen_stop"},
	{Program: "on_udp_bind", Kind: bpftarget.KindFexit, Func: "udp_lib_get_port"},
	{Program: "on_udp_unhash", Kind: bpftarget.KindFentry, Func: "udp_lib_unhash"},
	{Program: "dump_udp", Kind: bpftarget.KindIter, Func: "bpf_iter_udp"},
}

// stubSpec builds a real BTF spec holding the given types, as a kernel's would.
func stubSpec(t *testing.T, types ...btf.Type) *btf.Spec {
	t.Helper()
	b, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := b.Spec()
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func fn(name string) *btf.Func {
	return &btf.Func{Name: name, Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}}, Linkage: btf.GlobalFunc}
}

func funcs(names ...string) []btf.Type {
	out := make([]btf.Type, len(names))
	for i, n := range names {
		out[i] = fn(n)
	}
	return out
}

func TestCheckAttachTargetsAllPresent(t *testing.T) {
	spec := stubSpec(t, funcs("inet_csk_listen_start", "inet_csk_listen_stop", "udp_lib_get_port", "udp_lib_unhash", "bpf_iter_udp")...)
	if err := CheckAttachTargets(spec, listenTargets, release); err != nil {
		t.Fatalf("all present: %v", err)
	}
}

func missingError(t *testing.T, err error) *MissingTargetsError {
	t.Helper()
	var mt *MissingTargetsError
	if !errors.As(err, &mt) {
		t.Fatalf("want *MissingTargetsError, got %T: %v", err, err)
	}
	t.Logf("message: %s", err)
	if !strings.Contains(err.Error(), release) {
		t.Errorf("message must name the kernel release: %s", err)
	}
	return mt
}

func TestCheckAttachTargetsOneMissing(t *testing.T) {
	spec := stubSpec(t, funcs("inet_csk_listen_start", "inet_csk_listen_stop", "udp_lib_get_port", "bpf_iter_udp")...)
	mt := missingError(t, CheckAttachTargets(spec, listenTargets, release))
	if len(mt.Missing) != 1 || mt.Missing[0].Func != "udp_lib_unhash" {
		t.Fatalf("missing = %v", mt.Missing)
	}
	if msg := mt.Error(); !strings.Contains(msg, "cannot attach 1 kernel function the agent traces: missing fentry udp_lib_unhash (program on_udp_unhash);") {
		t.Errorf("message: %s", msg)
	}
}

func TestCheckAttachTargetsSeveralMissingAreAllNamed(t *testing.T) {
	spec := stubSpec(t, funcs("inet_csk_listen_stop", "udp_lib_get_port")...)
	mt := missingError(t, CheckAttachTargets(spec, listenTargets, release))
	msg := mt.Error()
	for _, want := range []string{"cannot attach 3 kernel functions the agent traces: missing ", "fexit inet_csk_listen_start (program on_listen)",
		"fentry udp_lib_unhash (program on_udp_unhash)", "iter bpf_iter_udp (program dump_udp)", "not supported"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
}

// A type of another kind under the function's name (a struct, say) is not a function the
// loader could attach to.
func TestCheckAttachTargetsOtherKindIsMissing(t *testing.T) {
	types := append(funcs("inet_csk_listen_start", "inet_csk_listen_stop", "udp_lib_unhash", "bpf_iter_udp"),
		&btf.Struct{Name: "udp_lib_get_port", Size: 0})
	mt := missingError(t, CheckAttachTargets(stubSpec(t, types...), listenTargets, release))
	if len(mt.Missing) != 1 || mt.Missing[0].Func != "udp_lib_get_port" {
		t.Fatalf("missing = %v", mt.Missing)
	}
}

// cilium/ebpf refuses to load against a name several kernel functions share
// (prog.go, "attaching to ambiguous kernel symbol is not supported").
func TestCheckAttachTargetsAmbiguousIsRefused(t *testing.T) {
	types := append(funcs("inet_csk_listen_start", "inet_csk_listen_stop", "udp_lib_get_port", "udp_lib_unhash", "bpf_iter_udp"),
		fn("udp_lib_unhash"))
	mt := missingError(t, CheckAttachTargets(stubSpec(t, types...), listenTargets, release))
	if len(mt.Missing) != 0 || len(mt.Ambiguous) != 1 || mt.Ambiguous[0].Func != "udp_lib_unhash" {
		t.Fatalf("missing = %v, ambiguous = %v", mt.Missing, mt.Ambiguous)
	}
	if !strings.Contains(mt.Error(), "1 kernel function the agent traces: ambiguous (several kernel symbols share the name) fentry udp_lib_unhash") {
		t.Errorf("message: %s", mt.Error())
	}
}

func TestCheckAttachTargetsTpBTFIsATypedef(t *testing.T) {
	tp := []bpftarget.Target{{Program: "on_tp", Kind: bpftarget.KindTpBTF, Func: "btf_trace_sched_switch"}}
	withTypedef := stubSpec(t, &btf.Typedef{Name: "btf_trace_sched_switch", Type: &btf.Int{Name: "int", Size: 4}})
	if err := CheckAttachTargets(withTypedef, tp, release); err != nil {
		t.Fatalf("typedef present: %v", err)
	}
	asFunc := stubSpec(t, fn("btf_trace_sched_switch"))
	missingError(t, CheckAttachTargets(asFunc, tp, release))
}

// An unreadable BTF is its own message, not a list of missing functions.
func TestCheckKernelTargetsUnreadableBTF(t *testing.T) {
	err := checkKernelTargets(func() (*btf.Spec, error) { return nil, errors.New("bad magic") }, listenTargets, release)
	var mt *MissingTargetsError
	if err == nil || errors.As(err, &mt) || !strings.Contains(err.Error(), "read kernel BTF at /sys/kernel/btf/vmlinux") {
		t.Fatalf("got %v", err)
	}
}
