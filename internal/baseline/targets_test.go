package baseline

import (
	"testing"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
)

// The two iterators are looked up as bpf_iter_<name> functions, as cilium/ebpf does.
func TestAttachTargetsMatchTheCommittedObjects(t *testing.T) {
	got, err := AttachTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want the two iterators", got)
	}
	funcs := map[string]bool{}
	for _, tg := range got {
		if tg.Kind != bpftarget.KindIter {
			t.Errorf("%v: want kind iter", tg)
		}
		funcs[tg.Func] = true
	}
	for _, f := range []string{"bpf_iter_task_file", "bpf_iter_udp"} {
		if !funcs[f] {
			t.Errorf("missing %s in %v", f, got)
		}
	}
}
