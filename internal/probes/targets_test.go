package probes

import (
	"testing"

	"github.com/thapr0digy/portwarden/internal/bpftarget"
)

// The committed listen object hooks exactly the four functions bpf/listen.bpf.c names,
// and proxyconn's cgroup programs contribute none.
func TestAttachTargetsMatchTheCommittedObjects(t *testing.T) {
	got, err := AttachTargets()
	if err != nil {
		t.Fatal(err)
	}
	want := []bpftarget.Target{
		{Program: "on_listen", Kind: bpftarget.KindFexit, Func: "inet_csk_listen_start"},
		{Program: "on_stop", Kind: bpftarget.KindFentry, Func: "inet_csk_listen_stop"},
		{Program: "on_udp_bind", Kind: bpftarget.KindFexit, Func: "udp_lib_get_port"},
		{Program: "on_udp_unhash", Kind: bpftarget.KindFentry, Func: "udp_lib_unhash"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %v, want %v", i, got[i], want[i])
		}
	}
}
