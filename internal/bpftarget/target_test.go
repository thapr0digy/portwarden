package bpftarget

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestFromCollectionSpecKinds(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"on_listen":  {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFExit, AttachTo: "inet_csk_listen_start"},
		"on_stop":    {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: "inet_csk_listen_stop"},
		"on_ret":     {Type: ebpf.Tracing, AttachType: ebpf.AttachModifyReturn, AttachTo: "security_x"},
		"walk_udp":   {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceIter, AttachTo: "udp"},
		"on_tp":      {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sched_switch"},
		"on_lsm":     {Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "socket_bind"},
		"connect4":   {Type: ebpf.CGroupSockAddr, AttachType: ebpf.AttachCGroupInet4Connect},
		"filter_skb": {Type: ebpf.SocketFilter},
	}}
	got, err := FromCollectionSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := []Target{
		{"on_listen", KindFexit, "inet_csk_listen_start"},
		{"on_lsm", KindLSM, "bpf_lsm_socket_bind"},
		{"on_ret", KindFmodRet, "security_x"},
		{"on_stop", KindFentry, "inet_csk_listen_stop"},
		{"on_tp", KindTpBTF, "btf_trace_sched_switch"},
		{"walk_udp", KindIter, "bpf_iter_udp"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %v, want %v", i, got[i], want[i])
		}
	}
	if !got[4].IsTypedef() || got[0].IsTypedef() {
		t.Error("only tp_btf targets are typedefs")
	}
}

func TestFromCollectionSpecUnknownTracingKindIsAnError(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"odd": {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceKprobeMulti, AttachTo: "x"},
	}}
	if _, err := FromCollectionSpec(spec); err == nil || !strings.Contains(err.Error(), "odd") {
		t.Fatalf("an unknown tracing attach type must fail and name the program, got %v", err)
	}
}

func TestFromCollectionSpecTracingWithoutTargetIsAnError(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"bare": {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry},
	}}
	if _, err := FromCollectionSpec(spec); err == nil {
		t.Fatal("a tracing program without a target must fail")
	}
}

func TestFromObjectRejectsGarbage(t *testing.T) {
	if _, err := FromObject("junk.o", []byte("not an ELF")); err == nil || !strings.Contains(err.Error(), "junk.o") {
		t.Fatalf("got %v", err)
	}
}
