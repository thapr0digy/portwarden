package inventory

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

var tamperAt = time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)

func ptracedStatus() *asmv1.TamperStatus {
	return &asmv1.TamperStatus{
		Flags: []*asmv1.TamperFlag{{Kind: "ptraced", Subject: "self", Detail: "pid 7 (gdb)", Since: timestamppb.New(tamperAt),
			Fingerprint: "7", Info: false}},
		CheckedAt: timestamppb.New(tamperAt), Checks: []string{"probes", "ptrace"}, Unknown: []string{"unit: none"},
		ProgRunCounts: map[string]uint64{"on_listen": 4}, RingbufDrops: 2,
	}
}

func TestTamperCarried(t *testing.T) {
	st := ptracedStatus()
	for _, tc := range []struct {
		name string
		msg  proto.Message
		want *asmv1.TamperStatus
		ok   bool
	}{
		{"tamper event", &asmv1.TamperEvent{Status: st}, st, true},
		// A tamper event always says something: no status is "all checks pass".
		{"tamper event without status", &asmv1.TamperEvent{}, &asmv1.TamperStatus{}, true},
		{"heartbeat", &asmv1.Heartbeat{Tamper: st}, st, true},
		// An agent without tamper checks: leave the stored status.
		{"heartbeat without status", &asmv1.Heartbeat{}, nil, false},
		{"snapshot", &asmv1.Snapshot{}, nil, false},
	} {
		got, ok := TamperOf(tc.msg)
		if ok != tc.ok || (tc.want != nil && len(got.GetFlags()) != len(tc.want.GetFlags())) || (tc.want == nil && got != nil) {
			t.Errorf("%s: got %v %v", tc.name, got, ok)
		}
	}
}

func TestTamperViewJSON(t *testing.T) {
	b, err := TamperJSON(ptracedStatus())
	if err != nil {
		t.Fatal(err)
	}
	var v TamperView
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Flags) != 1 || v.Flags[0].Kind != "ptraced" || v.Flags[0].Subject != "self" || v.Flags[0].Fingerprint != "7" ||
		v.Flags[0].Since == nil || !v.Flags[0].Since.Equal(tamperAt) {
		t.Fatalf("flags %+v", v.Flags)
	}
	if v.CheckedAt == nil || !v.CheckedAt.Equal(tamperAt) || !slices.Equal(v.Checks, []string{"probes", "ptrace"}) ||
		!slices.Equal(v.Unknown, []string{"unit: none"}) || v.RingbufDrops != 2 {
		t.Fatalf("view %+v", v)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, has := raw["prog_run_counts"]; has {
		t.Fatal("per-program run counts are not stored")
	}
	// An empty status is explicit: no flags, empty lists (not null).
	b, err = TamperJSON(&asmv1.TamperStatus{})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"flags":[],"checked_at":null,"checks":[],"unknown":[],"ringbuf_drops":0}` {
		t.Fatalf("empty status JSON %s", b)
	}
}

// Tamper events are part of the agent's sequence: consuming them keeps a host in sync
// (before M8 the inventory ignored them, and every one left a gap).
func TestTamperEventsKeepTheSequence(t *testing.T) {
	f := newFake()
	c := &Consumer{Store: f}
	handle(t, c, "snapshot", &asmv1.Snapshot{HostId: host, RunId: "01A", Seq: 1})
	handle(t, c, "tamper", &asmv1.TamperEvent{HostId: host, RunId: "01A", Seq: 2, Status: ptracedStatus()})
	handle(t, c, "heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01A", Seq: 3})
	if got := seqs(f); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Fatalf("applied seqs %v", got)
	}
	if cur := f.cursors[host]; cur.LastSeq != 3 || cur.NeedsResync {
		t.Fatalf("cursor %+v: a tamper event must not leave a gap", cur)
	}
	// A late tamper event of an earlier run is skipped like any other.
	handle(t, c, "heartbeat", &asmv1.Heartbeat{HostId: host, RunId: "01B", Seq: 1, BootId: "b", RunNumber: 2})
	handle(t, c, "tamper", &asmv1.TamperEvent{HostId: host, RunId: "01A", Seq: 4, Status: ptracedStatus()})
	if got := seqs(f); !slices.Equal(got, []uint64{1, 2, 3, 1}) {
		t.Fatalf("applied seqs %v: the old run's tamper event was applied", got)
	}
}

func TestTamperEventForAnotherHostIsForged(t *testing.T) {
	c := &Consumer{Store: newFake()}
	err := handleErr(c, "asm."+host+".tamper", &asmv1.TamperEvent{HostId: "other", RunId: "01A", Seq: 1})
	if err == nil {
		t.Fatal("a tamper event naming another host was accepted")
	}
}
