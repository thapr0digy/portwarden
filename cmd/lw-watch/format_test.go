package main

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/listener-watch/gen/asm/v1"
)

const hostID = "0123456789abcdef0123456789abcdef"

var at = timestamppb.New(time.Date(2026, 10, 30, 14, 2, 11, 418_000_000, time.UTC))

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func openedEvent(run string, seq uint64) *asmv1.ListenerEvent {
	return &asmv1.ListenerEvent{
		HostId: hostID, RunId: run, Seq: seq, ObservedAt: at, Kind: asmv1.Kind_OPENED,
		Listener:  &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 8443},
		Processes: []*asmv1.Process{{Pid: 4410, Exe: "/opt/app/bin/server"}},
	}
}

func TestFormatOpened(t *testing.T) {
	got, err := formatEvent("asm."+hostID+".listener.opened", mustMarshal(t, openedEvent("r1", 42)))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=42 OPENED tcp 0.0.0.0:8443 pid=4410 /opt/app/bin/server"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatClosedIPv6AndNoProcess(t *testing.T) {
	ev := &asmv1.ListenerEvent{
		HostId: hostID, RunId: "r1", Seq: 3, ObservedAt: at, Kind: asmv1.Kind_CLOSED,
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "::", Port: 80},
	}
	got, err := formatEvent("asm."+hostID+".listener.closed", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=3 CLOSED tcp [::]:80"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatSnapshot(t *testing.T) {
	snap := &asmv1.Snapshot{HostId: hostID, RunId: "r1", Seq: 1, TakenAt: at}
	for i := 0; i < 12; i++ {
		snap.Listeners = append(snap.Listeners, &asmv1.ListenerState{})
	}
	got, err := formatEvent("asm."+hostID+".snapshot", mustMarshal(t, snap))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=1 SNAPSHOT n=12"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatHeartbeat(t *testing.T) {
	hb := &asmv1.Heartbeat{HostId: hostID, RunId: "r1", Seq: 9, At: at}
	got, err := formatEvent("asm."+hostID+".heartbeat", mustMarshal(t, hb))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=9 HEARTBEAT drops=0/0/0"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestFormatErrors(t *testing.T) {
	if _, err := formatEvent("asm.h.unknown", nil); err == nil {
		t.Fatal("unknown subject accepted")
	}
	if _, err := formatEvent("asm.h.snapshot", []byte{0xff, 0xff}); err == nil {
		t.Fatal("garbage payload accepted")
	}
}

func TestGapDetected(t *testing.T) {
	var g gapTracker
	var lines []string
	for _, seq := range []uint64{1, 2, 4} {
		ev := openedEvent("runA", seq)
		if l := g.check(ev.RunId, ev.Seq); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 || lines[0] != "GAP run=runA expected=3 got=4" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestNewRunNoGap(t *testing.T) {
	var g gapTracker
	g.check("runA", 7)
	if l := g.check("runB", 1); l != "" {
		t.Fatalf("new run produced %q", l)
	}
	if l := g.check("runB", 2); l != "" {
		t.Fatalf("contiguous produced %q", l)
	}
	if strings.Contains(g.check("runB", 2), "GAP") {
		t.Fatal("duplicate seq must not be a gap")
	}
}
