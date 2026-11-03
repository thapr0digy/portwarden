package publish

import (
	"testing"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/tamper"
)

func TestTamperEventAndHeartbeatStatus(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	p.Heartbeat(0) // before any pass: no tamper block
	since := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	flag := tamper.Flag{Kind: tamper.KindPtraced, Subject: "self", Detail: "pid 7 (gdb) traces thread(s) 1", Since: since}
	st := tamper.Status{Flags: []tamper.Flag{flag}, CheckedAt: since, Checks: []string{"probes", "ptrace"},
		Unknown: []string{"unit: not running as a systemd service"}, RunCounts: map[string]uint64{"on_listen": 4}, RingbufDrops: 2}
	p.SetTamper(st)
	p.Tamper(tamper.Transition{Raised: []tamper.Flag{flag}, Status: st})
	p.Heartbeat(2)

	msgs := readStream(t, port, 3)
	want := []string{"heartbeat", "tamper", "heartbeat"}
	for i, m := range msgs {
		if m.subject != "asm."+testHost+"."+want[i] {
			t.Fatalf("message %d on %s, want %s", i, m.subject, want[i])
		}
	}
	var hb0 asmv1.Heartbeat
	mustUnmarshal(t, msgs[0].data, &hb0)
	if hb0.Tamper != nil {
		t.Fatalf("heartbeat before any pass carries tamper: %v", &hb0)
	}
	var ev asmv1.TamperEvent
	mustUnmarshal(t, msgs[1].data, &ev)
	if ev.HostId != testHost || ev.Seq != 2 || len(ev.Raised) != 1 || ev.Raised[0].Kind != "ptraced" ||
		!ev.Raised[0].Since.AsTime().Equal(since) || len(ev.Status.GetFlags()) != 1 || ev.Status.GetRingbufDrops() != 2 {
		t.Fatalf("tamper event = %v", &ev)
	}
	var hb asmv1.Heartbeat
	mustUnmarshal(t, msgs[2].data, &hb)
	ts := hb.GetTamper()
	if len(ts.GetFlags()) != 1 || ts.GetFlags()[0].GetDetail() != flag.Detail || len(ts.GetChecks()) != 2 ||
		len(ts.GetUnknown()) != 1 || ts.GetProgRunCounts()["on_listen"] != 4 {
		t.Fatalf("heartbeat tamper = %v", ts)
	}
}
