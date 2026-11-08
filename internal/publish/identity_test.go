package publish

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
)

const testExeHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func newIdentityPublisher(t *testing.T, port int, hash string) *Publisher {
	t.Helper()
	p, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, AgentVersion: "1.2.3", ExeSHA256: hash})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestHeartbeatCarriesIdentity(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newIdentityPublisher(t, port, testExeHash)
	p.Heartbeat(0)
	var hb asmv1.Heartbeat
	mustUnmarshal(t, readStream(t, port, 1)[0].data, &hb)
	if hb.GetAgentVersion() != "1.2.3" || hb.GetExeSha256() != testExeHash {
		t.Fatalf("heartbeat identity = %q %q", hb.GetAgentVersion(), hb.GetExeSha256())
	}
}

func TestEmptyHashStaysEmpty(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newIdentityPublisher(t, port, "")
	p.Heartbeat(0)
	var hb asmv1.Heartbeat
	mustUnmarshal(t, readStream(t, port, 1)[0].data, &hb)
	if hb.GetAgentVersion() != "1.2.3" || hb.GetExeSha256() != "" {
		t.Fatalf("heartbeat identity = %q %q, want version and no hash", hb.GetAgentVersion(), hb.GetExeSha256())
	}
}

func TestHostBlocksCarryIdentity(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newIdentityPublisher(t, port, testExeHash)
	p.SetHost(model.HostInfo{Cloud: "aws"})
	p.SetHost(model.HostInfo{Cloud: "gcp"}) // a change: host.changed
	var ev asmv1.HostEvent
	mustUnmarshal(t, readStream(t, port, 1)[0].data, &ev)
	for name, h := range map[string]*asmv1.HostInfo{"host": ev.GetHost(), "previous": ev.GetPrevious()} {
		if h.GetAgentVersion() != "1.2.3" || h.GetExeSha256() != testExeHash {
			t.Errorf("%s identity = %q %q", name, h.GetAgentVersion(), h.GetExeSha256())
		}
	}
	if ev.GetStopping() {
		t.Error("an ordinary host change is marked stopping")
	}
}

func TestStoppingHostEvent(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newIdentityPublisher(t, port, testExeHash)
	p.SetHost(model.HostInfo{Cloud: "aws"})
	p.Heartbeat(0)
	p.Stopping()
	msgs := readStream(t, port, 2)
	if msgs[1].subject != "asm."+testHost+".host.changed" {
		t.Fatalf("stop marker on %q", msgs[1].subject)
	}
	var hb asmv1.Heartbeat
	var ev asmv1.HostEvent
	mustUnmarshal(t, msgs[0].data, &hb)
	mustUnmarshal(t, msgs[1].data, &ev)
	if !ev.GetStopping() || ev.GetRunId() != hb.GetRunId() || ev.GetSeq() != hb.GetSeq()+1 || ev.GetHostId() != testHost {
		t.Fatalf("stop marker = %v after heartbeat %v", &ev, &hb)
	}
	if !proto.Equal(ev.GetHost(), ev.GetPrevious()) || ev.GetHost().GetCloud() != "aws" {
		t.Fatalf("stop marker host %v, previous %v: want the unchanged host block", ev.GetHost(), ev.GetPrevious())
	}
}

// The design assumes a stop marker the drain could not send goes out first on the next
// run, ahead of that run's heartbeats (spool order).
func TestSpooledStopPrecedesNextRun(t *testing.T) {
	port := freePort(t)
	dir := t.TempDir()
	a, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, SpoolDir: dir, SpoolMax: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	a.Stopping()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	startServer(t, port, t.TempDir())
	b, err := New(context.Background(), Config{URL: natsURL(port), HostID: testHost, SpoolDir: dir, SpoolMax: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	b.Heartbeat(0)
	msgs := readStream(t, port, 2)
	var ev asmv1.HostEvent
	var hb asmv1.Heartbeat
	mustUnmarshal(t, msgs[0].data, &ev)
	mustUnmarshal(t, msgs[1].data, &hb)
	if !ev.GetStopping() || ev.GetRunId() != a.runID || hb.GetRunId() != b.runID {
		t.Fatalf("order: %v then %v, want A's stop marker then B's heartbeat", &ev, &hb)
	}
}

// Old agents' messages lack the new fields and decode as empty; old consumers skip them.
func TestIdentityRoundTripAndOldSchema(t *testing.T) {
	hb := &asmv1.Heartbeat{HostId: testHost, RunId: "r", AgentVersion: "1.2.3", ExeSha256: testExeHash}
	b, err := proto.Marshal(hb)
	if err != nil {
		t.Fatal(err)
	}
	var back asmv1.Heartbeat
	if err := proto.Unmarshal(b, &back); err != nil || !proto.Equal(hb, &back) {
		t.Fatalf("round trip: %v, %v", &back, err)
	}
	old, err := proto.Marshal(&asmv1.Heartbeat{HostId: testHost, RunId: "r"})
	if err != nil {
		t.Fatal(err)
	}
	var fromOld asmv1.Heartbeat
	if err := proto.Unmarshal(old, &fromOld); err != nil || fromOld.GetAgentVersion() != "" || fromOld.GetExeSha256() != "" {
		t.Fatalf("old heartbeat decodes as %v, %v", &fromOld, err)
	}
	hi := &asmv1.HostInfo{Cloud: "aws", AgentVersion: "1.2.3", ExeSha256: testExeHash}
	ev := &asmv1.HostEvent{Host: hi, Stopping: true}
	if b, err = proto.Marshal(ev); err != nil {
		t.Fatal(err)
	}
	var evBack asmv1.HostEvent
	if err := proto.Unmarshal(b, &evBack); err != nil || !proto.Equal(ev, &evBack) {
		t.Fatalf("host event round trip: %v, %v", &evBack, err)
	}
}
