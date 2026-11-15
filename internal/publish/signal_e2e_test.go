package publish_test

import (
	"context"
	"crypto/ed25519"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/ingesttest"
	"github.com/slidehq/signal/schema/protocol"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/thapr0digy/portwarden/internal/agent"
	"github.com/thapr0digy/portwarden/internal/ingest/doortest"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/publish"
)

const e2eHost = "0123456789abcdef0123456789abcdef"

type events chan model.Observation

func (e events) Events() <-chan model.Observation { return e }

func listenerAt(port uint16) model.ListenerKey {
	return model.NewKey(4026531840, "tcp", netip.MustParseAddr("0.0.0.0"), port)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stored(ref *ingesttest.Server, typ string, port uint32) *eventsv1.Event {
	for _, e := range ref.Stored() {
		if e.GetType() == typ && (port == 0 || e.GetListenerChange().GetListener().GetPort() == port) {
			return e
		}
	}
	return nil
}

// The task's acceptance proof: a listener opened on the agent (its real event loop, fed
// one kernel observation) is stored by Signal's reference door, which runs the product's
// own signature, validation, scope and run-cursor code (schema/protocol). The host's key
// is the seed natsauth mints, registered the way import-nkeys registers it.
func TestE2EListenerOpenedOnTheAgentIsStoredBySignal(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "host-"+e2eHost+".nk")
	kp, err := natsauth.CreateUserSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	kp.Wipe()
	key, err := natsauth.ReadUserKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	ref := ingesttest.New()
	ref.AddPrincipal(protocol.Principal{ID: "pr-1", Kind: eventsv1.ProducerAgent, HostID: e2eHost}, "ak-1", key.Public().(ed25519.PublicKey))
	ts, pin := doortest.Start(t, ref, 0)

	pub, err := publish.New(context.Background(), publish.Config{
		HostID: e2eHost, AgentVersion: "v1.0.0", BootID: "boot-1", RunNumber: 1,
		SpoolDir: t.TempDir(),
		Ingest:   &publish.IngestConfig{URL: ts.URL, Pin: pin, KeyFile: seed, KeyID: "ak-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub.SetHost(model.HostInfo{Cloud: "aws", InstanceID: "i-0abc"})

	src := make(events)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	baseline := []model.Observation{{Kind: model.Opened, Cookie: 1, Key: listenerAt(22), Source: model.SourceBaseline,
		Proc: model.Process{PID: 10, Comm: "sshd"}}}
	go func() {
		done <- agent.Run(ctx, src, func() ([]model.Observation, error) { return baseline, nil }, pub, agent.Options{})
	}()
	waitFor(t, "the baseline snapshot", func() bool { return stored(ref, "asm.host.snapshot", 0) != nil })

	src <- model.Observation{Kind: model.Opened, Cookie: 2, Key: listenerAt(8080), At: time.Now(), Source: model.SourceEBPF,
		Proc: model.Process{PID: 42, Comm: "api", Cmdline: []string{"api", "--password=hunter2", "--port=8080"}}}
	pub.Heartbeat(0)
	waitFor(t, "asm.listener.opened for :8080", func() bool { return stored(ref, "asm.listener.opened", 8080) != nil })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	pub.Stopping()
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "asm.agent.stopping", func() bool { return stored(ref, "asm.agent.stopping", 0) != nil })

	opened := stored(ref, "asm.listener.opened", 8080)
	lc := opened.GetListenerChange()
	if lc.GetListener().GetKey() != listenerAt(8080).String() || lc.GetProcesses()[0].GetPid() != 42 ||
		lc.GetHost().GetInstanceId() != "i-0abc" || opened.GetSubject() != "host:"+e2eHost {
		t.Fatalf("opened = %v", opened)
	}
	if js, _ := protojson.Marshal(opened); strings.Contains(string(js), "hunter2") {
		t.Fatalf("a secret argument reached Signal: %s", js)
	}
	snap := stored(ref, "asm.host.snapshot", 0).GetHostSnapshot()
	if len(snap.GetListeners()) != 1 || snap.GetListeners()[0].GetListener().GetPort() != 22 {
		t.Fatalf("snapshot = %v", snap)
	}

	// One run, every seq once and in order, nothing refused, no gap.
	all := ref.Stored()
	run := all[0].GetSequence().GetRunId()
	var seqs []uint64
	for _, e := range all {
		if e.GetSequence().GetRunId() != run || e.GetSequence().GetBootId() != "boot-1" || e.GetSequence().GetRunNumber() != 1 {
			t.Fatalf("event of another run: %v", e.GetSequence())
		}
		seqs = append(seqs, e.GetSequence().GetSeq())
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("seqs %v are not 1..n", seqs)
		}
	}
	if !slices.IsSorted(seqs) || len(ref.Quarantined()) != 0 || len(ref.Gaps()) != 0 {
		t.Fatalf("quarantined %v, gaps %v", ref.Quarantined(), ref.Gaps())
	}
}
