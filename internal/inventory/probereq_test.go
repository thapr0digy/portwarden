package inventory

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
)

func TestBuildProbeRequest(t *testing.T) {
	in := ProbeInput{Key: "k", Proto: "tcp", Addr: "0.0.0.0", Port: 443, Level: 3,
		InboundIPs: []string{"203.0.113.1", "2001:db8::1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}}
	r := BuildProbeRequest("h", in, "exposure", time.Now())
	if !slices.Equal(r.GetAddresses(), []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}) ||
		!slices.Equal(r.GetPorts(), []uint32{443}) {
		t.Fatalf("%v", r)
	}
	in.Addr = "::"
	if r := BuildProbeRequest("h", in, "x", time.Now()); !slices.Contains(r.GetAddresses(), "2001:db8::1") {
		t.Fatalf(":: must include IPv6: %v", r.GetAddresses())
	}
	in.AgentEvidence = []string{model.EvidenceV6Only, "nft: accept tcp/443 from 0/0 (eth0, inet f in)"}
	if r := BuildProbeRequest("h", in, "x", time.Now()); !slices.Equal(r.GetAddresses(), []string{"2001:db8::1"}) {
		t.Fatalf("a v6-only :: listener is probed over IPv6 only: %v", r.GetAddresses())
	}
	in.Addr, in.AgentEvidence = "0.0.0.0", nil
	for i := range 10 {
		in.AgentEvidence = append(in.AgentEvidence, fmt.Sprintf("nat: dnat tcp/%d -> 172.17.0.2:80", 18000+i))
	}
	if r := BuildProbeRequest("h", in, "x", time.Now()); len(r.GetPorts()) != MaxProbePorts || r.GetPorts()[0] != 18000 {
		t.Fatalf("ports %v", r.GetPorts())
	}
	for _, bad := range []ProbeInput{{Addr: "127.0.0.1", Level: 3}, {Addr: "0.0.0.0", Level: 1}, {Addr: "junk", Level: 3}} {
		if BuildProbeRequest("h", bad, "x", time.Now()) != nil {
			t.Errorf("%+v requested", bad)
		}
	}
	if r := BuildProbeRequest("h", ProbeInput{Addr: "10.0.0.5", Port: 22, Proto: "tcp", Level: 2}, "x", time.Now()); !slices.Equal(r.GetAddresses(), []string{"10.0.0.5"}) {
		t.Fatalf("bind address: %v", r.GetAddresses())
	}
}

type fakeProbeState struct{ in ProbeInput }

func (f fakeProbeState) ProbeInput(context.Context, string, string) (ProbeInput, bool, error) {
	return f.in, true, nil
}
func (f fakeProbeState) StaleProbes(context.Context, time.Time, int) ([]HostKey, error) {
	return nil, nil
}

// The request uses stored state, and a full queue drops (and counts) instead of blocking.
func TestProbeRequesterUsesStoredStateAndBoundsItsQueue(t *testing.T) {
	var sent []*asmv1.ProbeRequest
	r := NewProbeRequester(fakeProbeState{ProbeInput{Key: "k", Proto: "tcp", Addr: "0.0.0.0", Port: 80, Level: 3,
		InboundIPs: []string{"203.0.113.9"}}}, func(_ context.Context, subject, _ string, m proto.Message) error {
		if subject != "pwb.probe.h.request" {
			t.Errorf("subject %s", subject)
		}
		sent = append(sent, m.(*asmv1.ProbeRequest))
		return nil
	})
	if err := r.Request(context.Background(), "h", "k", "exposure"); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].GetAddresses()[0] != "203.0.113.9" {
		t.Fatalf("%v", sent)
	}
	for range cap(r.queue) + 5 {
		r.Notify("h", "k")
	}
	if r.Dropped.Load() != 5 {
		t.Fatalf("dropped %d", r.Dropped.Load())
	}
}
