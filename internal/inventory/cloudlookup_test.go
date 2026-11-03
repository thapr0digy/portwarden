package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/cloud"
)

type fakeCloudState struct {
	hosts  map[string]CloudHost
	status map[string]string
}

func (f *fakeCloudState) CloudHost(_ context.Context, h string) (CloudHost, bool, error) {
	c, ok := f.hosts[h]
	return c, ok, nil
}
func (f *fakeCloudState) CloudHosts(context.Context) ([]string, error) {
	var out []string
	for h := range f.hosts {
		out = append(out, h)
	}
	return out, nil
}
func (f *fakeCloudState) SetCloudStatus(_ context.Context, h, s string, _ time.Time) error {
	f.status[h] = s
	return nil
}

type fakeProvider struct {
	incomplete bool
	open       map[string]bool
	err        error
	got        []cloud.Port
}

func (f *fakeProvider) Evaluate(_ context.Context, _ cloud.Host, ports []cloud.Port) ([]cloud.Verdict, error) {
	f.got = ports
	if f.err != nil {
		return nil, f.err
	}
	var out []cloud.Verdict
	for _, p := range ports {
		v := cloud.Verdict{Key: p.Key, Open: f.open[p.Key]}
		if v.Open {
			v.Evidence = []string{"cloud: sg-1 allows tcp from 0.0.0.0/0"}
		}
		v.Complete = !f.incomplete
		out = append(out, v)
	}
	return out, nil
}

func TestCloudLookupPublishesOnlyChanges(t *testing.T) {
	state := &fakeCloudState{status: map[string]string{}, hosts: map[string]CloudHost{"h1": {ID: "h1", Cloud: "aws", InstanceID: "i-1", Region: "r",
		Listeners: []CloudListener{
			{Key: "a", Proto: "tcp", Port: 443, AgentLevel: 3},
			{Key: "b", Proto: "tcp", Port: 8080, AgentLevel: 2},
			{Key: "c", Proto: "tcp", Port: 631, AgentLevel: 1},
			{Key: "d", Proto: "tcp", Port: 22, AgentLevel: 1, CloudLevel: 4}, // went local
		}}}}
	prov := &fakeProvider{open: map[string]bool{"a": true}}
	var sent []*asmv1.ExposureEvent
	l := NewCloudLookup(state, map[string]cloud.Provider{"aws": prov}, func(_ context.Context, subject, _ string, m proto.Message) error {
		if subject != "pwb.cloud.h1.exposure" {
			t.Errorf("subject %s", subject)
		}
		sent = append(sent, m.(*asmv1.ExposureEvent))
		return nil
	}, "cloud-run")
	if err := l.Check(context.Background(), "h1"); err != nil {
		t.Fatal(err)
	}
	if len(prov.got) != 2 {
		t.Fatalf("evaluated %+v; only level >= bound", prov.got)
	}
	if len(sent) != 2 || sent[0].GetListener().GetKey() != "a" || sent[0].GetExposure().GetLevel() != asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN ||
		sent[0].GetOrigin() != "cloud" || sent[0].GetSeq() != 0 || sent[0].GetPrevious().GetLevel() != asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN {
		t.Fatalf("sent %v", sent)
	}
	if sent[1].GetListener().GetKey() != "d" || sent[1].GetExposure().GetLevel() != asmv1.ExposureLevel_EXPOSURE_LOCAL {
		t.Fatalf("stale close: %v", sent[1])
	}
	if !strings.HasPrefix(state.status["h1"], "ok: 2 listeners checked, 1 open") {
		t.Fatalf("status %q", state.status["h1"])
	}
	// Same verdicts again (as the store now holds them): nothing new.
	h := state.hosts["h1"]
	h.Listeners[0].CloudLevel, h.Listeners[0].CloudEvidence = 4, []string{"cloud: sg-1 allows tcp from 0.0.0.0/0"}
	h.Listeners[3].CloudLevel = 0
	state.hosts["h1"] = h
	sent = nil
	_ = l.Check(context.Background(), "h1")
	if len(sent) != 0 {
		t.Fatalf("republished unchanged verdicts: %v", sent)
	}
	// A failure keeps the verdicts and records the error.
	prov.err = errors.New("throttled")
	if err := l.Check(context.Background(), "h1"); err == nil || len(sent) != 0 || !strings.Contains(state.status["h1"], "throttled") {
		t.Fatalf("err %v sent %v status %q", err, sent, state.status["h1"])
	}
}

func TestCloudLookupUnsupported(t *testing.T) {
	state := &fakeCloudState{status: map[string]string{}, hosts: map[string]CloudHost{
		"g": {ID: "g", Cloud: "gcp", InstanceID: "1", Listeners: []CloudListener{{Key: "a", AgentLevel: 3}}},
		"x": {ID: "x", Cloud: "oracle", InstanceID: "1"},
		"n": {ID: "n"},
	}}
	l := NewCloudLookup(state, nil, func(context.Context, string, string, proto.Message) error {
		t.Fatal("published for an unsupported provider")
		return nil
	}, "r")
	for _, h := range []string{"g", "x", "n"} {
		if err := l.Check(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(state.status["g"], "unsupported provider gcp: no level 3 evidence") ||
		!strings.Contains(state.status["x"], "unsupported provider oracle") {
		t.Fatalf("status %v", state.status)
	}
	if _, ok := state.status["n"]; ok {
		t.Fatal("a host off-cloud got a cloud status")
	}
}

// Partial cloud data never lowers a verdict, and a verdict already published is not
// republished while the store has not caught up with it.
func TestCloudLookupIncompleteNeverLowers(t *testing.T) {
	state := &fakeCloudState{status: map[string]string{}, hosts: map[string]CloudHost{"h1": {ID: "h1", Cloud: "aws", InstanceID: "i-1", Region: "r",
		Listeners: []CloudListener{{Key: "a", Proto: "tcp", Port: 443, AgentLevel: 2, CloudLevel: 4, CloudEvidence: []string{"cloud: lb x"}}}}}}
	prov := &fakeProvider{open: map[string]bool{}, incomplete: true}
	sent := 0
	l := NewCloudLookup(state, map[string]cloud.Provider{"aws": prov}, func(context.Context, string, string, proto.Message) error {
		sent++
		return nil
	}, "r")
	if err := l.Check(context.Background(), "h1"); err != nil {
		t.Fatal(err)
	}
	if sent != 0 || !strings.HasPrefix(state.status["h1"], "incomplete:") {
		t.Fatalf("sent %d status %q", sent, state.status["h1"])
	}
	prov.incomplete, prov.open = false, map[string]bool{"b": true}
	h := state.hosts["h1"]
	h.Listeners = append(h.Listeners, CloudListener{Key: "b", Proto: "tcp", Port: 80, AgentLevel: 3})
	state.hosts["h1"] = h
	_ = l.Check(context.Background(), "h1") // lowers a (complete data), opens b
	_ = l.Check(context.Background(), "h1") // the store still has the old state: nothing new
	if sent != 2 {
		t.Fatalf("sent %d, want 2", sent)
	}
}
