package ingesttest

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/protocol"
	"github.com/slidehq/signal/schema/sign"
)

const host = "0123456789abcdef0123456789abcdef"

type rig struct {
	t    *testing.T
	srv  *Server
	ts   *httptest.Server
	priv ed25519.PrivateKey
}

func newRig(t *testing.T) *rig {
	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	s := New()
	s.AddPrincipal(protocol.Principal{ID: "p1", Kind: eventsv1.ProducerAgent, HostID: host}, "k1", priv.Public().(ed25519.PublicKey))
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return &rig{t: t, srv: s, ts: ts, priv: priv}
}

func hb(run string, seq uint64, id string) *eventsv1.Event {
	return &eventsv1.Event{
		Id: id, Source: "urn:asm:agent:" + host, Type: "asm.agent.heartbeat", Subject: "host:" + host, Time: timestamppb.Now(),
		Sequence: &eventsv1.Sequence{RunId: run, Seq: seq, BootId: "b", RunNumber: 1},
		Data:     &eventsv1.Event_Heartbeat{Heartbeat: &eventsv1.Heartbeat{AgentVersion: "v1"}},
	}
}

func (r *rig) post(evs ...*eventsv1.Event) (*http.Response, *eventsv1.IngestResponse) {
	r.t.Helper()
	body, err := proto.Marshal(&eventsv1.Batch{Events: evs})
	if err != nil {
		r.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", r.ts.URL+"/v1/ingest/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", ContentBinary)
	if err := sign.Sign(req, body, r.priv, "k1", time.Now()); err != nil {
		r.t.Fatal(err)
	}
	res, err := r.ts.Client().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(res.Body)
	out := &eventsv1.IngestResponse{}
	if err := proto.Unmarshal(buf.Bytes(), out); err != nil {
		if err := protojson.Unmarshal(buf.Bytes(), out); err != nil {
			r.t.Fatalf("response: %v", err)
		}
	}
	return res, out
}

func TestStoreDuplicateGapAndStop(t *testing.T) {
	r := newRig(t)
	res, out := r.post(hb(run, 1, ulid("E1")), hb(run, 2, ulid("E2")))
	if res.StatusCode != 200 || out.Accepted != 2 {
		t.Fatalf("first: %d %+v", res.StatusCode, out)
	}
	_, out = r.post(hb(run, 2, ulid("E2")), hb(run, 3, ulid("E3")))
	if out.Duplicates != 1 || out.Accepted != 1 {
		t.Fatalf("retry after a lost response: %+v", out)
	}
	_, out = r.post(hb(run, 7, ulid("E7")))
	if len(out.Directives) != 1 || out.Directives[0].Kind != eventsv1.Directive_RESYNC_SNAPSHOT || len(r.srv.Gaps()) != 1 {
		t.Fatalf("gap: %+v %+v", out, r.srv.Gaps())
	}
	if n := len(r.srv.Stored()); n != 4 {
		t.Fatalf("stored %d, want 4", n)
	}
	r.srv.Disable("p1")
	res, out = r.post(hb(run, 8, ulid("E8")))
	if res.StatusCode != 403 || out.Directives[0].Kind != eventsv1.Directive_STOP {
		t.Fatalf("disabled: %d %+v", res.StatusCode, out)
	}
}

func TestForcedStatusesAndRefusals(t *testing.T) {
	r := newRig(t)
	for _, st := range []int{429, 503} {
		r.srv.Fail(st, 7*time.Second)
		res, _ := r.post(hb(run, 1, ulid("X")))
		if res.StatusCode != st || res.Header.Get("Retry-After") != "7" {
			t.Fatalf("%d: got %d retry-after %q", st, res.StatusCode, res.Header.Get("Retry-After"))
		}
	}
	// An agent writing another host's subject is quarantined, and the event is not stored.
	e := hb(run, 1, ulid("Y"))
	e.Subject = "host:ffffffffffffffffffffffffffffffff"
	_, out := r.post(e)
	if len(out.Rejected) != 1 || out.Rejected[0].Code != "forbidden_subject" || len(r.srv.Stored()) != 0 || len(r.srv.Quarantined()) != 1 {
		t.Fatalf("scope: %+v", out)
	}
	// An unsigned request is a 401 before anything is read.
	req, _ := http.NewRequest("POST", r.ts.URL+"/v1/ingest/batch", bytes.NewReader([]byte("x")))
	req.Header.Set("Content-Type", ContentBinary)
	res, err := r.ts.Client().Do(req)
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("unsigned: %v %v", res, err)
	}
	res.Body.Close()
}

// run is a valid run id (a ULID).
const run = "01JC8Z0000000000000000RVN1"

// ulid makes a valid 26-character id from a short label.
func ulid(label string) string {
	const pad = "01JC8Z0000000000000000000000"
	return pad[:26-len(label)] + label
}
