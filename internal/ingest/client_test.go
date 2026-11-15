package ingest_test

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/ingesttest"
	"github.com/slidehq/signal/schema/protocol"
	"github.com/slidehq/signal/schema/sign"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/thapr0digy/portwarden/internal/ingest"
	"github.com/thapr0digy/portwarden/internal/ingest/doortest"
)

const host = "0123456789abcdef0123456789abcdef"

var hostKey = ed25519.NewKeyFromSeed(doortest.Seed(7))

func heartbeat(seq uint64, run string) *eventsv1.Event {
	return &eventsv1.Event{
		Id: ulid.Make().String(), Type: "asm.agent.heartbeat",
		Source: "urn:asm:agent:" + host, Subject: "host:" + host, Time: timestamppb.Now(),
		Producer: &eventsv1.Producer{Name: "portwarden-agent", Version: "v1.0.0"},
		Sequence: &eventsv1.Sequence{RunId: run, Seq: seq, BootId: "boot-1", RunNumber: 1},
		Data:     &eventsv1.Event_Heartbeat{Heartbeat: &eventsv1.Heartbeat{RingbufDrops: seq}},
	}
}

func client(t *testing.T, url, pin string, local func(netip.Addr)) *ingest.Client {
	t.Helper()
	c, err := ingest.New(ingest.Config{URL: url, Pin: pin, Key: hostKey, LocalAddr: local})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The verification's "sample signed batch accepted by the reference server": a gzipped,
// signed binary batch through pinned TLS 1.3 to Signal's own ingesttest.
func TestSignedBatchIsAcceptedByTheReferenceServer(t *testing.T) {
	ref := ingesttest.New()
	ref.AddPrincipal(protocol.Principal{ID: "pr-1", Kind: eventsv1.ProducerAgent, HostID: host}, "ak-1", hostKey.Public().(ed25519.PublicKey))
	ts, pin := doortest.Start(t, ref, 0)
	var local atomic.Bool
	c := client(t, ts.URL, pin, func(a netip.Addr) { local.Store(a.IsLoopback()) })

	run := ulid.Make().String()
	a, err := c.Batch(t.Context(), "ak-1", &eventsv1.Batch{Events: []*eventsv1.Event{heartbeat(1, run), heartbeat(2, run)}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != http.StatusOK || a.Resp.GetAccepted() != 2 || len(a.Resp.GetRejected()) != 0 {
		t.Fatalf("answer %d %v", a.Status, a.Resp)
	}
	if c := a.Resp.GetCursor(); c.GetRunId() != run || c.GetSeq() != 2 {
		t.Fatalf("cursor %v", c)
	}
	if got := len(ref.Stored()); got != 2 {
		t.Fatalf("stored %d", got)
	}
	if !local.Load() {
		t.Fatal("the local address of the connection was not reported")
	}
	// A key the door does not know is an answer (401 unknown_key), not an error.
	a, err = c.Batch(t.Context(), "ak-other", &eventsv1.Batch{Events: []*eventsv1.Event{heartbeat(3, run)}})
	if err != nil || a.Status != http.StatusUnauthorized || a.Code() != "unknown_key" {
		t.Fatalf("unknown key: %d %q %v", a.Status, a.Code(), err)
	}
}

func TestAnotherServerKeyIsRefusedBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int32
	ts, _ := doortest.Start(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), 0)
	_, otherPin := doortest.Cert(t, doortest.Seed(2))
	_, err := client(t, ts.URL, otherPin, nil).Batch(t.Context(), "ak-1", &eventsv1.Batch{Events: []*eventsv1.Event{heartbeat(1, ulid.Make().String())}})
	var pe *ingest.PinError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a PinError", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the request reached a server with the wrong key")
	}
}

func TestTLS12IsRefused(t *testing.T) {
	var hits atomic.Int32
	ts, pin := doortest.Start(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), tls.VersionTLS12)
	if _, err := client(t, ts.URL, pin, nil).Batch(t.Context(), "ak-1", &eventsv1.Batch{}); err == nil || hits.Load() != 0 {
		t.Fatalf("a TLS 1.2 door was used: err %v, hits %d", err, hits.Load())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var redirected atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ingest/batch", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/elsewhere", func(http.ResponseWriter, *http.Request) { redirected.Add(1) })
	ts, pin := doortest.Start(t, mux, 0)
	a, err := client(t, ts.URL, pin, nil).Batch(t.Context(), "ak-1", &eventsv1.Batch{})
	if err != nil || a.Status != http.StatusTemporaryRedirect || redirected.Load() != 0 {
		t.Fatalf("status %d err %v redirected %d", a.Status, err, redirected.Load())
	}
}

func TestRetryAfterSecondsDatesAndCap(t *testing.T) {
	for _, c := range []struct {
		header string
		want   time.Duration
	}{
		{"", 0}, {"7", 7 * time.Second}, {"0", 0}, {"-3", 0}, {"junk", 0},
		{"999999999", time.Hour},
		{time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat), 90 * time.Second},
		{time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat), 0},
	} {
		ts, pin := doortest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
			w.WriteHeader(http.StatusTooManyRequests)
		}), 0)
		a, err := client(t, ts.URL, pin, nil).Batch(t.Context(), "ak-1", &eventsv1.Batch{})
		if err != nil {
			t.Fatal(err)
		}
		// An HTTP date has 1 s precision.
		if d := a.RetryAfter - c.want; d < -time.Second || d > time.Second {
			t.Errorf("Retry-After %q = %s, want %s", c.header, a.RetryAfter, c.want)
		}
	}
}

func TestEnrolSignsWithTheKeyItRegistersAndReturnsTheAssignedKeyID(t *testing.T) {
	ts, pin := doortest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ingest.EnrollPath {
			http.NotFound(w, r)
			return
		}
		params, err := sign.ParseHeaders(r.Header)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Token, Pubkey, Machine_ID, Hostname string //nolint:revive // the wire names
		}
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err != nil || dec.Decode(&req) != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		pub, _ := base64.StdEncoding.DecodeString(req.Pubkey)
		if sign.Verify(r, body, params, pub, time.Now(), 0) != nil || req.Token != "join-1" || req.Machine_ID != host {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"bad_token"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"principal_id":"pr-9","keyid":"ak-9"}`)
	}), 0)
	c := client(t, ts.URL, pin, nil)
	kid, a, err := c.Enroll(t.Context(), ingest.Enrolment{JoinCode: "join-1", MachineID: host, Hostname: "web-1"})
	if err != nil || kid != "ak-9" || a.Status != http.StatusCreated {
		t.Fatalf("enrol: %q %d %v", kid, a.Status, err)
	}
	kid, a, err = c.Enroll(t.Context(), ingest.Enrolment{JoinCode: "spent", MachineID: host})
	if err != nil || kid != "" || a.Status != http.StatusForbidden || a.Code() != "bad_token" {
		t.Fatalf("bad code: %q %d %q %v", kid, a.Status, a.Code(), err)
	}
}

func TestConfigIsChecked(t *testing.T) {
	_, pin := doortest.Cert(t, doortest.Seed(1))
	for name, cfg := range map[string]ingest.Config{
		"http":       {URL: "http://100.64.0.5:8443", Pin: pin, Key: hostKey},
		"path":       {URL: "https://100.64.0.5:8443/v1", Pin: pin, Key: hostKey},
		"user info":  {URL: "https://u:p@100.64.0.5:8443", Pin: pin, Key: hostKey},
		"no pin":     {URL: "https://100.64.0.5:8443", Key: hostKey},
		"short pin":  {URL: "https://100.64.0.5:8443", Pin: "sha256/AAAA", Key: hostKey},
		"other hash": {URL: "https://100.64.0.5:8443", Pin: strings.Replace(pin, "sha256/", "sha1/", 1), Key: hostKey},
		"no key":     {URL: "https://100.64.0.5:8443", Pin: pin},
	} {
		if _, err := ingest.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOversizedBatchIsRefusedLocally(t *testing.T) {
	var hits atomic.Int32
	ts, pin := doortest.Start(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), 0)
	ev := heartbeat(1, ulid.Make().String())
	ev.GetHeartbeat().AgentVersion = strings.Repeat("x", ingest.MaxDecompressed)
	_, err := client(t, ts.URL, pin, nil).Batch(t.Context(), "ak-1", &eventsv1.Batch{Events: []*eventsv1.Event{ev}})
	if !errors.Is(err, ingest.ErrTooLarge) || hits.Load() != 0 {
		t.Fatalf("err %v hits %d", err, hits.Load())
	}
}
