package publish

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/ingesttest"
	"github.com/slidehq/signal/schema/protocol"
	"github.com/slidehq/signal/schema/sign"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/thapr0digy/portwarden/internal/ingest/doortest"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/tamper"
)

const testKeyID = "ak-1"

// hostSeed writes a host seed (as natsauth mints it) and returns its path and public key.
func hostSeed(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host.nk")
	kp, err := natsauth.CreateUserSeed(path)
	if err != nil {
		t.Fatal(err)
	}
	kp.Wipe()
	key, err := natsauth.ReadUserKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, key.Public().(ed25519.PublicKey)
}

// counted counts the requests that reach h.
func counted(h http.Handler) (http.Handler, *atomic.Int32) {
	var n atomic.Int32
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h.ServeHTTP(w, r)
	}), &n
}

// refDoor is Signal's reference server behind pinned TLS, with the host registered as
// testKeyID unless register is false.
func refDoor(t *testing.T, pub ed25519.PublicKey, register bool) (*ingesttest.Server, IngestConfig, *atomic.Int32) {
	t.Helper()
	ref := ingesttest.New()
	if register {
		ref.AddPrincipal(protocol.Principal{ID: "pr-1", Kind: eventsv1.ProducerAgent, HostID: testHost}, testKeyID, pub)
	}
	h, hits := counted(ref)
	ts, pin := doortest.Start(t, h, 0)
	return ref, IngestConfig{URL: ts.URL, Pin: pin, KeyID: testKeyID}, hits
}

func ingestPublisher(t *testing.T, ic IngestConfig) *Publisher {
	t.Helper()
	p, err := New(context.Background(), Config{HostID: testHost, AgentVersion: "v1.0.0", BootID: "boot-1", RunNumber: 1, Ingest: &ic})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func types(evs []*eventsv1.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.GetType()
	}
	return out
}

func healthFlag(p *Publisher) string {
	flags, _ := p.IngestCheck().Run()
	if len(flags) == 0 {
		return ""
	}
	if flags[0].Kind != tamper.KindIngestRefused {
		return "wrong kind " + flags[0].Kind
	}
	return flags[0].Fingerprint
}

func TestIngest429And503WaitForRetryAfter(t *testing.T) {
	keyFile, pub := hostSeed(t)
	ref, ic, _ := refDoor(t, pub, true)
	ic.KeyFile = keyFile
	ref.Fail(http.StatusTooManyRequests, time.Second)
	ref.Fail(http.StatusServiceUnavailable, time.Second)
	p := ingestPublisher(t, ic)
	start := time.Now()
	p.Heartbeat(1)
	eventually(t, "the heartbeat", func() bool { return len(ref.Stored()) == 1 })
	if took := time.Since(start); took < 1900*time.Millisecond {
		t.Fatalf("delivered after %s: the two Retry-After: 1 were not waited for", took)
	}
}

func TestIngestUnknownKeyRaisesTheFlagUntilTheKeyIsRegistered(t *testing.T) {
	keyFile, pub := hostSeed(t)
	ref, ic, hits := refDoor(t, pub, false)
	ic.KeyFile = keyFile
	p := ingestPublisher(t, ic)
	p.Heartbeat(1)
	eventually(t, "the unknown_key flag", func() bool { return healthFlag(p) == "unknown_key" })
	ref.AddPrincipal(protocol.Principal{ID: "pr-1", Kind: eventsv1.ProducerAgent, HostID: testHost}, testKeyID, pub)
	eventually(t, "delivery once the key is known", func() bool { return len(ref.Stored()) == 1 })
	eventually(t, "the flag to clear", func() bool { return healthFlag(p) == "" })
	if hits.Load() < 2 {
		t.Fatalf("hits %d: the 401 was not retried", hits.Load())
	}
}

func healthDetail(p *Publisher) string {
	flags, _ := p.IngestCheck().Run()
	if len(flags) == 0 {
		return ""
	}
	return flags[0].Detail
}

// A 401 whose body names no code (a proxy's page, an empty answer) is still a refusal.
func TestIngestUnauthorizedWithoutABodyRaisesTheFlag(t *testing.T) {
	keyFile, _ := hostSeed(t)
	var refuse atomic.Bool
	refuse.Store(true)
	ts, pin := doortest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if refuse.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		out, _ := proto.Marshal(ok(1))
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(out)
	}), 0)
	p := ingestPublisher(t, IngestConfig{URL: ts.URL, Pin: pin, KeyID: testKeyID, KeyFile: keyFile})
	p.Heartbeat(1)
	eventually(t, "the http_401 flag", func() bool { return healthFlag(p) == "http_401" })
	refuse.Store(false)
	eventually(t, "the flag to clear once a batch is accepted", func() bool { return healthFlag(p) == "" })
}

// A 415 is about the request's encoding, not an event: nothing is split or dropped.
func TestIngestUnsupportedMediaTypeRetriesAndDropsNothing(t *testing.T) {
	keyFile, _ := hostSeed(t)
	var refuse atomic.Bool
	refuse.Store(true)
	var delivered atomic.Int32
	ic, calls := scriptedDoor(t, func(_ int, b *eventsv1.Batch) (int, *eventsv1.IngestResponse) {
		if refuse.Load() {
			return http.StatusUnsupportedMediaType, &eventsv1.IngestResponse{Error: &eventsv1.ErrorInfo{Code: "unsupported_media_type"}}
		}
		delivered.Add(int32(len(b.GetEvents()))) //nolint:gosec // a test batch
		return http.StatusOK, ok(len(b.GetEvents()))
	})
	ic.KeyFile = keyFile
	p := ingestPublisher(t, ic)
	for i := uint64(1); i <= 3; i++ {
		p.Heartbeat(i)
	}
	eventually(t, "the unsupported_media_type flag", func() bool { return healthFlag(p) == "unsupported_media_type" })
	eventually(t, "several refused attempts", func() bool { return calls.Load() >= 4 })
	if p.q.Dropped() != 0 || p.q.Len() != 3 {
		t.Fatalf("after 415s: dropped %d, spooled %d: want nothing dropped and all 3 kept", p.q.Dropped(), p.q.Len())
	}
	refuse.Store(false)
	eventually(t, "all three heartbeats", func() bool { return delivered.Load() == 3 })
	if p.q.Dropped() != 0 {
		t.Fatalf("dropped %d", p.q.Dropped())
	}
}

func TestIngestStopHaltsSendingAndKeepsSpooling(t *testing.T) {
	keyFile, pub := hostSeed(t)
	ref, ic, hits := refDoor(t, pub, true)
	ic.KeyFile = keyFile
	p := ingestPublisher(t, ic)
	p.Heartbeat(1)
	eventually(t, "the first heartbeat", func() bool { return len(ref.Stored()) == 1 })
	ref.Disable("pr-1")
	p.Heartbeat(2)
	eventually(t, "the principal_disabled flag", func() bool { return healthFlag(p) == "principal_disabled" })
	sent := hits.Load()
	p.Heartbeat(3)
	time.Sleep(5 * reconnectWait)
	if hits.Load() != sent {
		t.Fatalf("requests after STOP: %d -> %d", sent, hits.Load())
	}
	if p.q.Len() != 2 {
		t.Fatalf("spool holds %d, want both unsent heartbeats", p.q.Len())
	}
}

// scriptedDoor decodes each batch and answers with what answer returns.
func scriptedDoor(t *testing.T, answer func(call int, b *eventsv1.Batch) (int, *eventsv1.IngestResponse)) (IngestConfig, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	ts, pin := doortest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "gzip", http.StatusBadRequest)
			return
		}
		raw, _ := io.ReadAll(zr)
		b := &eventsv1.Batch{}
		if err := proto.Unmarshal(raw, b); err != nil {
			http.Error(w, "proto", http.StatusBadRequest)
			return
		}
		status, resp := answer(int(calls.Add(1)), b)
		out, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		_, _ = w.Write(out)
	}), 0)
	return IngestConfig{URL: ts.URL, Pin: pin, KeyID: testKeyID}, &calls
}

func ok(n int, ds ...*eventsv1.Directive) *eventsv1.IngestResponse {
	return &eventsv1.IngestResponse{Accepted: uint32(n), Directives: ds} //nolint:gosec // a test batch
}

func TestIngestSplitsARefusedBatchAndDropsAnEventThatIsRefusedAlone(t *testing.T) {
	keyFile, _ := hostSeed(t)
	var mu sync.Mutex
	var got []uint64
	ic, _ := scriptedDoor(t, func(_ int, b *eventsv1.Batch) (int, *eventsv1.IngestResponse) {
		if len(b.GetEvents()) > 1 {
			return http.StatusRequestEntityTooLarge, &eventsv1.IngestResponse{}
		}
		if b.GetEvents()[0].GetHeartbeat().GetRingbufDrops() == 2 {
			return http.StatusUnprocessableEntity, &eventsv1.IngestResponse{}
		}
		mu.Lock()
		got = append(got, b.GetEvents()[0].GetHeartbeat().GetRingbufDrops())
		mu.Unlock()
		return http.StatusOK, ok(1)
	})
	ic.KeyFile = keyFile
	p := ingestPublisher(t, ic)
	for i := uint64(1); i <= 3; i++ {
		p.Heartbeat(i)
	}
	eventually(t, "heartbeats 1 and 3", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 2
	})
	if got[0] != 1 || got[1] != 3 || p.q.Dropped() != 1 {
		t.Fatalf("delivered %v, dropped %d: want 1 and 3 delivered and 2 dropped", got, p.q.Dropped())
	}
}

func TestIngestResyncSnapshotDirectiveSendsAFullSnapshot(t *testing.T) {
	keyFile, _ := hostSeed(t)
	var snapshots atomic.Int32
	ic, _ := scriptedDoor(t, func(call int, b *eventsv1.Batch) (int, *eventsv1.IngestResponse) {
		for _, e := range b.GetEvents() {
			if e.GetType() == "asm.host.snapshot" {
				snapshots.Add(1)
			}
		}
		if call == 2 { // the heartbeat after the first snapshot: the server lost track
			return http.StatusOK, ok(len(b.GetEvents()), &eventsv1.Directive{Kind: eventsv1.Directive_RESYNC_SNAPSHOT})
		}
		return http.StatusOK, ok(len(b.GetEvents()))
	})
	ic.KeyFile = keyFile
	p := ingestPublisher(t, ic)
	p.Snapshot(nil, nil)
	eventually(t, "the first snapshot", func() bool { return snapshots.Load() == 1 })
	p.Heartbeat(1)
	eventually(t, "the resync snapshot", func() bool { return snapshots.Load() == 2 })
}

func TestIngestLimitsAndBackoffDirectives(t *testing.T) {
	keyFile, _ := hostSeed(t)
	var mu sync.Mutex
	var sizes []int
	var at []time.Time
	ic, _ := scriptedDoor(t, func(call int, b *eventsv1.Batch) (int, *eventsv1.IngestResponse) {
		mu.Lock()
		sizes, at = append(sizes, len(b.GetEvents())), append(at, time.Now())
		mu.Unlock()
		if call == 1 {
			return http.StatusOK, ok(len(b.GetEvents()),
				&eventsv1.Directive{Kind: eventsv1.Directive_LIMITS, MaxEvents: 2},
				&eventsv1.Directive{Kind: eventsv1.Directive_BACKOFF, After: timestamppb.New(time.Now().Add(time.Second))})
		}
		return http.StatusOK, ok(len(b.GetEvents()))
	})
	ic.KeyFile = keyFile
	p := ingestPublisher(t, ic)
	p.Heartbeat(0)
	eventually(t, "the first batch", func() bool { mu.Lock(); defer mu.Unlock(); return len(sizes) == 1 })
	for i := uint64(1); i <= 5; i++ {
		p.Heartbeat(i)
	}
	eventually(t, "the queue to drain", func() bool { return p.q.Len() == 0 })
	mu.Lock()
	defer mu.Unlock()
	for _, n := range sizes[1:] {
		if n > 2 {
			t.Fatalf("batch sizes %v: LIMITS max_events 2 was not kept", sizes)
		}
	}
	if gap := at[1].Sub(at[0]); gap < 900*time.Millisecond {
		t.Fatalf("second request %s after the first: BACKOFF was not kept", gap)
	}
}

func TestIngestAnotherServerKeyRaisesPinMismatch(t *testing.T) {
	keyFile, pub := hostSeed(t)
	_, ic, hits := refDoor(t, pub, true)
	ic.KeyFile = keyFile
	_, ic.Pin = doortest.Cert(t, doortest.Seed(9))
	p := ingestPublisher(t, ic)
	p.Heartbeat(1)
	eventually(t, "the pin_mismatch flag", func() bool { return healthFlag(p) == "pin_mismatch" })
	if hits.Load() != 0 {
		t.Fatal("a request reached the server with the wrong key")
	}
}

// enrolDoor is the reference server plus POST /v1/enroll: a good join code registers the
// signed request's key under keyid "ak-enrolled".
func enrolDoor(t *testing.T) (*ingesttest.Server, IngestConfig, *atomic.Int32) {
	t.Helper()
	ref := ingesttest.New()
	var enrols atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("/v1/ingest/batch", ref)
	mux.HandleFunc("/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		enrols.Add(1)
		params, err := sign.ParseHeaders(r.Header)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Token     string `json:"token"`
			Pubkey    string `json:"pubkey"`
			MachineID string `json:"machine_id"`
			Hostname  string `json:"hostname"`
		}
		_ = json.Unmarshal(body, &req)
		pub, _ := base64.StdEncoding.DecodeString(req.Pubkey)
		w.Header().Set("Content-Type", "application/json")
		if err != nil || len(pub) != ed25519.PublicKeySize || sign.Verify(r, body, params, pub, time.Now(), 0) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if req.Token != "join-good" || req.MachineID != testHost || req.Hostname != "web-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"bad_token"}}`)
			return
		}
		ref.AddPrincipal(protocol.Principal{ID: "pr-e", Kind: eventsv1.ProducerAgent, HostID: testHost}, "ak-enrolled", pub)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"principal_id":"pr-e","keyid":"ak-enrolled"}`)
	})
	ts, pin := doortest.Start(t, mux, 0)
	return ref, IngestConfig{URL: ts.URL, Pin: pin, Hostname: "web-1"}, &enrols
}

func TestIngestEnrolsWithAJoinCodeOnceAndKeepsTheKeyID(t *testing.T) {
	ref, ic, enrols := enrolDoor(t)
	dir := t.TempDir()
	ic.KeyFile, ic.KeyIDFile, ic.JoinCodeFile = filepath.Join(dir, "ingest", "key.nk"), filepath.Join(dir, "ingest", "keyid"), filepath.Join(dir, "join")
	if err := os.WriteFile(ic.JoinCodeFile, []byte("join-good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ingestPublisher(t, ic)
	if st, err := os.Stat(ic.KeyFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("host key not created 0600: %v %v", st, err)
	}
	p.Heartbeat(1)
	eventually(t, "the heartbeat", func() bool { return len(ref.Stored()) == 1 })
	if b, _ := os.ReadFile(ic.KeyIDFile); strings.TrimSpace(string(b)) != "ak-enrolled" {
		t.Fatalf("key id file holds %q", b)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// The next run reads the key id: no second enrolment (the code is spent).
	p2, err := New(context.Background(), Config{HostID: testHost, AgentVersion: "v1.0.0", BootID: "boot-1", RunNumber: 2, Ingest: &ic})
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	p2.Heartbeat(2)
	eventually(t, "the next run's heartbeat", func() bool { return len(ref.Stored()) == 2 })
	if enrols.Load() != 1 {
		t.Fatalf("enrolled %d times", enrols.Load())
	}
}

func TestIngestRefusedEnrolmentHalts(t *testing.T) {
	ref, ic, enrols := enrolDoor(t)
	dir := t.TempDir()
	ic.KeyFile, ic.KeyIDFile, ic.JoinCodeFile = filepath.Join(dir, "key.nk"), filepath.Join(dir, "keyid"), filepath.Join(dir, "join")
	if err := os.WriteFile(ic.JoinCodeFile, []byte("join-spent"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ingestPublisher(t, ic)
	p.Heartbeat(1)
	eventually(t, "the bad_token flag", func() bool { return healthFlag(p) == "bad_token" })
	time.Sleep(5 * reconnectWait)
	if enrols.Load() != 1 || len(ref.Stored()) != 0 {
		t.Fatalf("enrolments %d, stored %d: a refused enrolment must stop the run", enrols.Load(), len(ref.Stored()))
	}
	if _, err := os.Stat(ic.KeyIDFile); err == nil {
		t.Fatal("a key id file was written for a refused enrolment")
	}
}

// The door registers the key and spends the code, but its 201 never reaches the agent: the
// retry is refused, and the flag says how to recover.
func TestIngestRefusedEnrolmentAfterALostAnswerSaysHowToRecover(t *testing.T) {
	var enrols atomic.Int32
	ts, pin := doortest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if enrols.Add(1) == 1 {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"code":"bad_token"}}`)
	}), 0)
	dir := t.TempDir()
	ic := IngestConfig{URL: ts.URL, Pin: pin, Hostname: "web-1",
		KeyFile: filepath.Join(dir, "key.nk"), KeyIDFile: filepath.Join(dir, "keyid"), JoinCodeFile: filepath.Join(dir, "join")}
	if err := os.WriteFile(ic.JoinCodeFile, []byte("join-good"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := ingestPublisher(t, ic)
	p.Heartbeat(1)
	eventually(t, "the bad_token flag", func() bool { return healthFlag(p) == "bad_token" })
	detail := healthDetail(p)
	for _, want := range []string{"already be registered", "signal admin ingest principal list", "--ingest-key-id", ic.KeyIDFile} {
		if !strings.Contains(detail, want) {
			t.Errorf("flag detail %q does not mention %q", detail, want)
		}
	}
	if enrols.Load() != 2 {
		t.Fatalf("enrolment attempts %d: want the lost one and the refused retry", enrols.Load())
	}
}

func TestIngestConfigIsChecked(t *testing.T) {
	keyFile, _ := hostSeed(t)
	_, pin := doortest.Cert(t, doortest.Seed(1))
	good := IngestConfig{URL: "https://127.0.0.1:8443", Pin: pin, KeyFile: keyFile, KeyID: testKeyID}
	missingKey := good
	missingKey.KeyFile = filepath.Join(t.TempDir(), "absent.nk")
	noKeyID := good
	noKeyID.KeyID = ""
	badPin := good
	badPin.Pin = "sha256/AAAA"
	for name, cfg := range map[string]Config{
		"NATS settings too":           {HostID: testHost, URL: "nats://127.0.0.1:4222", Ingest: &good},
		"no key id and no join code":  {HostID: testHost, Ingest: &noKeyID},
		"a registered key is missing": {HostID: testHost, Ingest: &missingKey},
		"a bad pin":                   {HostID: testHost, Ingest: &badPin},
		"no destination":              {HostID: testHost},
	} {
		if p, err := New(context.Background(), cfg); err == nil {
			p.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(missingKey.KeyFile); err == nil {
		t.Fatal("a key was created for a host that is not enrolling")
	}
}

func TestBackoffGrowsWithJitterAndIsCapped(t *testing.T) {
	for n := 1; n <= 40; n++ {
		d := backoff(n)
		full := min(reconnectWait<<min(n-1, 16), ingestMaxBackoff)
		if d < full/2 || d > full {
			t.Fatalf("backoff(%d) = %s, want within [%s, %s]", n, d, full/2, full)
		}
	}
}
