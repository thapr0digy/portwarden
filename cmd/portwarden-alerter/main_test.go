package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/alerter"
	"github.com/thapr0digy/portwarden/internal/alerter/pgstate"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/backend/testnats"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// TestMain doubles as the alerter binary for the child-process tests: with
// PW_TEST_HELPER set it runs the real main (with an in-memory store, or PostgreSQL with
// PW_TEST_REAL_PG) on --config PW_TEST_CONFIG.
func TestMain(m *testing.M) {
	defaultHealthListen = "127.0.0.1:0" // tests never take the real port
	if os.Getenv("PW_TEST_HELPER") == "1" {
		openStore = opener(newFakeStore())
		if os.Getenv("PW_TEST_REAL_PG") == "1" {
			openStore = openPG // the two-instance tests (handover_integration_test.go)
		}
		os.Args = []string{os.Args[0], "--config", os.Getenv("PW_TEST_CONFIG")}
		main()
		return
	}
	os.Exit(m.Run())
}

const (
	fakeDSN       = "postgres://alerter@127.0.0.1/pw_test"
	webhookSecret = "webhook-secret-0123456789"
	host          = testnats.Host
)

func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PORTWARDEN_ALERTER_DSN", "")
	t.Setenv("PORTWARDEN_ALERTER_WEBHOOK_SECRET", "")
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func configFile(t *testing.T, cfg any) string {
	t.Helper()
	if s, ok := cfg.(string); ok {
		return writeFile(t, "alerter.json", s)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "alerter.json", string(b))
}

func TestLoadBadConfig(t *testing.T) {
	clearEnv(t)
	if _, err := load(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	for name, body := range map[string]string{
		"bad json":          `{"rules": `,
		"unknown key":       `{"rule": {}}`,
		"negative duration": `{"rules": {"dedupe_window": "-1h"}}`,
		"wrong type":        `{"webhook": {"max_attempts": "lots"}}`,
	} {
		p := configFile(t, body)
		if _, err := load(p); err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("%s: %v (want an error naming the file)", name, err)
		}
	}
}

func TestLoadValidation(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	secret := writeFile(t, "secret", webhookSecret)
	for name, c := range map[string]struct{ body, want string }{
		"bad page level": {`{"rules": {"page_level": "loud"}}`, "page_level"},
		"plain http":     {`{"webhook": {"url": "http://hooks.example/pw", "secret_file": "` + secret + `"}}`, "must be https"},
		"not a url":      {`{"webhook": {"url": "::nope", "secret_file": "` + secret + `"}}`, "is not a URL"},
	} {
		if _, err := load(configFile(t, c.body)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
	st, err := load(configFile(t, `{}`))
	if err != nil || st.hook != nil || st.dsn != fakeDSN || st.rules.PageLevel != "host_firewall_open" ||
		st.rules.DedupeWindow != time.Hour || !st.rules.PageOnConfirmed || !st.rules.PageOnSilence || !st.rules.PageOnTamper {
		t.Fatalf("defaults: %+v %v", st, err)
	}
	st, err = load(configFile(t, `{"rules": {"page_level": "confirmed", "page_on_confirmed": false, "dedupe_window": "1m"}}`))
	if err != nil || st.rules.PageLevel != "confirmed" || st.rules.PageOnConfirmed || st.rules.DedupeWindow != time.Minute {
		t.Fatalf("set rules: %+v %v", st.rules, err)
	}
	st, err = load(configFile(t, `{"webhook": {"url": "http://127.0.0.1:1/pw", "allow_insecure": true, "secret_file": "`+secret+`", "timeout": "2s"}}`))
	if err != nil || st.hook == nil || st.hook.Timeout != 2*time.Second || string(st.hook.Secret) != webhookSecret {
		t.Fatalf("webhook: %+v %v", st.hook, err)
	}
}

func TestLoadMissingCredentials(t *testing.T) {
	clearEnv(t)
	empty := writeFile(t, "empty", "\n")
	hook := `"webhook": {"url": "https://hooks.example/pw"`
	for name, c := range map[string]struct{ body, want string }{
		"no dsn":            {`{}`, "postgres dsn: set PORTWARDEN_ALERTER_DSN"},
		"empty dsn file":    {`{"postgres_dsn_file": "` + empty + `"}`, "postgres dsn: " + empty + " is empty"},
		"dsn file gone":     {`{"postgres_dsn_file": "` + filepath.Join(t.TempDir(), "nope") + `"}`, "postgres dsn: "},
		"no webhook secret": {`{` + hook + `}}`, "webhook secret: set PORTWARDEN_ALERTER_WEBHOOK_SECRET"},
		"empty secret file": {`{` + hook + `, "secret_file": "` + empty + `"}}`, "webhook secret: "},
	} {
		if _, err := load(configFile(t, c.body)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
	// The environment wins over the files, trimmed.
	t.Setenv("PORTWARDEN_ALERTER_DSN", " "+fakeDSN+"\n")
	t.Setenv("PORTWARDEN_ALERTER_WEBHOOK_SECRET", webhookSecret)
	st, err := load(configFile(t, `{"postgres_dsn_file": "`+empty+`", `+hook+`, "secret_file": "`+empty+`"}}`))
	if err != nil || st.dsn != fakeDSN || string(st.hook.Secret) != webhookSecret {
		t.Fatalf("env: %+v %v", st, err)
	}
}

func TestOpenPGBadDSN(t *testing.T) {
	if s, err := openPG(context.Background(), "postgres://%zz"); err == nil || s != nil || !strings.Contains(err.Error(), "pgstate: dsn") {
		t.Fatalf("%v %v", s, err)
	}
}

func TestExitCode(t *testing.T) {
	if exitCode(nil) != 0 || exitCode(context.Canceled) != 0 || exitCode(fmt.Errorf("consume: %w", context.Canceled)) != 0 {
		t.Fatal("a clean stop must exit 0")
	}
	if exitCode(errors.New("postgres dsn: set PORTWARDEN_ALERTER_DSN")) != 1 {
		t.Fatal("an error must exit 1")
	}
}

// newApp builds the app as run does, around an in-memory store.
func newApp(t *testing.T, store *fakeStore, hook *alerter.Webhook) *app {
	t.Helper()
	rules := alerter.Rules{PageOnConfirmed: true, PageOnSilence: true, PageOnTamper: true, PageOnUncleanRestart: true}
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	a := &app{engine: alerter.NewEngine(rules, bus.NewEventID), store: store, live: liveness.New(time.Minute),
		feed: liveness.NewFeed(time.Minute, time.Now()), hook: hook, maxAttempts: 20,
		tamperSig: map[string]string{}, noSilence: map[string]bool{}, runSig: map[string]string{}, out: io.Discard,
		forgotten: alerter.NewForgotten(nil), stream: time.Unix(1700000000, 0)}
	return a
}

func marshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func listenerAt(port uint32) *asmv1.Listener {
	return &asmv1.Listener{Netns: 1, Proto: "tcp", Addr: "0.0.0.0", Port: port, Key: fmt.Sprintf("1/tcp/0.0.0.0:%d", port)}
}

func exposure(port uint32, level, prev asmv1.ExposureLevel, origin string) *asmv1.ExposureEvent {
	return &asmv1.ExposureEvent{HostId: host, Listener: listenerAt(port), Origin: origin,
		Exposure: &asmv1.Exposure{Level: level}, Previous: &asmv1.Exposure{Level: prev}}
}

func TestHeartbeatAndTamper(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	a := newApp(t, store, nil)
	a.replayUpTo = 10
	hb := marshal(t, &asmv1.Heartbeat{HostId: host, RunId: "r1", At: timestamppb.Now()})
	subj := bus.Subject(host, bus.KindHeartbeat)

	// A replayed heartbeat seeds liveness and records the host's run (M11, one
	// transaction: a restart while the alerter was down is judged from the replay); it
	// pages nothing.
	if err := a.heartbeat(ctx, fakeMsg{subject: subj, data: hb, seq: 5}); err != nil || store.txs != 1 || store.runs[host].ID != "r1" {
		t.Fatalf("replay: %v, %d transactions, run %+v", err, store.txs, store.runs[host])
	}
	// A live one checks for an outstanding silence page once, then no more.
	for range 2 {
		if err := a.heartbeat(ctx, fakeMsg{subject: subj, data: hb, seq: 11}); err != nil {
			t.Fatal(err)
		}
	}
	if store.txs != 2 || !a.noSilence[host] {
		t.Fatalf("live heartbeats: %d transactions, quiet %v", store.txs, a.noSilence[host])
	}
	// Forged, undecodable and foreign messages.
	forged := marshal(t, &asmv1.Heartbeat{HostId: "other"})
	for name, m := range map[string]fakeMsg{
		"forged heartbeat": {subject: subj, data: forged, seq: 12},
		"bad heartbeat":    {subject: subj, data: []byte("\xff"), seq: 12},
		"forged tamper":    {subject: bus.Subject(host, bus.KindTamper), data: marshal(t, &asmv1.TamperEvent{HostId: "other"}), seq: 12},
		"bad tamper":       {subject: bus.Subject(host, bus.KindTamper), data: []byte("\xff"), seq: 12},
		"bad forgotten":    {subject: bus.ForgottenSubject(host), data: []byte("\xff"), seq: 12},
	} {
		if err := a.heartbeat(ctx, m); !svc.IsPermanent(err) {
			t.Errorf("%s: %v (want permanent)", name, err)
		}
	}
	if err := a.heartbeat(ctx, fakeMsg{subject: "nope", data: hb}); err != nil {
		t.Errorf("foreign subject: %v", err)
	}

	// A raised tamper flag pages once; the same status again touches no database.
	tamper := marshal(t, &asmv1.TamperEvent{HostId: host, Status: &asmv1.TamperStatus{Flags: []*asmv1.TamperFlag{{Kind: "ptraced", Subject: "self"}}}})
	for range 2 {
		if err := a.heartbeat(ctx, fakeMsg{subject: bus.Subject(host, bus.KindTamper), data: tamper, seq: 13}); err != nil {
			t.Fatal(err)
		}
	}
	if k := store.kinds(); len(k) != 1 || k[0] != alerter.KindTamper || store.txs != 3 {
		t.Fatalf("tamper: pages %v, %d transactions", k, store.txs)
	}
	// An empty tamper event clears it.
	if err := a.heartbeat(ctx, fakeMsg{subject: bus.Subject(host, bus.KindTamper), data: marshal(t, &asmv1.TamperEvent{HostId: host}), seq: 14}); err != nil || a.tamperSig[host] != "" {
		t.Fatalf("cleared: %v %q", err, a.tamperSig[host])
	}
	// A database outage is a transient error (the message is retried).
	store.txFails = 1
	delete(a.noSilence, host)
	if err := a.heartbeat(ctx, fakeMsg{subject: subj, data: hb, seq: 15}); err == nil || svc.IsPermanent(err) {
		t.Fatalf("outage: %v", err)
	}
}

// M11: a stop marker (host.changed with stopping) before the next run's heartbeat is a
// clean restart; a new run without one raises one informational alert; heartbeats of a
// stored run touch no database.
func TestCleanAndUncleanRestart(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	a := newApp(t, store, nil)
	subj := bus.Subject(host, bus.KindHeartbeat)
	beat := func(run string, n uint64, seq uint64) {
		t.Helper()
		b := marshal(t, &asmv1.Heartbeat{HostId: host, RunId: run, BootId: "b1", RunNumber: n, AgentVersion: "1.4.0", At: timestamppb.Now()})
		if err := a.heartbeat(ctx, fakeMsg{subject: subj, data: b, seq: seq}); err != nil {
			t.Fatal(err)
		}
	}
	beat("r1", 1, 1)
	txs := store.txs
	beat("r1", 1, 2)
	if store.txs != txs {
		t.Fatalf("a heartbeat of the stored run used %d transactions", store.txs-txs)
	}
	hi := &asmv1.HostInfo{AgentVersion: "1.4.0"}
	stop := marshal(t, &asmv1.HostEvent{HostId: host, RunId: "r1", BootId: "b1", RunNumber: 1, Host: hi, Previous: hi, Stopping: true})
	if err := a.heartbeat(ctx, fakeMsg{subject: bus.Subject(host, bus.KindHostChanged), data: stop, seq: 3}); err != nil {
		t.Fatal(err)
	}
	beat("r2", 2, 4)
	if k := store.kinds(); len(k) != 0 {
		t.Fatalf("clean restart paged %v", k)
	}
	beat("r3", 3, 5)
	if k := store.kinds(); len(k) != 1 || k[0] != alerter.KindAgentRestartedUnclean {
		t.Fatalf("unclean restart: pages %v", k)
	}
	forged := marshal(t, &asmv1.HostEvent{HostId: "other", RunId: "r3", Stopping: true})
	if err := a.heartbeat(ctx, fakeMsg{subject: bus.Subject(host, bus.KindHostChanged), data: forged, seq: 6}); !svc.IsPermanent(err) {
		t.Fatalf("forged stop marker: %v (want permanent)", err)
	}
}

func TestExposureAndConfirmation(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	a := newApp(t, store, nil)
	agent := bus.Subject(host, bus.KindExposureChanged)
	open := asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN
	bound := asmv1.ExposureLevel_EXPOSURE_BOUND

	// Newly reachable from the agent pages; the same listener again is deduped.
	for range 2 {
		if err := a.exposure(ctx, fakeMsg{subject: agent, data: marshal(t, exposure(443, open, bound, "")), seq: 1}); err != nil {
			t.Fatal(err)
		}
	}
	// A cloud verdict for another listener pages too.
	if err := a.exposure(ctx, fakeMsg{subject: bus.CloudSubject(host), data: marshal(t, exposure(8443, asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN, bound, "cloud")), seq: 2}); err != nil {
		t.Fatal(err)
	}
	// The outside checker confirms a third listener: a page.
	conf := marshal(t, &asmv1.ExposureConfirmation{HostId: host, Listener: listenerAt(22), Result: "confirmed"})
	if err := a.exposure(ctx, fakeMsg{subject: bus.VerifierSubject(host), data: conf, seq: 3}); err != nil {
		t.Fatal(err)
	}
	want := []string{alerter.KindConfirmed, alerter.KindNewlyReachable, alerter.KindNewlyReachable}
	if k := store.kinds(); strings.Join(k, ",") != strings.Join(want, ",") {
		t.Fatalf("pages %v, want %v", k, want)
	}
	for name, m := range map[string]fakeMsg{
		"agent claims cloud origin": {subject: agent, data: marshal(t, exposure(1, open, bound, "cloud")), seq: 4},
		"exposure for another host": {subject: bus.CloudSubject(host), data: marshal(t, &asmv1.ExposureEvent{HostId: "other"}), seq: 4},
		"bad exposure":              {subject: agent, data: []byte("\xff"), seq: 4},
		"forged confirmation":       {subject: bus.VerifierSubject(host), data: marshal(t, &asmv1.ExposureConfirmation{HostId: "other"}), seq: 4},
		"bad confirmation":          {subject: bus.VerifierSubject(host), data: []byte("\xff"), seq: 4},
	} {
		if err := a.exposure(ctx, m); !svc.IsPermanent(err) {
			t.Errorf("%s: %v (want permanent)", name, err)
		}
	}
	if err := a.exposure(ctx, fakeMsg{subject: "asm.only"}); err != nil {
		t.Errorf("unparsable subject: %v", err)
	}
}

// The inventory's forgotten-host announcement drops the host's state once; its leftovers
// are skipped, verdicts about it are skipped until it comes back, and its first agent
// message after the announcement brings it back.
func TestForgetAnnouncement(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	a := newApp(t, store, nil)
	a.noSilence[host], a.tamperSig[host] = true, "x"
	forget := fakeMsg{subject: bus.ForgottenSubject(host), data: marshal(t, &asmv1.HostForgotten{HostId: host}), seq: 10}
	if err := a.heartbeat(ctx, forget); err != nil {
		t.Fatal(err)
	}
	if m, ok := store.marks[host]; !ok || m.Seq != 10 || a.noSilence[host] || a.tamperSig[host] != "" {
		t.Fatalf("after forget: mark %+v %v, caches %v %q", m, ok, a.noSilence[host], a.tamperSig[host])
	}
	txs := store.txs
	if err := a.heartbeat(ctx, forget); err != nil || store.txs != txs {
		t.Fatalf("second delivery: %v, %d transactions (want none)", err, store.txs-txs)
	}
	if err := a.heartbeat(ctx, fakeMsg{subject: forget.subject, data: marshal(t, &asmv1.HostForgotten{HostId: "other"}), seq: 11}); !svc.IsPermanent(err) {
		t.Fatalf("forged forget: %v", err)
	}
	open, bound := asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN, asmv1.ExposureLevel_EXPOSURE_BOUND
	// Stored before the announcement: leftovers.
	hb := marshal(t, &asmv1.Heartbeat{HostId: host})
	if err := a.heartbeat(ctx, fakeMsg{subject: bus.Subject(host, bus.KindHeartbeat), data: hb, seq: 9}); err != nil {
		t.Fatal(err)
	}
	if err := a.exposure(ctx, fakeMsg{subject: bus.Subject(host, bus.KindExposureChanged), data: marshal(t, exposure(443, open, bound, "")), seq: 9}); err != nil {
		t.Fatal(err)
	}
	// A verdict after it, while the host has not come back: skipped.
	if err := a.exposure(ctx, fakeMsg{subject: bus.CloudSubject(host), data: marshal(t, exposure(443, asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN, bound, "cloud")), seq: 12}); err != nil {
		t.Fatal(err)
	}
	if len(store.pages()) != 0 {
		t.Fatalf("pages for a forgotten host: %v", store.kinds())
	}
	// Its agent comes back: a new host; its exposure pages again.
	if err := a.exposure(ctx, fakeMsg{subject: bus.Subject(host, bus.KindExposureChanged), data: marshal(t, exposure(443, open, bound, "")), seq: 13}); err != nil {
		t.Fatal(err)
	}
	if !store.marks[host].Back || len(store.pages()) != 1 {
		t.Fatalf("came back: mark %+v, pages %v", store.marks[host], store.kinds())
	}
	if err := a.heartbeat(ctx, fakeMsg{subject: bus.Subject(host, bus.KindHeartbeat), data: hb, seq: 14}); err != nil {
		t.Fatal(err)
	}
}

// retry stores a decision without a message to fall back on until it succeeds.
func TestRetryUntilStored(t *testing.T) {
	store := newFakeStore()
	a := newApp(t, store, nil)
	store.txFails = 1
	calls := 0
	a.retry(context.Background(), "feed", func(alerter.State) (alerter.Decision, error) { calls++; return alerter.Decision{}, nil })
	if calls != 1 || store.txs != 2 {
		t.Fatalf("calls %d, transactions %d", calls, store.txs)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store.txFails = 5
	a.retry(ctx, "feed", func(alerter.State) (alerter.Decision, error) { return alerter.Decision{}, nil })
}

// queued puts a page in the store's outbox.
func queued(store *fakeStore, id string, attempts int) {
	store.outbox = append(store.outbox, &fakePage{Page: pgstate.Page{ID: id, Attempts: attempts,
		Alert: alerter.Alert{ID: id, Kind: alerter.KindNewlyReachable, Host: host, Summary: "tcp 0.0.0.0:443 on " + host}}})
}

// runDeliver runs the delivery loop until cond holds.
func runDeliver(t *testing.T, a *app, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.deliver(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("delivery never got there")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}

type syncBuf struct {
	mu  chan struct{}
	buf bytes.Buffer
}

func newSyncBuf() *syncBuf { return &syncBuf{mu: make(chan struct{}, 1)} }
func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu <- struct{}{}
	defer func() { <-b.mu }()
	return b.buf.Write(p)
}
func (b *syncBuf) String() string {
	b.mu <- struct{}{}
	defer func() { <-b.mu }()
	return b.buf.String()
}

func TestDeliver(t *testing.T) {
	t.Run("stdout only", func(t *testing.T) {
		store := newFakeStore()
		queued(store, "p1", 0)
		a := newApp(t, store, nil)
		out := newSyncBuf()
		a.out = out
		runDeliver(t, a, func() bool { return store.pages()[0].delivered })
		var got alerter.Alert
		if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &got); err != nil || got.ID != "p1" {
			t.Fatalf("stdout %q: %v", out.String(), err)
		}
	})
	t.Run("webhook", func(t *testing.T) {
		var status atomic.Int32
		status.Store(http.StatusOK)
		var posts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			posts.Add(1)
			w.WriteHeader(int(status.Load()))
		}))
		defer srv.Close()
		hook := alerter.NewWebhook(srv.URL, []byte(webhookSecret), time.Second, 1)

		store := newFakeStore()
		queued(store, "ok", 0)
		a := newApp(t, store, hook)
		runDeliver(t, a, func() bool { return store.pages()[0].delivered })

		// A server error is retried later; a client error gives up at once.
		status.Store(http.StatusInternalServerError)
		store = newFakeStore()
		queued(store, "retry", 0)
		a = newApp(t, store, hook)
		runDeliver(t, a, func() bool { return store.pages()[0].Attempts == 1 })
		if p := store.pages()[0]; p.gaveUp || p.delivered || !p.next.After(time.Now()) || p.lastErr == "" {
			t.Fatalf("5xx: %+v", p)
		}
		status.Store(http.StatusBadRequest)
		store = newFakeStore()
		queued(store, "bad", 0)
		a = newApp(t, store, hook)
		runDeliver(t, a, func() bool { return store.pages()[0].gaveUp })
		// The last allowed attempt gives up too.
		status.Store(http.StatusServiceUnavailable)
		store = newFakeStore()
		queued(store, "last", 19)
		a = newApp(t, store, hook)
		runDeliver(t, a, func() bool { return store.pages()[0].gaveUp })
		if posts.Load() < 4 {
			t.Fatalf("posts %d", posts.Load())
		}
	})
	t.Run("outbox unreadable", func(t *testing.T) {
		store := newFakeStore()
		store.dueErr = errors.New("pg: connection refused")
		a := newApp(t, store, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		defer cancel()
		a.deliver(ctx) // logs and keeps going until ctx ends
	})
}

// natsConfig is the config's nats block for the alerter user of ts.
func natsConfig(ts *testnats.Server) svc.NATS {
	return svc.NATS{URL: ts.URL, NkeyFile: ts.Seeds[natsauth.RoleAlerter]}
}

func TestRunStartFailures(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	missing := filepath.Join(t.TempDir(), "alerter.nk")
	failing := func(context.Context, string) (stateStore, error) { return nil, errors.New("pg: connection refused") }
	for name, c := range map[string]struct {
		cfg  Config
		open openStoreFunc
		want string
	}{
		"store down":        {Config{}, failing, "connection refused"},
		"missing seed":      {Config{NATS: svc.NATS{URL: "nats://127.0.0.1:1", NkeyFile: missing}}, nil, "bus: "},
		"unreadable seed":   {Config{NATS: svc.NATS{URL: "nats://127.0.0.1:1", NkeyFile: writeFile(t, "nk", "not a seed")}}, nil, "bus: nkey"},
		"cert without key":  {Config{NATS: svc.NATS{URL: "nats://127.0.0.1:1", CertFile: missing}}, nil, "together"},
		"malformed address": {Config{NATS: svc.NATS{URL: "nats://[::1"}}, nil, "bus: connect"},
	} {
		store := newFakeStore()
		open := c.open
		if open == nil {
			open = opener(store)
		}
		err := run(ctx, configFile(t, c.cfg), open)
		if err == nil || !strings.Contains(err.Error(), c.want) || exitCode(err) != 1 {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
		if c.open == nil && !store.closed {
			t.Errorf("%s: store left open", name)
		}
	}
}

// The alerter connects with its own seed, waits for the stream, loads its forget marks,
// creates both consumers, pages a newly reachable listener and delivers the page to the
// webhook; on cancel it stops its workers before closing the store and returns
// context.Canceled (exit 0).
func TestRunWiringAndShutdown(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	ts := testnats.Start(t)
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == "" {
			t.Error("webhook post without a content type")
		}
		posts.Add(1)
	}))
	defer srv.Close()
	p := configFile(t, `{"nats": {"url": "`+ts.URL+`", "nkey_file": "`+ts.Seeds[natsauth.RoleAlerter]+`"},
		"webhook": {"url": "`+srv.URL+`", "allow_insecure": true, "secret_file": "`+writeFile(t, "secret", webhookSecret)+`"}}`)
	store := newFakeStore()
	store.pruneDrops = 1
	store.marks["gone-1"] = alerter.ForgetMark{Seq: 1, Stream: time.Unix(1, 0)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, p, opener(store)) }()
	time.Sleep(100 * time.Millisecond)
	ts.CreateStream(t)
	ts.WaitConsumer(t, natsauth.ConsumerAlerter)
	ts.WaitConsumer(t, natsauth.ConsumerAlerterHB)

	open, bound := asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN, asmv1.ExposureLevel_EXPOSURE_BOUND
	if _, err := ts.HostJS.Publish(ctx, bus.Subject(host, bus.KindHeartbeat), marshal(t, &asmv1.Heartbeat{HostId: host})); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.HostJS.Publish(ctx, bus.Subject(host, bus.KindExposureChanged), marshal(t, exposure(443, open, bound, ""))); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if pg := store.pages(); len(pg) == 1 && pg[0].delivered && posts.Load() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("page not delivered: %+v, %d posts", store.pages(), posts.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || exitCode(err) != 0 {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	if !store.closed || store.afterClose != 0 {
		t.Fatalf("store closed %v, %d calls after close", store.closed, store.afterClose)
	}
}

// Cancelled while waiting for the stream: a clean stop.
func TestRunShutdownWhileWaitingForStream(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORTWARDEN_ALERTER_DSN", fakeDSN)
	ts := testnats.Start(t)
	store := newFakeStore()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := run(ctx, configFile(t, Config{NATS: natsConfig(ts)}), opener(store)); !errors.Is(err, context.DeadlineExceeded) || !store.closed {
		t.Fatalf("%v, closed %v", err, store.closed)
	}
}

func startChild(t *testing.T, config, want string) (*exec.Cmd, chan struct{}) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "PW_TEST_HELPER=1", "PW_TEST_CONFIG="+config, "PORTWARDEN_ALERTER_DSN="+fakeDSN)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		once := false
		for sc.Scan() {
			if !once && strings.Contains(sc.Text(), want) {
				once = true
				close(seen)
			}
		}
		if !once {
			close(seen)
		}
	}()
	return cmd, seen
}

func waitExit(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatal(err)
		}
		return cmd.ProcessState.ExitCode()
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit")
	}
	return -1
}

// A real SIGTERM stops the alerter cleanly with exit status 0; a bad config exits 1.
func TestMainSignals(t *testing.T) {
	clearEnv(t)
	ts := testnats.Start(t)
	ts.CreateStream(t)
	cmd, seen := startChild(t, configFile(t, Config{NATS: natsConfig(ts)}), "alerter running")
	select {
	case <-seen:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("alerter never ran")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, cmd); code != 0 {
		t.Fatalf("SIGTERM: exit %d, want 0", code)
	}
	cmd, _ = startChild(t, configFile(t, `{"rules": {"page_level": "loud"}}`), "")
	if code := waitExit(t, cmd); code != 1 {
		t.Fatalf("bad config: exit %d, want 1", code)
	}
}
