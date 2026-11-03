package alerter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
)

func engine(t *testing.T, r Rules) *Engine { //nolint:unparam
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	n := 0
	return NewEngine(r, func() string { n++; return "a" + strconv.Itoa(n) })
}

func exposure(port uint32, prev, lvl asmv1.ExposureLevel, origin string) *asmv1.ExposureEvent {
	ev := &asmv1.ExposureEvent{
		Listener: &asmv1.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: port, Key: "1/tcp/0.0.0.0:" + strconv.Itoa(int(port))},
		Exposure: &asmv1.Exposure{Level: lvl, Evidence: []string{"bind:any"}}, Origin: origin,
		Host: &asmv1.HostInfo{PublicIps: []*asmv1.PublicIP{{Ip: "54.1.2.3", Dir: "in"}, {Ip: "198.51.100.4", Dir: "out"}}},
	}
	if prev != 0 {
		ev.Previous = &asmv1.Exposure{Level: prev}
	}
	return ev
}

const (
	bound     = asmv1.ExposureLevel_EXPOSURE_BOUND
	open      = asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN
	cloudOpen = asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN
	local     = asmv1.ExposureLevel_EXPOSURE_LOCAL
)

var bg = context.Background()

func mustD(t *testing.T) func(Decision, error) Decision {
	return func(d Decision, err error) Decision {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
}

func confirmation(port uint32, result string) *asmv1.ExposureConfirmation {
	return &asmv1.ExposureConfirmation{Result: result, Listener: exposure(port, 0, 0, "").Listener, Target: "10.0.0.1:" + strconv.Itoa(int(port))}
}

func TestNewlyReachableOncePerListener(t *testing.T) {
	e, st, d := engine(t, Rules{PageOnConfirmed: true, DedupeWindow: time.Hour}), NewMemState(), mustD(t)
	now := time.Now()
	r := d(e.Exposure(bg, st, "h1", "", exposure(8092, 0, open, ""), now))
	if r.Alert == nil || r.Alert.Kind != KindNewlyReachable || r.Alert.Level != "host_firewall_open" || r.Alert.PreviousLevel != "" ||
		len(r.Alert.PublicIPs) != 1 || r.Alert.Origin != "agent" || len(st.Queue) != 1 {
		t.Fatalf("opened at level 2: %+v", r)
	}
	// The verifier confirms it a moment later: same listener, same window -> suppressed.
	if c := d(e.Confirmation(bg, st, "h1", confirmation(8092, "confirmed"), now.Add(time.Second))); c.Alert != nil || c.Suppressed != "dedupe" {
		t.Fatalf("confirmation: %+v", c)
	}
	if r := d(e.Exposure(bg, st, "h1", "cloud", exposure(8092, open, cloudOpen, ""), now)); r.Alert != nil || r.Suppressed != "" {
		t.Fatalf("2->3: %+v", r)
	}
	for _, ev := range []*asmv1.ExposureEvent{exposure(1, 0, bound, ""), exposure(2, 0, local, ""), exposure(3, open, bound, "")} {
		if r := d(e.Exposure(bg, st, "h1", "", ev, now)); r.Alert != nil {
			t.Fatalf("paged %+v", ev)
		}
	}
	if r := d(e.Exposure(bg, st, "h1", "cloud", exposure(8080, bound, cloudOpen, ""), now)); r.Alert == nil || r.Alert.Origin != "cloud" {
		t.Fatalf("lb path: %+v", r)
	}
	if r := d(e.Exposure(bg, st, "h1", "", exposure(8092, bound, open, ""), now.Add(2*time.Hour))); r.Alert == nil {
		t.Fatal("no page after the dedupe window")
	}
}

// A confirmation pages only on a transition to confirmed: a reprobe that keeps the
// verdict never pages, even after the dedupe window or a restart (the state is durable).
func TestConfirmedOnlyOnTransition(t *testing.T) {
	e, st, d := engine(t, Rules{PageOnConfirmed: true, DedupeWindow: time.Hour}), NewMemState(), mustD(t)
	now := time.Now()
	if r := d(e.Confirmation(bg, st, "h", confirmation(53, "no_response"), now)); r.Alert != nil {
		t.Fatal("no_response paged")
	}
	if r := d(e.Confirmation(bg, st, "h", confirmation(53, "confirmed"), now)); r.Alert == nil || r.Alert.Kind != KindConfirmed {
		t.Fatalf("first confirmed: %+v", r)
	}
	later := now.Add(48 * time.Hour)
	e2 := engine(t, Rules{PageOnConfirmed: true, DedupeWindow: time.Hour}) // a restarted alerter, same state
	if r := d(e2.Confirmation(bg, st, "h", confirmation(53, "confirmed"), later)); r.Alert != nil || r.Suppressed != "not a transition" {
		t.Fatalf("reprobe paged: %+v", r)
	}
	d(e2.Confirmation(bg, st, "h", confirmation(53, "unreachable"), later))
	if r := d(e2.Confirmation(bg, st, "h", confirmation(53, "confirmed"), later.Add(2*time.Hour))); r.Alert == nil {
		t.Fatal("unreachable -> confirmed did not page")
	}
}

func TestIgnore(t *testing.T) {
	e, st, d := engine(t, Rules{PageOnConfirmed: true, Ignore: []Ignore{{Proto: "tcp", Port: 22}}}), NewMemState(), mustD(t)
	if r := d(e.Exposure(bg, st, "h", "", exposure(22, 0, open, ""), time.Now())); r.Alert != nil || r.Suppressed != "ignore" {
		t.Fatalf("ignored port: %+v", r)
	}
	if err := (&Rules{PageLevel: "huge"}).Validate(); err == nil {
		t.Fatal("bad page_level accepted")
	}
}

func TestSilenceAcrossRestarts(t *testing.T) {
	e, st, d := engine(t, Rules{PageOnSilence: true}), NewMemState(), mustD(t)
	now := time.Now()
	if r := d(e.Heard(bg, st, "h", now)); r.Alert != nil {
		t.Fatal("recovery without a silence page")
	}
	r := d(e.Silent(bg, st, liveness.Transition{Host: "h", Silent: true, LastSeen: now.Add(-2 * time.Minute), At: now}))
	if r.Alert == nil || r.Alert.Kind != KindHostSilent || r.Alert.LastHeartbeat == nil {
		t.Fatalf("%+v", r)
	}
	e2 := engine(t, Rules{PageOnSilence: true}) // restarted: the host is still silent
	if r := d(e2.Silent(bg, st, liveness.Transition{Host: "h", Silent: true, At: now})); r.Alert != nil {
		t.Fatal("silence paged twice")
	}
	if r := d(e2.Heard(bg, st, "h", now)); r.Alert == nil || r.Alert.Kind != KindHostRecovered {
		t.Fatalf("recovery: %+v", r)
	}
	if r := d(e2.Feed(bg, st, liveness.FeedStalled, now)); r.Alert == nil || r.Alert.Kind != KindFeedStalled {
		t.Fatalf("feed: %+v", r)
	}
}

func TestCheckURLAndFreshness(t *testing.T) {
	if CheckURL("http://x/", false) == nil || CheckURL("https://x/", false) != nil || CheckURL("http://x/", true) != nil || CheckURL("nope", true) == nil {
		t.Fatal("CheckURL")
	}
	secret, body, now := []byte("s"), []byte("{}"), time.Now()
	sig := Sign(secret, now.Unix(), body)
	if !VerifyFresh(secret, now.Unix(), body, sig, now, time.Minute) || VerifyFresh(secret, now.Unix(), body, sig, now.Add(time.Hour), time.Minute) {
		t.Fatal("VerifyFresh")
	}
}

func TestWebhookSignsAndRetries(t *testing.T) {
	secret := []byte("test-secret-generated-here")
	var calls atomic.Int32
	var got Alert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		ts, _ := strconv.ParseInt(r.Header.Get(HeaderTimestamp), 10, 64)
		if !Verify(secret, ts, body, r.Header.Get(HeaderSignature)) || r.Header.Get("User-Agent") != userAgent {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	w := NewWebhook(srv.URL, secret, time.Second, 5)
	w.sleep = func(context.Context, time.Duration) error { return nil }
	if err := w.Send(context.Background(), &Alert{ID: "a1", Kind: KindHostSilent, Host: "h"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || got.ID != "a1" {
		t.Fatalf("calls %d got %+v", calls.Load(), got)
	}
	// A 4xx is permanent: one attempt.
	calls.Store(0)
	bad := NewWebhook(srv.URL, []byte("wrong"), time.Second, 5)
	bad.sleep = w.sleep
	if err := bad.Send(context.Background(), &Alert{ID: "a2"}); err == nil || calls.Load() != 1 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}
	// Bounded: a server that always fails is tried MaxAttempts times.
	var fails atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fails.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer down.Close()
	dw := NewWebhook(down.URL, secret, time.Second, 4)
	dw.sleep = w.sleep
	if err := dw.Send(context.Background(), &Alert{ID: "a3"}); err == nil || fails.Load() != 4 {
		t.Fatalf("err %v attempts %d", err, fails.Load())
	}
	// Redirects are not followed.
	redir := httptest.NewServer(http.RedirectHandler(srv.URL, http.StatusFound))
	defer redir.Close()
	calls.Store(0)
	rw := NewWebhook(redir.URL, secret, time.Second, 2)
	rw.sleep = w.sleep
	if err := rw.Send(context.Background(), &Alert{ID: "a4"}); err == nil || calls.Load() != 0 {
		t.Fatalf("redirect followed: err %v calls %d", err, calls.Load())
	}
}
