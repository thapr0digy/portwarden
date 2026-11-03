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

func engine(t *testing.T, r Rules) *Engine {
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
	bound = asmv1.ExposureLevel_EXPOSURE_BOUND
	open  = asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN
	cloud = asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN
	local = asmv1.ExposureLevel_EXPOSURE_LOCAL
)

func TestNewlyReachableOncePerListener(t *testing.T) {
	e := engine(t, Rules{PageOnConfirmed: true, DedupeWindow: time.Hour})
	now := time.Now()
	d := e.Exposure("h1", exposure(8092, 0, open, ""), now)
	if d.Alert == nil || d.Alert.Kind != KindNewlyReachable || d.Alert.Level != "host_firewall_open" || d.Alert.PreviousLevel != "" ||
		len(d.Alert.PublicIPs) != 1 || d.Alert.Origin != "agent" {
		t.Fatalf("opened at level 2: %+v", d)
	}
	// The verifier confirms it a moment later: same listener, same window -> suppressed.
	c := e.Confirmation("h1", &asmv1.ExposureConfirmation{Result: "confirmed", Listener: exposure(8092, 0, 0, "").Listener, Target: "10.0.0.1:8092"}, now.Add(time.Second))
	if c.Alert != nil || c.Suppressed != "dedupe" {
		t.Fatalf("confirmation: %+v", c)
	}
	// The cloud's level 3 on top of level 2 is not newly reachable.
	if d := e.Exposure("h1", exposure(8092, open, cloud, "cloud"), now); d.Alert != nil || d.Suppressed != "" {
		t.Fatalf("2->3: %+v", d)
	}
	// Not reaching the threshold, or already above it.
	for _, ev := range []*asmv1.ExposureEvent{exposure(1, 0, bound, ""), exposure(2, 0, local, ""), exposure(3, open, bound, "")} {
		if d := e.Exposure("h1", ev, now); d.Alert != nil {
			t.Fatalf("paged %+v", ev)
		}
	}
	// An LB path at level 1 -> 3 from the cloud pages.
	if d := e.Exposure("h1", exposure(8080, bound, cloud, "cloud"), now); d.Alert == nil || d.Alert.Origin != "cloud" {
		t.Fatalf("lb path: %+v", d)
	}
	// After the window the same listener pages again.
	if d := e.Exposure("h1", exposure(8092, bound, open, ""), now.Add(2*time.Hour)); d.Alert == nil {
		t.Fatal("no page after the dedupe window")
	}
	e.Expire(now.Add(5 * time.Hour))
	if len(e.paged) != 0 {
		t.Fatalf("expire left %v", e.paged)
	}
}

func TestConfirmationAndIgnore(t *testing.T) {
	e := engine(t, Rules{PageOnConfirmed: true, Ignore: []Ignore{{Proto: "tcp", Port: 22}}})
	l := &asmv1.Listener{Proto: "udp", Addr: "0.0.0.0", Port: 53, Key: "k53"}
	if d := e.Confirmation("h", &asmv1.ExposureConfirmation{Result: "no_response", Listener: l}, time.Now()); d.Alert != nil {
		t.Fatal("no_response paged")
	}
	d := e.Confirmation("h", &asmv1.ExposureConfirmation{Result: "confirmed", Listener: l, Probe: "dns", Target: "1.2.3.4:53"}, time.Now())
	if d.Alert == nil || d.Alert.Kind != KindConfirmed || d.Alert.Probe.Probe != "dns" {
		t.Fatalf("%+v", d)
	}
	if d := e.Exposure("h", exposure(22, 0, open, ""), time.Now()); d.Alert != nil || d.Suppressed != "ignore" {
		t.Fatalf("ignored port: %+v", d)
	}
	if err := (&Rules{PageLevel: "huge"}).Validate(); err == nil {
		t.Fatal("bad page_level accepted")
	}
}

func TestSilence(t *testing.T) {
	e := engine(t, Rules{PageOnSilence: true})
	now := time.Now()
	if d := e.Liveness(liveness.Transition{Host: "h", Silent: false, At: now}); d.Alert != nil {
		t.Fatal("recovery without a silence page")
	}
	d := e.Liveness(liveness.Transition{Host: "h", Silent: true, LastSeen: now.Add(-2 * time.Minute), At: now})
	if d.Alert == nil || d.Alert.Kind != KindHostSilent || d.Alert.LastHeartbeat == nil {
		t.Fatalf("%+v", d)
	}
	if d := e.Liveness(liveness.Transition{Host: "h", Silent: true, At: now}); d.Alert != nil {
		t.Fatal("silence paged twice")
	}
	if d := e.Liveness(liveness.Transition{Host: "h", Silent: false, At: now}); d.Alert == nil || d.Alert.Kind != KindHostRecovered {
		t.Fatalf("recovery: %+v", d)
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
