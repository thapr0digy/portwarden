package alerter

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/backend/liveness"
)

func TestEngineForgetDropsOnlyTheHostsState(t *testing.T) {
	e := engine(t, Rules{PageOnSilence: true})
	st := NewMemState()
	ctx := context.Background()
	now := time.Now()
	for _, k := range []string{"silent:web", "tamper:web/ptraced/self/7", "listener:web/1/tcp/0.0.0.0:22",
		"silent:web-2", "tamper:web-2/ptraced/self/7", "listener:web-2/k", "silent:we", "feed"} {
		st.Paged[k] = now
	}
	st.Probes["web/1/tcp/0.0.0.0:22"] = "confirmed"
	st.Probes["web-2/k"] = "confirmed"
	if err := e.Forget(ctx, st, "web", 42); err != nil {
		t.Fatal(err)
	}
	var left []string
	for k := range st.Paged {
		left = append(left, k)
	}
	slices.Sort(left)
	if want := []string{"feed", "listener:web-2/k", "silent:we", "silent:web-2", "tamper:web-2/ptraced/self/7"}; !slices.Equal(left, want) {
		t.Fatalf("marks left %v, want %v", left, want)
	}
	if _, ok := st.Probes["web/1/tcp/0.0.0.0:22"]; ok || st.Probes["web-2/k"] != "confirmed" {
		t.Fatalf("probes %v", st.Probes)
	}
	if st.Forgotten["web"] != 42 {
		t.Fatalf("watermark %v", st.Forgotten)
	}
	// The host is new afterwards: its next silence pages again, and its next heartbeat
	// is no recovery.
	if d, _ := e.Heard(ctx, st, "web", now); d.Alert != nil {
		t.Fatal("a heartbeat after the forget paged host_recovered")
	}
	if d, _ := e.Silent(ctx, st, liveness.Transition{Host: "web", Silent: true, LastSeen: now, At: now}); d.Alert == nil || d.Alert.Kind != KindHostSilent {
		t.Fatalf("the returned host's silence did not page: %+v", d)
	}
}

func TestForgottenWatermarks(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := NewForgotten(map[string]uint64{"old": 10})
	if !f.Leftover("old", 9) || f.Leftover("old", 10) || f.Leftover("old", 11) {
		t.Fatal("watermark 10 from the database")
	}
	if f.Leftover("other", 1) || f.Leftover("old", 0) {
		t.Fatal("a host never forgotten, or a message without a sequence, is never a leftover")
	}
	f.Set("web", 50, t0)
	f.Set("web", 40, t0.Add(time.Minute)) // a replayed, older announcement
	if !f.Leftover("web", 49) || f.Leftover("web", 51) {
		t.Fatal("the highest watermark must win")
	}
	if !f.Covers("web", 50) || !f.Covers("old", 10) || f.Covers("web", 51) || f.Covers("never", 1) || f.Covers("web", 0) {
		t.Fatal("Covers")
	}
	if !f.Since("web", t0) || f.Since("web", t0.Add(2*time.Minute)) || f.Since("never", t0) {
		t.Fatal("Since")
	}
}
