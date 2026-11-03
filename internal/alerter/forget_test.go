package alerter

import (
	"context"
	"slices"
	"testing"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
)

var (
	streamA = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	streamB = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
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
	if err := e.Forget(ctx, st, "web", ForgetMark{Seq: 42, Stream: streamA, Back: true}); err != nil {
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
	if st.Forgotten["web"] != (ForgetMark{Seq: 42, Stream: streamA}) {
		t.Fatalf("mark %+v (a forget always starts not back)", st.Forgotten["web"])
	}
	// A heartbeat after the forget is no recovery.
	if d, _ := e.Heard(ctx, st, "web", now); d.Alert != nil {
		t.Fatal("a heartbeat after the forget paged host_recovered")
	}
	// A silence noticed for the forgotten host (a race with the forget) does not page …
	tr := liveness.Transition{Host: "web", Silent: true, LastSeen: now, At: now}
	if d, _ := e.Silent(ctx, st, tr); d.Alert != nil || d.Suppressed != "forgotten" {
		t.Fatalf("a forgotten host's silence: %+v", d)
	}
	// … once it came back, its next silence does.
	_ = st.SetBack(ctx, "web")
	if d, _ := e.Silent(ctx, st, tr); d.Alert == nil || d.Alert.Kind != KindHostSilent {
		t.Fatalf("the returned host's silence did not page: %+v", d)
	}
}

// Inside a decision's transaction: leftovers and verdicts before the host is back skip.
func TestEngineForgottenInTheTransaction(t *testing.T) {
	e := engine(t, Rules{})
	st := NewMemState()
	ctx := context.Background()
	if skip, _ := e.Forgotten(ctx, st, "web", 5, true); skip {
		t.Fatal("a host never forgotten skipped")
	}
	_ = st.SetForgotten(ctx, "web", ForgetMark{Seq: 10, Stream: streamA})
	for _, tc := range []struct {
		seq     uint64
		verdict bool
		want    bool
	}{{9, false, true}, {11, false, false}, {11, true, true}, {9, true, true}} {
		if skip, _ := e.Forgotten(ctx, st, "web", tc.seq, tc.verdict); skip != tc.want {
			t.Errorf("seq %d verdict %v: skip %v", tc.seq, tc.verdict, skip)
		}
	}
	_ = st.SetBack(ctx, "web")
	if skip, _ := e.Forgotten(ctx, st, "web", 12, true); skip {
		t.Fatal("a verdict after the host came back skipped")
	}
}

// The exposure rule itself still pages a returned host (the skips live in front of it).
func TestReturnedHostPagesAgain(t *testing.T) {
	e := engine(t, Rules{})
	st := NewMemState()
	ctx := context.Background()
	_ = st.SetForgotten(ctx, "web", ForgetMark{Seq: 10, Stream: streamA, Back: true})
	d, err := e.Exposure(ctx, st, "web", "", exposure(443, 0, asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN, ""), time.Now())
	if err != nil || d.Alert == nil {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestForgottenMarks(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := NewForgotten(map[string]ForgetMark{"old": {Seq: 10, Stream: streamA}})
	if !f.Leftover("old", 9) || f.Leftover("old", 10) || f.Leftover("old", 11) {
		t.Fatal("Leftover with mark 10 from the database")
	}
	if f.Leftover("other", 1) || f.Leftover("old", 0) {
		t.Fatal("a host never forgotten, or a message without a sequence, is never a leftover")
	}
	f.Set("web", 50, streamA, t0)
	f.Set("web", 40, streamA, t0.Add(time.Minute)) // a replayed, older announcement
	if !f.Leftover("web", 49) || f.Leftover("web", 51) {
		t.Fatal("the highest mark of a stream must win")
	}
	if !f.Covers("web", 50) || !f.Covers("old", 10) || f.Covers("web", 51) || f.Covers("never", 1) || f.Covers("web", 0) {
		t.Fatal("Covers")
	}
	if !f.Since("web", t0) || f.Since("web", t0.Add(2*time.Minute)) || f.Since("never", t0) || f.Since("old", t0) {
		t.Fatal("Since")
	}
	// Verdicts are skipped until the host came back, and always before the mark.
	if !f.SkipVerdict("web", 60) || !f.SkipVerdict("web", 49) || f.SkipVerdict("never", 1) {
		t.Fatal("SkipVerdict before the host came back")
	}
	if f.ComingBack("web", 50) || !f.ComingBack("web", 51) {
		t.Fatal("ComingBack")
	}
	f.Back("web")
	if f.ComingBack("web", 52) || f.SkipVerdict("web", 60) || !f.SkipVerdict("web", 49) {
		t.Fatal("after Back")
	}
	// A new stream's announcement replaces the old mark even with a lower sequence.
	f.Set("web", 3, streamB, t0)
	if f.Leftover("web", 4) || !f.Leftover("web", 2) || !f.SkipVerdict("web", 9) {
		t.Fatal("a new stream's mark")
	}
}

// At start only marks of the current stream, at or below its last sequence, are kept.
func TestUsableMarks(t *testing.T) {
	for _, tc := range []struct {
		m    ForgetMark
		want bool
	}{
		{ForgetMark{Seq: 10, Stream: streamB}, true},
		{ForgetMark{Seq: 100, Stream: streamB}, true},
		{ForgetMark{Seq: 101, Stream: streamB}, false}, // past the end: the stream was reset
		{ForgetMark{Seq: 10, Stream: streamA}, false},  // another stream (recreated)
	} {
		if got := Usable(tc.m, streamB, 100); got != tc.want {
			t.Errorf("%+v: %v", tc.m, got)
		}
	}
}
