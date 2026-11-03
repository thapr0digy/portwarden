package liveness

import (
	"testing"
	"time"
)

func TestSilentThenRecovered(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	tr := New(90 * time.Second)
	if r := tr.Seen("a", t0, t0); r != nil {
		t.Fatal("first heartbeat is not a recovery")
	}
	tr.Seen("b", t0.Add(60*time.Second), t0.Add(60*time.Second))
	if got := tr.Check(t0.Add(90 * time.Second)); len(got) != 0 {
		t.Fatalf("exactly at the limit is not silent: %+v", got)
	}
	got := tr.Check(t0.Add(91 * time.Second))
	if len(got) != 1 || got[0].Host != "a" || !got[0].Silent || !got[0].LastSeen.Equal(t0) {
		t.Fatalf("got %+v", got)
	}
	if again := tr.Check(t0.Add(200 * time.Second)); len(again) != 1 || again[0].Host != "b" {
		t.Fatalf("a must be reported once, b now: %+v", again)
	}
	if r := tr.Seen("a", t0, t0.Add(300*time.Second)); r != nil {
		t.Fatal("a replayed old heartbeat must not recover the host")
	}
	r := tr.Seen("a", t0.Add(299*time.Second), t0.Add(300*time.Second))
	if r == nil || r.Silent || r.Host != "a" {
		t.Fatalf("recovery: %+v", r)
	}
	if _, silent, _, _ := tr.State("a"); silent {
		t.Fatal("a still silent")
	}
}

func TestStaleHeartbeatDoesNotRecover(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	tr := New(time.Minute)
	tr.Seen("a", t0, t0)
	tr.Check(t0.Add(2 * time.Minute))
	// A spooled heartbeat from just after t0, delivered late, is newer but itself stale.
	if r := tr.Seen("a", t0.Add(10*time.Second), t0.Add(3*time.Minute)); r != nil {
		t.Fatalf("a stale heartbeat must not end the silence: %+v", r)
	}
}

func TestForget(t *testing.T) {
	t0 := time.Now()
	tr := New(time.Second)
	tr.Seen("a", t0, t0)
	tr.Forget("a")
	if got := tr.Check(t0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("forgotten host reported: %+v", got)
	}
}
