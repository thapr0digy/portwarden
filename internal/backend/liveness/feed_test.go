package liveness

import (
	"testing"
	"time"
)

// A NATS outage of 2 x After gives one stall and one recovery, and no host is judged
// until one After after the recovery.
func TestFeedStallAndGrace(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	after := 90 * time.Second
	f := NewFeed(after, t0)
	tr := New(after)
	tr.Seen("a", t0, t0)
	tr.Seen("b", t0, t0)
	if _, judge := f.Check(t0.Add(10 * time.Second)); judge {
		t.Fatal("judged inside the start-up grace")
	}
	f.Received(t0.Add(80 * time.Second))
	tr.Seen("a", t0.Add(80*time.Second), t0.Add(80*time.Second))
	tr.Seen("b", t0.Add(80*time.Second), t0.Add(80*time.Second))
	if ev, judge := f.Check(t0.Add(95 * time.Second)); ev != FeedNoChange || !judge {
		t.Fatalf("healthy: %v %v", ev, judge)
	}
	down := t0.Add(100 * time.Second)
	f.SetConnected(false, down)
	stalls, pages := 0, 0
	for now := down; now.Before(down.Add(2 * after)); now = now.Add(5 * time.Second) {
		ev, judge := f.Check(now)
		if ev == FeedStalled {
			stalls++
		}
		if judge {
			pages += len(tr.Check(now))
		}
	}
	up := down.Add(2 * after)
	f.SetConnected(true, up)
	if ev, judge := f.Check(up); ev != FeedRecovered || judge {
		t.Fatalf("recovery: %v %v", ev, judge)
	}
	// Host a comes back in the grace period, b does not.
	f.Received(up.Add(time.Second))
	tr.Seen("a", up.Add(time.Second), up.Add(time.Second))
	if _, judge := f.Check(up.Add(after / 2)); judge {
		t.Fatal("judged inside the grace after recovery")
	}
	f.Received(up.Add(after))
	_, judge := f.Check(up.Add(after + time.Second))
	if !judge {
		t.Fatal("not judged after the grace")
	}
	silent := tr.Check(up.Add(after + time.Second))
	if stalls != 1 || pages != 0 || len(silent) != 1 || silent[0].Host != "b" {
		t.Fatalf("stalls %d host pages during outage %d silent after %+v", stalls, pages, silent)
	}
	// Nothing from any host for After is a stall too.
	if ev, _ := f.Check(up.Add(3 * after)); ev != FeedStalled {
		t.Fatalf("no traffic: %v", ev)
	}
}
