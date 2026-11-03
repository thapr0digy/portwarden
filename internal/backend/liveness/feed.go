package liveness

import "time"

// FeedEvent is a change in the backend's own feed.
type FeedEvent int

const (
	FeedNoChange FeedEvent = iota
	// FeedStalled: the backend itself stopped receiving (NATS down, or nothing from any
	// host for After). Host silence is not judged meanwhile.
	FeedStalled
	// FeedRecovered: messages flow again; host silence is judged again after one more
	// After (grace), so hosts have time to be heard.
	FeedRecovered
)

// Feed watches the backend's own view of the fleet, on the backend's clock. When the
// feed stalls, every host looks silent; the caller raises one "feed stalled" alert instead
// of one per host and stops judging hosts until the feed recovers plus a grace period.
// Not safe for concurrent use.
type Feed struct {
	After        time.Duration
	lastAny      time.Time
	disconnected bool
	stalled      bool
	graceUntil   time.Time
}

// NewFeed starts with a grace period: right after start (or a consumer replay) hosts are
// not judged for After.
func NewFeed(after time.Duration, now time.Time) *Feed {
	return &Feed{After: after, lastAny: now, graceUntil: now.Add(after)}
}

// Received records a message from any host, at the local receive time.
func (f *Feed) Received(now time.Time) {
	if now.After(f.lastAny) {
		f.lastAny = now
	}
}

// SetConnected records the NATS connection state.
func (f *Feed) SetConnected(connected bool, now time.Time) {
	f.disconnected = !connected
	if connected {
		// A reconnect is a fresh start for the timer: the backlog follows.
		f.Received(now)
	}
}

// Check returns the feed transition (if any) and whether host silence may be judged now.
func (f *Feed) Check(now time.Time) (FeedEvent, bool) {
	stalled := f.disconnected || now.Sub(f.lastAny) > f.After
	ev := FeedNoChange
	switch {
	case stalled && !f.stalled:
		f.stalled, ev = true, FeedStalled
	case !stalled && f.stalled:
		f.stalled, ev = false, FeedRecovered
		f.graceUntil = now.Add(f.After)
	}
	return ev, !f.stalled && !now.Before(f.graceUntil)
}

// Stalled reports whether the feed is stalled.
func (f *Feed) Stalled() bool { return f.stalled }
