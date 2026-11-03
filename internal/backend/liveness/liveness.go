// Package liveness turns heartbeats into "host silent" and "host recovered" transitions
// (design §6: silence is a signal). It is pure: callers feed it heartbeat times and ask
// it, on their own tick, which hosts went silent.
package liveness

import (
	"sort"
	"time"
)

// Transition is a host going silent or coming back.
type Transition struct {
	Host   string
	Silent bool
	// LastSeen is the host's last heartbeat; At is when the transition was noticed.
	LastSeen, At time.Time
}

type hostState struct {
	lastSeen    time.Time
	silent      bool
	silentSince time.Time
}

// Tracker remembers each host's last heartbeat. A host is silent once now - lastSeen
// exceeds After; it recovers on the next heartbeat newer than the one it went silent on.
// Not safe for concurrent use.
type Tracker struct {
	After time.Duration
	hosts map[string]*hostState
}

// New returns a tracker that calls a host silent after `after` without a heartbeat.
func New(after time.Duration) *Tracker {
	return &Tracker{After: after, hosts: map[string]*hostState{}}
}

// Seen records a heartbeat at `at` (the stream's time for it). It returns a recovered
// transition when the host was silent and this heartbeat is newer than its last one.
// An older heartbeat (redelivery, replay) changes nothing.
func (t *Tracker) Seen(host string, at, now time.Time) *Transition {
	h, ok := t.hosts[host]
	if !ok {
		t.hosts[host] = &hostState{lastSeen: at}
		return nil
	}
	if !at.After(h.lastSeen) {
		return nil
	}
	h.lastSeen = at
	if h.silent && now.Sub(at) <= t.After {
		h.silent, h.silentSince = false, time.Time{}
		return &Transition{Host: host, Silent: false, LastSeen: at, At: now}
	}
	return nil
}

// Check returns the hosts that became silent since the last call, sorted by host.
func (t *Tracker) Check(now time.Time) []Transition {
	var out []Transition
	for host, h := range t.hosts {
		if !h.silent && now.Sub(h.lastSeen) > t.After {
			h.silent, h.silentSince = true, now
			out = append(out, Transition{Host: host, Silent: true, LastSeen: h.lastSeen, At: now})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// State reports a host's last heartbeat and whether it is silent (and since when).
func (t *Tracker) State(host string) (lastSeen time.Time, silent bool, since time.Time, known bool) {
	h, ok := t.hosts[host]
	if !ok {
		return time.Time{}, false, time.Time{}, false
	}
	return h.lastSeen, h.silent, h.silentSince, true
}

// Forget drops a host (decommissioned): it is never reported silent again.
func (t *Tracker) Forget(host string) { delete(t.hosts, host) }
