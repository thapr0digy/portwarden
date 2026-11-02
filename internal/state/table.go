// Package state tracks live listening sockets and collapses them into listeners.
package state

import (
	"slices"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

// Change is a listener-level transition produced by Table.Apply.
type Change struct {
	Kind   model.Kind
	Key    model.ListenerKey
	Procs  []model.Process
	At     time.Time
	Source model.Source
}

// Listener is a currently open listener and the processes holding its sockets.
type Listener struct {
	Key   model.ListenerKey
	Procs []model.Process
}

// Table tracks sockets by cookie and groups them by listener key
// (SO_REUSEPORT puts several sockets on one key). It is not safe for
// concurrent use; callers serialise access.
type Table struct {
	sockets map[uint64]model.Observation
	byKey   map[model.ListenerKey]map[uint64]struct{}
	// coOwners holds the extra processes the baseline found holding a socket that
	// has several (a socket-activated sshd is held by systemd and by sshd).
	coOwners map[uint64][]model.Process
}

// New returns an empty table.
func New() *Table {
	return &Table{
		sockets: make(map[uint64]model.Observation),
		byKey:   make(map[model.ListenerKey]map[uint64]struct{}),

		coOwners: make(map[uint64][]model.Process),
	}
}

// Apply records an observation and returns the listener-level changes it causes.
// A listener opens when its first socket appears and closes when its last goes.
// A Closed observation is matched by cookie alone: the Change carries the Key and
// process stored when the socket opened, since the kernel reports only the cookie.
func (t *Table) Apply(o model.Observation) []Change {
	switch o.Kind {
	case model.Opened:
		return t.open(o)
	case model.Closed:
		return t.close(o)
	}
	return nil
}

func (t *Table) open(o model.Observation) []Change {
	if stored, live := t.sockets[o.Cookie]; live {
		// A baseline taken in a race can miss the owner that the kernel event carries.
		if stored.Proc.IsZero() {
			stored.Proc = o.Proc
			t.sockets[o.Cookie] = stored
		} else if o.Source == model.SourceBaseline && stored.Source == model.SourceBaseline && !o.Proc.IsZero() {
			// The baseline reports one observation per holder of a socket.
			t.coOwners[o.Cookie] = append(t.coOwners[o.Cookie], o.Proc)
		}
		return nil
	}
	t.sockets[o.Cookie] = o
	cookies := t.byKey[o.Key]
	if cookies == nil {
		cookies = make(map[uint64]struct{})
		t.byKey[o.Key] = cookies
	}
	cookies[o.Cookie] = struct{}{}
	if len(cookies) > 1 {
		return nil
	}
	return []Change{{Kind: model.Opened, Key: o.Key, Procs: procsOf(o), At: o.At, Source: o.Source}}
}

func (t *Table) close(o model.Observation) []Change {
	stored, live := t.sockets[o.Cookie]
	if !live {
		return nil
	}
	delete(t.sockets, o.Cookie)
	delete(t.coOwners, o.Cookie)
	cookies := t.byKey[stored.Key]
	delete(cookies, o.Cookie)
	if len(cookies) > 0 {
		return nil
	}
	delete(t.byKey, stored.Key)
	return []Change{{Kind: model.Closed, Key: stored.Key, Procs: procsOf(stored), At: o.At, Source: o.Source}}
}

// Snapshot returns the open listeners sorted by key. Each listener's processes
// are deduplicated by PID and sorted by PID; kernel-owned listeners get an
// empty, non-nil slice.
func (t *Table) Snapshot() []Listener {
	out := make([]Listener, 0, len(t.byKey))
	for key, cookies := range t.byKey {
		byPID := make(map[uint32]model.Process)
		for cookie := range cookies {
			if p := t.sockets[cookie].Proc; !p.IsZero() {
				byPID[p.PID] = p
			}
			for _, p := range t.coOwners[cookie] {
				byPID[p.PID] = p
			}
		}
		procs := make([]model.Process, 0, len(byPID))
		for _, p := range byPID {
			procs = append(procs, p)
		}
		slices.SortFunc(procs, func(a, b model.Process) int { return int(a.PID) - int(b.PID) })
		out = append(out, Listener{Key: key, Procs: procs})
	}
	slices.SortFunc(out, func(a, b Listener) int {
		switch ka, kb := a.Key.String(), b.Key.String(); {
		case ka < kb:
			return -1
		case ka > kb:
			return 1
		}
		return 0
	})
	return out
}

func procsOf(o model.Observation) []model.Process {
	if o.Proc.IsZero() {
		return []model.Process{}
	}
	return []model.Process{o.Proc}
}
