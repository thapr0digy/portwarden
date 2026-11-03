// Package state tracks live listening sockets and collapses them into listeners.
package state

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

// Change is a listener-level transition produced by Table.Apply, Expire or
// Reconcile. PrevProcs is set on OwnerChanged only. The table leaves Exposure empty;
// the agent fills it in (on Closed: the listener's last exposure).
type Change struct {
	Kind      model.Kind
	Key       model.ListenerKey
	Procs     []model.Process
	PrevProcs []model.Process
	At        time.Time
	Source    model.Source
	Exposure  model.Exposure
	// BehindProxy lists the proxy routes ending at the listener; the agent fills it in.
	BehindProxy []model.ProxyRef
}

// Listener is a currently open listener and the processes holding its sockets. The
// table leaves Exposure empty; the agent fills it in.
type Listener struct {
	Key   model.ListenerKey
	Procs []model.Process
	// V6Only is the sockets' IPV6_V6ONLY flag: On when every socket of the key is
	// v6-only, Off when any is dual-stack, otherwise Unknown.
	V6Only   model.V6Only
	Exposure model.Exposure
	// BehindProxy lists the proxy routes ending at the listener; the agent fills it in.
	BehindProxy []model.ProxyRef
}

// ExposureChange is a listener judged for the first time (Previous is zero) or whose
// exposure level changed. Trigger says what made the agent judge again: opened,
// listener (another listener changed, e.g. a port mapping's proxy), firewall,
// interfaces or recheck.
type ExposureChange struct {
	Key      model.ListenerKey
	Procs    []model.Process
	Exposure model.Exposure
	Previous model.Exposure
	Trigger  string
	At       time.Time
}

// pendingClose is a listener whose last socket closed and whose Closed change
// waits out the close grace, so a quick restart reads as an owner change.
type pendingClose struct {
	procs    []model.Process
	at       time.Time
	source   model.Source
	deadline time.Time
}

// Table tracks sockets by cookie and groups them by listener key
// (SO_REUSEPORT puts several sockets on one key). It is not safe for
// concurrent use; callers serialise access.
type Table struct {
	closeGrace time.Duration
	sockets    map[uint64]model.Observation
	byKey      map[model.ListenerKey]map[uint64]struct{}
	// coOwners holds the extra processes the baseline found holding a socket that
	// has several (a socket-activated sshd is held by systemd and by sshd).
	coOwners map[uint64][]model.Process
	pending  map[model.ListenerKey]pendingClose
}

// New returns an empty table. A listener that loses its last socket closes
// after closeGrace; 0 closes it at once.
func New(closeGrace time.Duration) *Table {
	return &Table{
		closeGrace: closeGrace,
		sockets:    make(map[uint64]model.Observation),
		byKey:      make(map[model.ListenerKey]map[uint64]struct{}),
		coOwners:   make(map[uint64][]model.Process),
		pending:    make(map[model.ListenerKey]pendingClose),
	}
}

// Apply records an observation and returns the listener-level changes it causes.
// A listener opens when its first socket appears and closes when its last goes
// (after the close grace); a change to the set of processes holding an open
// listener yields OwnerChanged (see sameProcs). A Closed observation is matched by cookie alone:
// the Change carries the Key and process stored when the socket opened, since the
// kernel reports only the cookie.
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
		// The socket stays under its stored key even if re-observed under another.
		before := t.procsOf(stored.Key)
		// A baseline taken in a race can miss the owner that the kernel event carries.
		if stored.V6Only == model.V6OnlyUnknown && o.V6Only != model.V6OnlyUnknown {
			stored.V6Only = o.V6Only
			t.sockets[o.Cookie] = stored
		}
		if stored.Proc.IsZero() {
			stored.Proc = o.Proc
			t.sockets[o.Cookie] = stored
		} else if o.Source == model.SourceBaseline && stored.Source == model.SourceBaseline && !o.Proc.IsZero() {
			// The baseline reports one observation per holder of a socket.
			t.coOwners[o.Cookie] = append(t.coOwners[o.Cookie], o.Proc)
		}
		return t.ownerDelta(stored.Key, before, o.At, o.Source)
	}
	before := t.procsOf(o.Key)
	t.addSocket(o)
	if len(t.byKey[o.Key]) > 1 {
		return t.ownerDelta(o.Key, before, o.At, o.Source)
	}
	return t.listenerOpened(o.Key, o.At, o.Source)
}

// listenerOpened handles a listener's first socket: a fresh Opened, or, when
// the listener was waiting out its close grace, the cancelled close.
func (t *Table) listenerOpened(k model.ListenerKey, at time.Time, src model.Source) []Change {
	procs := t.procsOf(k)
	p, wasPending := t.pending[k]
	if !wasPending {
		return []Change{{Kind: model.Opened, Key: k, Procs: procs, At: at, Source: src}}
	}
	delete(t.pending, k)
	if sameProcs(p.procs, procs) {
		return nil
	}
	return []Change{{Kind: model.OwnerChanged, Key: k, Procs: procs, PrevProcs: p.procs, At: at, Source: src}}
}

// ownerDelta returns an OwnerChanged if the open listener's process set differs
// from before.
func (t *Table) ownerDelta(k model.ListenerKey, before []model.Process, at time.Time, src model.Source) []Change {
	after := t.procsOf(k)
	if sameProcs(before, after) {
		return nil
	}
	return []Change{{Kind: model.OwnerChanged, Key: k, Procs: after, PrevProcs: before, At: at, Source: src}}
}

func (t *Table) addSocket(o model.Observation) {
	t.sockets[o.Cookie] = o
	cookies := t.byKey[o.Key]
	if cookies == nil {
		cookies = make(map[uint64]struct{})
		t.byKey[o.Key] = cookies
	}
	cookies[o.Cookie] = struct{}{}
}

// removeSocket drops a socket and reports its key and whether the listener
// still has other sockets.
func (t *Table) removeSocket(cookie uint64) (key model.ListenerKey, listenerGone bool) {
	stored := t.sockets[cookie]
	delete(t.sockets, cookie)
	delete(t.coOwners, cookie)
	cookies := t.byKey[stored.Key]
	delete(cookies, cookie)
	if len(cookies) > 0 {
		return stored.Key, false
	}
	delete(t.byKey, stored.Key)
	return stored.Key, true
}

func (t *Table) close(o model.Observation) []Change {
	stored, live := t.sockets[o.Cookie]
	if !live {
		return nil
	}
	before := t.procsOf(stored.Key)
	key, gone := t.removeSocket(o.Cookie)
	if !gone {
		return t.ownerDelta(key, before, o.At, o.Source)
	}
	if t.closeGrace <= 0 {
		return []Change{{Kind: model.Closed, Key: key, Procs: before, At: o.At, Source: o.Source}}
	}
	t.pending[key] = pendingClose{procs: before, at: o.At, source: o.Source, deadline: o.At.Add(t.closeGrace)}
	return nil
}

// Expire returns a Closed change for every pending listener whose grace has run
// out at now, sorted by key. Each carries the processes the listener had and the
// time its last socket closed.
func (t *Table) Expire(now time.Time) []Change {
	var out []Change
	for key, p := range t.pending {
		if p.deadline.After(now) {
			continue
		}
		delete(t.pending, key)
		out = append(out, Change{Kind: model.Closed, Key: key, Procs: p.procs, At: p.at, Source: p.source})
	}
	sortChanges(out)
	return out
}

// NextDeadline returns the earliest pending close deadline, if any.
func (t *Table) NextDeadline() (time.Time, bool) {
	var next time.Time
	found := false
	for _, p := range t.pending {
		if !found || p.deadline.Before(next) {
			next, found = p.deadline, true
		}
	}
	return next, found
}

// Reconcile compares the table with a fresh dump of the kernel's listening
// sockets, ignoring every cookie in touched (sockets the live stream has
// reported since the dump began). A cookie missing from the dump is closed at
// once (no grace), one missing from the table is opened, and a live cookie's
// holders are replaced by the dump's. Listener-level changes carry
// SourceReconcile and At = at, sorted by key.
func (t *Table) Reconcile(dump []model.Observation, touched map[uint64]struct{}, at time.Time) []Change {
	dumped := make(map[uint64][]model.Observation)
	var order []uint64
	for _, o := range dump {
		if _, skip := touched[o.Cookie]; skip {
			continue
		}
		if _, seen := dumped[o.Cookie]; !seen {
			order = append(order, o.Cookie)
		}
		dumped[o.Cookie] = append(dumped[o.Cookie], o)
	}

	// before records each affected listener's process set the first time a
	// mutation touches it.
	before := make(map[model.ListenerKey][]model.Process)
	wasOpen := make(map[model.ListenerKey]bool)
	note := func(k model.ListenerKey) {
		if _, ok := wasOpen[k]; ok {
			return
		}
		_, open := t.byKey[k]
		wasOpen[k] = open
		before[k] = t.procsOf(k)
	}

	var stale []uint64
	for cookie := range t.sockets {
		if _, skip := touched[cookie]; skip {
			continue
		}
		if _, ok := dumped[cookie]; !ok {
			stale = append(stale, cookie)
		}
	}
	for _, cookie := range stale {
		note(t.sockets[cookie].Key)
		t.removeSocket(cookie)
	}
	for _, cookie := range order {
		holders := dumped[cookie]
		if stored, live := t.sockets[cookie]; live {
			note(stored.Key)
			stored.Proc = holders[0].Proc
			t.sockets[cookie] = stored
			t.coOwners[cookie] = nil
			for _, h := range holders[1:] {
				if !h.Proc.IsZero() {
					t.coOwners[cookie] = append(t.coOwners[cookie], h.Proc)
				}
			}
			continue
		}
		first := holders[0]
		note(first.Key)
		t.addSocket(first)
		for _, h := range holders[1:] {
			if !h.Proc.IsZero() {
				t.coOwners[cookie] = append(t.coOwners[cookie], h.Proc)
			}
		}
	}

	var out []Change
	for key, was := range wasOpen {
		_, now := t.byKey[key]
		switch {
		case was && now:
			out = append(out, t.ownerDelta(key, before[key], at, model.SourceReconcile)...)
		case was:
			delete(t.pending, key)
			out = append(out, Change{Kind: model.Closed, Key: key, Procs: before[key], At: at, Source: model.SourceReconcile})
		case now:
			out = append(out, t.listenerOpened(key, at, model.SourceReconcile)...)
		}
	}
	sortChanges(out)
	return out
}

func sortChanges(cs []Change) {
	slices.SortFunc(cs, func(a, b Change) int { return strings.Compare(a.Key.String(), b.Key.String()) })
}

// procsOf returns the processes holding listener k's sockets, deduplicated by
// PID and sorted by PID; an ownerless or absent listener gets an empty, non-nil
// slice.
func (t *Table) procsOf(k model.ListenerKey) []model.Process {
	cookies := make([]uint64, 0, len(t.byKey[k]))
	for c := range t.byKey[k] {
		cookies = append(cookies, c)
	}
	slices.Sort(cookies)
	byPID := make(map[uint32]model.Process)
	for _, cookie := range cookies {
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
	slices.SortFunc(procs, func(a, b model.Process) int { return cmp.Compare(a.PID, b.PID) })
	return procs
}

// v6OnlyOf combines the IPV6_V6ONLY flags of a key's sockets: one dual-stack socket
// takes IPv4 for the key, and an unread one leaves it unknown.
func (t *Table) v6OnlyOf(key model.ListenerKey) model.V6Only {
	on, unknown := false, false
	for cookie := range t.byKey[key] {
		switch t.sockets[cookie].V6Only {
		case model.V6OnlyOff:
			return model.V6OnlyOff
		case model.V6OnlyOn:
			on = true
		default:
			unknown = true
		}
	}
	if on && !unknown {
		return model.V6OnlyOn
	}
	return model.V6OnlyUnknown
}

// sameProcs reports whether two holder sets have the same owners. Only identity
// fields count: a change of UID, Comm or Cmdline alone is stored silently and
// shows in snapshots and later events.
func sameProcs(a, b []model.Process) bool {
	return slices.EqualFunc(a, b, model.Process.SameIdentity)
}

// Snapshot returns the open listeners sorted by key, each with its processes
// deduplicated and sorted by PID. Listeners waiting out their close grace are
// not open and are excluded.
func (t *Table) Snapshot() []Listener {
	out := make([]Listener, 0, len(t.byKey))
	for key := range t.byKey {
		out = append(out, Listener{Key: key, Procs: t.procsOf(key), V6Only: t.v6OnlyOf(key)})
	}
	slices.SortFunc(out, func(a, b Listener) int { return strings.Compare(a.Key.String(), b.Key.String()) })
	return out
}
