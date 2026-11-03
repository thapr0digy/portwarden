package alerter

import (
	"context"
	"sync"
	"time"
)

// ForgetMark is a forgotten host's announcement (pwb.inventory.<host>.forgotten): its
// stream sequence, the stream's identity (its creation time; a recreated stream starts its
// sequences over) and whether the host has sent an agent message after it (came back).
type ForgetMark struct {
	Seq    uint64
	Stream time.Time
	Back   bool
}

// Forget drops a forgotten host's state (M8): its silence, tamper and listener dedupe
// marks and its listeners' probe results, and records the mark, in the caller's
// transaction. Afterwards the host is new: a heartbeat pages no recovery, and once it has
// come back a later silence pages again. Pages already in the outbox are still delivered.
func (e *Engine) Forget(ctx context.Context, st State, host string, mark ForgetMark) error {
	if err := st.ClearPaged(ctx, "silent:"+host); err != nil {
		return err
	}
	for _, prefix := range []string{TamperPrefix(host), "listener:" + host + "/"} {
		keys, err := st.PagedKeys(ctx, prefix)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err := st.ClearPaged(ctx, k); err != nil {
				return err
			}
		}
	}
	if err := st.ClearProbes(ctx, host+"/"); err != nil {
		return err
	}
	mark.Back = false
	return st.SetForgotten(ctx, host, mark)
}

// Forgotten reports, inside a decision's transaction, whether a message of host stored at
// stream sequence seq must be skipped because the host was forgotten: it was stored before
// the announcement, or it is a backend verdict (verdict true) while the host has not come
// back. Checking in the transaction closes the race with a forget applied meanwhile.
func (e *Engine) Forgotten(ctx context.Context, st State, host string, seq uint64, verdict bool) (bool, error) {
	m, ok, err := st.ForgetMark(ctx, host)
	if err != nil || !ok {
		return false, err
	}
	return skip(m, seq, verdict), nil
}

func skip(m ForgetMark, seq uint64, verdict bool) bool {
	return (seq != 0 && seq < m.Seq) || (verdict && !m.Back)
}

// Forgotten holds every forgotten host's mark in memory (loaded from the state at start,
// then kept up to date), so each heartbeat is checked without the database. Safe for
// concurrent use.
type Forgotten struct {
	mu    sync.Mutex
	marks map[string]forgottenMark
}

type forgottenMark struct {
	ForgetMark
	at time.Time
}

// NewForgotten starts from the stored marks.
func NewForgotten(stored map[string]ForgetMark) *Forgotten {
	f := &Forgotten{marks: map[string]forgottenMark{}}
	for h, m := range stored {
		f.marks[h] = forgottenMark{ForgetMark: m}
	}
	return f
}

// Set records a host forgotten at stream sequence seq of stream, at local time at; an
// older announcement of the same stream (a replay) changes nothing.
func (f *Forgotten) Set(host string, seq uint64, stream, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.marks[host]; !ok || !old.Stream.Equal(stream) || seq > old.Seq {
		f.marks[host] = forgottenMark{ForgetMark: ForgetMark{Seq: seq, Stream: stream}, at: at}
	}
}

// Leftover reports whether a host's message stored at stream sequence seq predates its
// forget (it is skipped: a replayed or redelivered message of the forgotten host). seq 0,
// a message without stream metadata, is never a leftover.
func (f *Forgotten) Leftover(host string, seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.marks[host]
	return ok && seq != 0 && seq < m.Seq
}

// SkipVerdict reports whether a cloud or verifier verdict about host must be skipped: the
// host was forgotten and has not sent an agent message since (a look-up or probe started
// before the forget), or the verdict was stored before the announcement.
func (f *Forgotten) SkipVerdict(host string, seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.marks[host]
	return ok && skip(m.ForgetMark, seq, true)
}

// ComingBack reports whether an agent message at seq is the forgotten host's first after
// its announcement: the caller persists that (State.SetBack) and then calls Back.
func (f *Forgotten) ComingBack(host string, seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.marks[host]
	return ok && !m.Back && seq > m.Seq
}

// Back records that the host came back.
func (f *Forgotten) Back(host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.marks[host]; ok {
		m.Back = true
		f.marks[host] = m
	}
}

// Covers reports whether the announcement at stream sequence seq is already applied (a
// replay at start, a redelivery): applying it again would drop the marks of a host that
// has come back since.
func (f *Forgotten) Covers(host string, seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.marks[host]
	return ok && seq != 0 && seq <= m.Seq
}

// Since reports whether the host was forgotten (in this process) at or after t.
func (f *Forgotten) Since(host string, t time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.marks[host]
	return ok && !m.at.IsZero() && !m.at.Before(t)
}

// Usable reports whether a stored mark belongs to the current stream (created at stream,
// last sequence lastSeq); marks of another stream, or past its end, are dropped at start.
func Usable(m ForgetMark, stream time.Time, lastSeq uint64) bool {
	return m.Stream.Equal(stream) && m.Seq <= lastSeq
}
