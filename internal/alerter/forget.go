package alerter

import (
	"context"
	"sync"
	"time"
)

// Forget drops a forgotten host's state (M8: the inventory's
// pwb.inventory.<host>.forgotten, stored at stream sequence streamSeq): its silence,
// tamper and listener dedupe marks and its listeners' probe results, and records the
// watermark, in the caller's transaction. Afterwards the host is new: a heartbeat pages
// no recovery, and a later silence pages again. Pages already in the outbox are still
// delivered.
func (e *Engine) Forget(ctx context.Context, st State, host string, streamSeq uint64) error {
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
	return st.SetForgotten(ctx, host, streamSeq)
}

// Forgotten holds every forgotten host's watermark in memory (loaded from the state at
// start, then kept up to date), so each message is checked without the database. Safe
// for concurrent use.
type Forgotten struct {
	mu    sync.Mutex
	marks map[string]forgottenMark
}

type forgottenMark struct {
	seq uint64
	at  time.Time
}

// NewForgotten starts from the stored watermarks (host to stream sequence).
func NewForgotten(stored map[string]uint64) *Forgotten {
	f := &Forgotten{marks: map[string]forgottenMark{}}
	for h, seq := range stored {
		f.marks[h] = forgottenMark{seq: seq}
	}
	return f
}

// Set records a host forgotten at stream sequence seq, at local time at; an older
// announcement (a replay) changes nothing.
func (f *Forgotten) Set(host string, seq uint64, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if seq > f.marks[host].seq {
		f.marks[host] = forgottenMark{seq: seq, at: at}
	}
}

// Leftover reports whether a host's message stored at stream sequence seq predates its
// forget (it is skipped: a replayed or redelivered message of the forgotten host). seq 0,
// a message without stream metadata, is never a leftover.
func (f *Forgotten) Leftover(host string, seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return seq != 0 && seq < f.marks[host].seq
}

// Covers reports whether the announcement at stream sequence seq is already applied (a
// replay at start, a redelivery): applying it again would drop the marks of a host that
// has come back since.
func (f *Forgotten) Covers(host string, seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return seq != 0 && seq <= f.marks[host].seq
}

// Since reports whether the host was forgotten (in this process) at or after t: a
// silence noticed before then is not paged.
func (f *Forgotten) Since(host string, t time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.marks[host]
	return ok && !m.at.IsZero() && !m.at.Before(t)
}
