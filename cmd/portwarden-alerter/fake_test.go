package main

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/alerter"
	"github.com/thapr0digy/portwarden/internal/alerter/pgstate"
)

// fakeStore is an in-memory stateStore and alerter.State. InTx holds the lock for the
// whole transaction (there is no rollback: a failing f leaves its writes, which the
// tests do not rely on).
type fakeStore struct {
	mu         sync.Mutex
	paged      map[string]time.Time
	probes     map[string]string
	marks      map[string]alerter.ForgetMark
	runs       map[string]alerter.Run
	outbox     []*fakePage
	closed     bool
	afterClose int
	// txFails makes the next n transactions fail (a database outage).
	txFails int
	txs     int
	dueErr  error
	// pruned counts PruneForgotten's drops to report.
	pruneDrops int64
}

type fakePage struct {
	pgstate.Page
	next      time.Time
	delivered bool
	gaveUp    bool
	lastErr   string
}

func newFakeStore() *fakeStore {
	return &fakeStore{paged: map[string]time.Time{}, probes: map[string]string{}, marks: map[string]alerter.ForgetMark{},
		runs: map[string]alerter.Run{}}
}

func (f *fakeStore) touch() {
	if f.closed {
		f.afterClose++
	}
}

func (f *fakeStore) InTx(ctx context.Context, fn func(alerter.State) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touch()
	f.txs++
	if f.txFails > 0 {
		f.txFails--
		return errors.New("pg: connection refused")
	}
	return fn(memTx{f})
}

func (f *fakeStore) Forgotten(context.Context) (map[string]alerter.ForgetMark, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]alerter.ForgetMark{}
	for k, v := range f.marks {
		out[k] = v
	}
	return out, nil
}

func (f *fakeStore) PruneForgotten(context.Context, time.Time, uint64) (int64, error) {
	return f.pruneDrops, nil
}

func (f *fakeStore) Due(_ context.Context, now time.Time, limit int) ([]pgstate.Page, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touch()
	if f.dueErr != nil {
		return nil, f.dueErr
	}
	var out []pgstate.Page
	for _, p := range f.outbox {
		if !p.delivered && !p.gaveUp && !p.next.After(now) && len(out) < limit {
			out = append(out, p.Page)
		}
	}
	return out, nil
}

func (f *fakeStore) page(id string) *fakePage {
	for _, p := range f.outbox {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func (f *fakeStore) Delivered(_ context.Context, id string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touch()
	if p := f.page(id); p != nil {
		p.delivered = true
		p.Attempts++
	}
	return nil
}

func (f *fakeStore) Failed(_ context.Context, id string, next time.Time, giveUp bool, why string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touch()
	if p := f.page(id); p != nil {
		p.Attempts++
		p.next, p.gaveUp, p.lastErr = next, giveUp, why
	}
	return nil
}

func (f *fakeStore) Prune(context.Context, time.Time, time.Duration) error { return nil }

func (f *fakeStore) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

// pages returns a copy of the outbox.
func (f *fakeStore) pages() []fakePage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakePage, len(f.outbox))
	for i, p := range f.outbox {
		out[i] = *p
	}
	return out
}

func (f *fakeStore) kinds() []string {
	var k []string
	for _, p := range f.pages() {
		k = append(k, p.Alert.Kind)
	}
	sort.Strings(k)
	return k
}

// memTx is the State inside a fakeStore transaction (the lock is held).
type memTx struct{ f *fakeStore }

func (t memTx) LastPaged(_ context.Context, key string) (time.Time, bool, error) {
	at, ok := t.f.paged[key]
	return at, ok, nil
}

func (t memTx) SetPaged(_ context.Context, key string, at time.Time) error {
	t.f.paged[key] = at
	return nil
}

func (t memTx) ClearPaged(_ context.Context, key string) error {
	delete(t.f.paged, key)
	return nil
}

func (t memTx) PagedKeys(_ context.Context, prefix string) ([]string, error) {
	var out []string
	for k := range t.f.paged {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (t memTx) ProbeResult(_ context.Context, key string) (string, error) {
	return t.f.probes[key], nil
}

func (t memTx) SetProbeResult(_ context.Context, key, result string, _ time.Time) error {
	t.f.probes[key] = result
	return nil
}

func (t memTx) ClearProbes(_ context.Context, prefix string) error {
	for k := range t.f.probes {
		if strings.HasPrefix(k, prefix) {
			delete(t.f.probes, k)
		}
	}
	return nil
}

func (t memTx) SetForgotten(_ context.Context, host string, mark alerter.ForgetMark) error {
	if old, ok := t.f.marks[host]; ok && old.Stream.Equal(mark.Stream) && old.Seq > mark.Seq {
		return nil
	}
	mark.Back = false
	t.f.marks[host] = mark
	return nil
}

func (t memTx) SetBack(_ context.Context, host string) error {
	if m, ok := t.f.marks[host]; ok {
		m.Back = true
		t.f.marks[host] = m
	}
	return nil
}

func (t memTx) ForgetMark(_ context.Context, host string) (alerter.ForgetMark, bool, error) {
	m, ok := t.f.marks[host]
	return m, ok, nil
}

func (t memTx) Enqueue(_ context.Context, a *alerter.Alert) error {
	if t.f.page(a.ID) == nil {
		t.f.outbox = append(t.f.outbox, &fakePage{Page: pgstate.Page{ID: a.ID, Alert: *a}})
	}
	return nil
}

func opener(s *fakeStore) openStoreFunc {
	return func(context.Context, string) (stateStore, error) { return s, nil }
}

// fakeMsg is a stream message for the handlers (only what they read).
type fakeMsg struct {
	jetstream.Msg
	subject string
	data    []byte
	seq     uint64
}

func (m fakeMsg) Subject() string { return m.subject }
func (m fakeMsg) Data() []byte    { return m.data }
func (m fakeMsg) Metadata() (*jetstream.MsgMetadata, error) {
	if m.seq == 0 {
		return nil, jetstream.ErrNotJSMessage
	}
	return &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: m.seq}}, nil
}

func (t memTx) Run(_ context.Context, host string) (alerter.Run, bool, error) {
	r, ok := t.f.runs[host]
	return r, ok, nil
}

func (t memTx) SetRun(_ context.Context, host string, r alerter.Run) error {
	t.f.runs[host] = r
	return nil
}

func (t memTx) ClearRun(_ context.Context, host string) error {
	delete(t.f.runs, host)
	return nil
}
