package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/thapr0digy/portwarden/internal/inventory"
)

// fakeStore is an in-memory invStore: it records what run and the consumer do with it.
type fakeStore struct {
	mu          sync.Mutex
	applied     []inventory.Event
	cursors     map[string]inventory.Cursor
	quarantined []string
	forgotten   []string
	pings       int
	closed      bool
	afterClose  int // calls made after Close (a worker outliving the store)
	dsn         string
}

func newFakeStore() *fakeStore { return &fakeStore{cursors: map[string]inventory.Cursor{}} }

func (f *fakeStore) call() {
	if f.closed {
		f.afterClose++
	}
}

func (f *fakeStore) snapshot() (applied, quarantined, forgotten int, closed bool, afterClose int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied), len(f.quarantined), len(f.forgotten), f.closed, f.afterClose
}

func (f *fakeStore) Cursor(_ context.Context, host string) (inventory.Cursor, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call()
	c, ok := f.cursors[host]
	return c, ok, nil
}

func (f *fakeStore) Apply(_ context.Context, e inventory.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call()
	f.applied = append(f.applied, e)
	return nil
}

func (f *fakeStore) SetCursor(_ context.Context, host string, c inventory.Cursor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call()
	f.cursors[host] = c
	return nil
}

func (f *fakeStore) SetSilent(context.Context, string, time.Time) error { return nil }

func (f *fakeStore) LastHeartbeats(context.Context) (map[string]time.Time, error) {
	return map[string]time.Time{}, nil
}

func (f *fakeStore) Forget(_ context.Context, host string, _ inventory.Mark) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call()
	f.forgotten = append(f.forgotten, host)
	return true, nil
}

func (f *fakeStore) ForgottenMark(context.Context, string) (inventory.Mark, bool, error) {
	return inventory.Mark{}, false, nil
}

func (f *fakeStore) PruneMarks(context.Context, time.Time, uint64) (int64, error) { return 0, nil }

func (f *fakeStore) Hosts(context.Context, inventory.HostQuery) ([]inventory.HostView, error) {
	return nil, nil
}

func (f *fakeStore) Host(context.Context, string) (inventory.HostView, bool, error) {
	return inventory.HostView{}, false, nil
}

func (f *fakeStore) Listeners(context.Context, inventory.ListenerFilter) ([]inventory.ListenerView, error) {
	return nil, nil
}

func (f *fakeStore) History(context.Context, inventory.HistoryQuery) ([]inventory.HistoryView, error) {
	return nil, nil
}

func (f *fakeStore) Proxies(context.Context, string, string) ([]inventory.ProxyView, error) {
	return nil, nil
}

func (f *fakeStore) Ping(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings++
	return nil
}

func (f *fakeStore) CloudHost(context.Context, string) (inventory.CloudHost, bool, error) {
	return inventory.CloudHost{}, false, nil
}

func (f *fakeStore) CloudHosts(context.Context) ([]string, error) { return nil, nil }

func (f *fakeStore) SetCloudStatus(context.Context, string, string, time.Time) error { return nil }

func (f *fakeStore) ProbeInput(context.Context, string, string) (inventory.ProbeInput, bool, error) {
	return inventory.ProbeInput{}, false, nil
}

func (f *fakeStore) StaleProbes(context.Context, time.Time, int) ([]inventory.HostKey, error) {
	return nil, nil
}

func (f *fakeStore) PruneHistory(context.Context, time.Time, int) (int64, error)    { return 0, nil }
func (f *fakeStore) PruneQuarantine(context.Context, time.Time, int) (int64, error) { return 0, nil }

func (f *fakeStore) Quarantine(_ context.Context, _ uint64, subject, _ string, _ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call()
	f.quarantined = append(f.quarantined, subject)
	return nil
}

func (f *fakeStore) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

// opener returns an openStoreFunc that hands out s and records the DSN it was given.
func opener(s *fakeStore) openStoreFunc {
	return func(_ context.Context, d string) (invStore, error) {
		s.mu.Lock()
		s.dsn = d
		s.mu.Unlock()
		return s, nil
	}
}

func (f *fakeStore) openedWith() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dsn
}

func failingOpener(context.Context, string) (invStore, error) {
	return nil, errors.New("pg: connection refused")
}
