package alerter

import (
	"context"
	"slices"
	"strings"
	"time"
)

// MemState is an in-memory State (tests, and the stdout-only mode has no use for it).
type MemState struct {
	Paged     map[string]time.Time
	Probes    map[string]string
	Forgotten map[string]ForgetMark
	Runs      map[string]Run
	Queue     []*Alert
}

// NewMemState returns an empty state.
func NewMemState() *MemState {
	return &MemState{Paged: map[string]time.Time{}, Probes: map[string]string{}, Forgotten: map[string]ForgetMark{},
		Runs: map[string]Run{}}
}
func (m *MemState) ClearProbes(_ context.Context, prefix string) error {
	for k := range m.Probes {
		if strings.HasPrefix(k, prefix) {
			delete(m.Probes, k)
		}
	}
	return nil
}
func (m *MemState) SetForgotten(_ context.Context, host string, mark ForgetMark) error {
	if old, ok := m.Forgotten[host]; ok && old.Stream.Equal(mark.Stream) && old.Seq >= mark.Seq {
		return nil
	}
	m.Forgotten[host] = mark
	return nil
}
func (m *MemState) SetBack(_ context.Context, host string) error {
	if f, ok := m.Forgotten[host]; ok {
		f.Back = true
		m.Forgotten[host] = f
	}
	return nil
}
func (m *MemState) ForgetMark(_ context.Context, host string) (ForgetMark, bool, error) {
	f, ok := m.Forgotten[host]
	return f, ok, nil
}

func (m *MemState) LastPaged(_ context.Context, key string) (time.Time, bool, error) {
	at, ok := m.Paged[key]
	return at, ok, nil
}
func (m *MemState) SetPaged(_ context.Context, key string, at time.Time) error {
	m.Paged[key] = at
	return nil
}
func (m *MemState) ClearPaged(_ context.Context, key string) error {
	delete(m.Paged, key)
	return nil
}
func (m *MemState) PagedKeys(_ context.Context, prefix string) ([]string, error) {
	var out []string
	for k := range m.Paged {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}
func (m *MemState) ProbeResult(_ context.Context, key string) (string, error) {
	return m.Probes[key], nil
}
func (m *MemState) SetProbeResult(_ context.Context, key, result string, _ time.Time) error {
	m.Probes[key] = result
	return nil
}
func (m *MemState) Enqueue(_ context.Context, a *Alert) error {
	m.Queue = append(m.Queue, a)
	return nil
}
func (m *MemState) Run(_ context.Context, host string) (Run, bool, error) {
	r, ok := m.Runs[host]
	return r, ok, nil
}
func (m *MemState) SetRun(_ context.Context, host string, r Run) error {
	m.Runs[host] = r
	return nil
}
func (m *MemState) ClearRun(_ context.Context, host string) error {
	delete(m.Runs, host)
	return nil
}
