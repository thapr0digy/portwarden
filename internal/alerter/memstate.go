package alerter

import (
	"context"
	"time"
)

// MemState is an in-memory State (tests, and the stdout-only mode has no use for it).
type MemState struct {
	Paged  map[string]time.Time
	Probes map[string]string
	Queue  []*Alert
}

// NewMemState returns an empty state.
func NewMemState() *MemState {
	return &MemState{Paged: map[string]time.Time{}, Probes: map[string]string{}}
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
