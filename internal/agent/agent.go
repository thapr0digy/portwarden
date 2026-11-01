// Package agent sequences startup so no listener is missed or reported twice.
package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/thapr0digy/listener-watch/internal/model"
	"github.com/thapr0digy/listener-watch/internal/state"
)

// EventSource delivers live observations from the kernel probes.
type EventSource interface {
	Events() <-chan model.Observation
}

// Snapshotter takes the baseline of currently listening sockets.
type Snapshotter func() ([]model.Observation, error)

// Sink receives what the agent publishes.
type Sink interface {
	Changes([]state.Change)
	Snapshot([]state.Listener)
}

// Run starts probe-first: it buffers events from src, takes the baseline, publishes
// it as one Snapshot (no Opened changes), replays the buffered events in arrival
// order, then forwards live changes until ctx is cancelled or src closes.
// It returns nil on cancellation or a closed source, and the snapshot error otherwise.
func Run(ctx context.Context, src EventSource, snap Snapshotter, sink Sink) error {
	buf := bufferEvents(ctx, src.Events())

	baseline, err := snap()
	if err != nil {
		buf.stop()
		return fmt.Errorf("baseline snapshot: %w", err)
	}
	buffered := buf.stop()

	table := state.New()
	for _, o := range baseline {
		table.Apply(o)
	}
	sink.Snapshot(table.Snapshot())

	for _, o := range buffered {
		publish(sink, table.Apply(o))
	}

	events := src.Events()
	for {
		select {
		case <-ctx.Done():
			return nil
		case o, ok := <-events:
			if !ok {
				return nil
			}
			publish(sink, table.Apply(o))
		}
	}
}

func publish(sink Sink, changes []state.Change) {
	if len(changes) > 0 {
		sink.Changes(changes)
	}
}

// eventBuffer collects events in a goroutine until stopped, so the source is
// drained while the baseline is being taken.
type eventBuffer struct {
	quit chan struct{}
	done chan struct{}
	once sync.Once
	got  []model.Observation
}

func bufferEvents(ctx context.Context, events <-chan model.Observation) *eventBuffer {
	b := &eventBuffer{quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(b.done)
		for {
			select {
			case <-b.quit:
				return
			case <-ctx.Done():
				return
			case o, ok := <-events:
				if !ok {
					return
				}
				b.got = append(b.got, o)
			}
		}
	}()
	return b
}

// stop ends the goroutine and returns everything it received, in arrival order.
func (b *eventBuffer) stop() []model.Observation {
	b.once.Do(func() { close(b.quit) })
	<-b.done
	return b.got
}
