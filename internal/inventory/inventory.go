// Package inventory keeps the current state of every host, listener, exposure and proxy
// route from the ASM_EVENTS stream (design §1 "Inventory"). The Consumer decodes each
// message, tracks every host's run and sequence number, and hands the store one Event per
// message; the store applies it in one transaction together with the host's cursor, so a
// redelivered message is recognised and skipped.
//
// Sequence handling (design §6): within a run seq must rise by one. A duplicate (seq at
// or below the cursor) is skipped. A gap reloads the host's latest snapshot from the
// stream when that snapshot is at or past the gap (the snapshot replaces the host's
// listeners and every later event applies on top); otherwise the event is applied and the
// host is marked needs_resync until its next snapshot (every 5 minutes, and after every
// agent reconnect). Run ids are ULIDs, so a message from an older run than the host's
// current one (a late leftover) is skipped; a newer run starts a new cursor.
//
// Backend events (exposure.changed with an origin, exposure.confirmed) are not part of
// the host's sequence and are applied without touching the cursor.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
)

// Meta is where a message came from.
type Meta struct {
	Host, Kind string
	// StreamSeq and StreamTime are the JetStream sequence and server time of the message.
	StreamSeq  uint64
	StreamTime time.Time
}

// Cursor is a host's position in its agent's sequence.
type Cursor struct {
	RunID       string
	LastSeq     uint64
	NeedsResync bool
}

// Event is one decoded message for the store. Cursor is nil for backend events, which
// must not move the host's cursor.
type Event struct {
	Meta   Meta
	Cursor *Cursor
	// One of *asmv1.Snapshot, *asmv1.ListenerEvent, *asmv1.ExposureEvent,
	// *asmv1.ExposureConfirmation, *asmv1.ProxyRoutes, *asmv1.HostEvent, *asmv1.Heartbeat.
	Msg proto.Message
}

// Store is the inventory's state. Apply must be atomic: the message's effect and the
// cursor are written together.
type Store interface {
	Cursor(ctx context.Context, host string) (Cursor, bool, error)
	Apply(ctx context.Context, e Event) error
	// SetCursor writes only a host's cursor (a skipped message that still moves it).
	SetCursor(ctx context.Context, host string, c Cursor) error
	// SetSilent records a host going silent (since non-zero) or recovering (zero).
	SetSilent(ctx context.Context, host string, since time.Time) error
	// LastHeartbeats returns every host's last heartbeat time, to seed liveness.
	LastHeartbeats(ctx context.Context) (map[string]time.Time, error)
}

// SnapshotSource fetches a host's latest snapshot from the stream (gap reload).
type SnapshotSource interface {
	LatestSnapshot(ctx context.Context, host string) (*asmv1.Snapshot, Meta, error)
}

// ErrNoSnapshot means the stream holds no snapshot for the host.
var ErrNoSnapshot = errors.New("no snapshot")

// Consumer turns stream messages into store events.
type Consumer struct {
	Store     Store
	Snapshots SnapshotSource
	Liveness  *liveness.Tracker
	// Changed, when set, is called after a message that may change what the cloud
	// look-up sees for the host (its listeners, exposure or host block).
	Changed func(host string)
	Now     func() time.Time
}

// Handle processes one message. An error means it was not applied and must be retried;
// malformed or unknown messages are logged and dropped (nil).
func (c *Consumer) Handle(ctx context.Context, subject string, data []byte, m Meta) error {
	host, kind, ok := bus.ParseSubject(subject)
	if !ok {
		slog.Warn("inventory: skipping message on unexpected subject", "subject", subject)
		return nil
	}
	m.Host, m.Kind = host, kind
	msg, run, seq, origin, err := decode(kind, data)
	if err != nil {
		slog.Warn("inventory: skipping undecodable message", "subject", subject, "err", err)
		return nil
	}
	if msg == nil {
		return nil // a kind the inventory does not keep
	}
	if hostOf(msg) != "" && hostOf(msg) != host {
		// The subject is what NATS permissions vouch for; a body naming another host is
		// an impersonation attempt or a bug.
		slog.Warn("inventory: dropping message whose host_id differs from its subject", "subject", subject, "host_id", hostOf(msg))
		return nil
	}
	if origin != "" {
		if err := c.Store.Apply(ctx, Event{Meta: m, Msg: msg}); err != nil {
			return err
		}
		c.changed(host, kind)
		return nil
	}
	return c.handleAgent(ctx, m, msg, run, seq)
}

func (c *Consumer) handleAgent(ctx context.Context, m Meta, msg proto.Message, run string, seq uint64) error {
	cur, known, err := c.Store.Cursor(ctx, m.Host)
	if err != nil {
		return err
	}
	if _, ok := msg.(*asmv1.Heartbeat); ok && c.Liveness != nil {
		if r := c.Liveness.Seen(m.Host, m.StreamTime, c.now()); r != nil {
			slog.Info("host recovered", "host", m.Host, "last_heartbeat", r.LastSeen)
			if err := c.Store.SetSilent(ctx, m.Host, time.Time{}); err != nil {
				return err
			}
		}
	}
	switch {
	case known && run < cur.RunID:
		slog.Info("inventory: skipping message from an older agent run", "host", m.Host, "run", run, "current", cur.RunID, "seq", seq)
		return nil
	case !known || run > cur.RunID:
		cur = Cursor{RunID: run, NeedsResync: cur.NeedsResync}
	case seq <= cur.LastSeq:
		return nil // duplicate (redelivery)
	}

	_, isSnap := msg.(*asmv1.Snapshot)
	gap := seq != cur.LastSeq+1
	next := Cursor{RunID: run, LastSeq: seq, NeedsResync: cur.NeedsResync}
	if isSnap {
		next.NeedsResync = false
	} else if gap {
		reloaded, err := c.reload(ctx, m.Host, run, seq)
		if err != nil {
			return err
		}
		if reloaded {
			return nil // the snapshot is at or past this message: it is already reflected
		}
		slog.Warn("inventory: sequence gap; host needs a resync (next snapshot)", "host", m.Host, "run", run,
			"expected", cur.LastSeq+1, "got", seq)
		next.NeedsResync = true
	}
	if err := c.Store.Apply(ctx, Event{Meta: m, Cursor: &next, Msg: msg}); err != nil {
		return err
	}
	c.changed(m.Host, m.Kind)
	return nil
}

// reload applies the host's latest snapshot when it belongs to run and is at or past
// seq, and reports whether it did.
func (c *Consumer) reload(ctx context.Context, host, run string, seq uint64) (bool, error) {
	if c.Snapshots == nil {
		return false, nil
	}
	snap, sm, err := c.Snapshots.LatestSnapshot(ctx, host)
	if errors.Is(err, ErrNoSnapshot) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("gap reload: %w", err)
	}
	if snap.GetRunId() != run || snap.GetSeq() < seq || snap.GetHostId() != host {
		return false, nil
	}
	sm.Host, sm.Kind = host, bus.KindSnapshot
	slog.Info("inventory: sequence gap; reloaded the host's latest snapshot", "host", host, "run", run, "snapshot_seq", snap.GetSeq(), "at_seq", seq)
	if err := c.Store.Apply(ctx, Event{Meta: sm, Cursor: &Cursor{RunID: run, LastSeq: snap.GetSeq()}, Msg: snap}); err != nil {
		return false, err
	}
	c.changed(host, bus.KindSnapshot)
	return true, nil
}

func (c *Consumer) changed(host, kind string) {
	if c.Changed == nil {
		return
	}
	switch kind {
	case bus.KindHeartbeat, bus.KindProxyRoutes, bus.KindExposureConfirmed:
		return
	}
	c.Changed(host)
}

// CheckSilence records hosts that went silent since the last call.
func (c *Consumer) CheckSilence(ctx context.Context) error {
	if c.Liveness == nil {
		return nil
	}
	for _, t := range c.Liveness.Check(c.now()) {
		slog.Warn("host silent", "host", t.Host, "last_heartbeat", t.LastSeen, "after", c.Liveness.After)
		if err := c.Store.SetSilent(ctx, t.Host, t.At); err != nil {
			return err
		}
	}
	return nil
}

// SeedLiveness loads every host's last heartbeat from the store.
func (c *Consumer) SeedLiveness(ctx context.Context) error {
	if c.Liveness == nil {
		return nil
	}
	last, err := c.Store.LastHeartbeats(ctx)
	if err != nil {
		return err
	}
	for h, at := range last {
		c.Liveness.Seen(h, at, c.now())
	}
	return nil
}

func (c *Consumer) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func hostOf(m proto.Message) string {
	if h, ok := m.(interface{ GetHostId() string }); ok {
		return h.GetHostId()
	}
	return ""
}

// decode returns the message for kind with its run, seq and origin; a nil message for
// kinds the inventory ignores.
func decode(kind string, data []byte) (proto.Message, string, uint64, string, error) {
	var msg interface {
		proto.Message
		GetRunId() string
		GetSeq() uint64
	}
	switch kind {
	case bus.KindOpened, bus.KindClosed, bus.KindOwnerChanged:
		msg = &asmv1.ListenerEvent{}
	case bus.KindExposureChanged:
		msg = &asmv1.ExposureEvent{}
	case bus.KindExposureConfirmed:
		msg = &asmv1.ExposureConfirmation{}
	case bus.KindProxyRoutes:
		msg = &asmv1.ProxyRoutes{}
	case bus.KindSnapshot:
		msg = &asmv1.Snapshot{}
	case bus.KindHeartbeat:
		msg = &asmv1.Heartbeat{}
	case bus.KindHostChanged:
		msg = &asmv1.HostEvent{}
	default:
		return nil, "", 0, "", nil
	}
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, "", 0, "", err
	}
	origin := ""
	switch e := msg.(type) {
	case *asmv1.ExposureEvent:
		origin = e.GetOrigin()
	case *asmv1.ExposureConfirmation:
		origin = "verifier" // never part of a host's sequence, whatever it says
	}
	if origin == "" && msg.GetRunId() == "" {
		return nil, "", 0, "", errors.New("agent event without run_id")
	}
	return msg, msg.GetRunId(), msg.GetSeq(), origin, nil
}
