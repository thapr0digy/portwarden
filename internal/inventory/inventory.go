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
// agent reconnect).
//
// Run ordering: agents since the M5 fix wave stamp every message with the kernel boot id
// and a run counter kept in their spool directory. A run from another boot, or with a
// higher counter in the same boot, is a new run; the previous run id is retired and its
// late leftovers skipped. For older agents (counter 0) the run id's ULID order decides.
//
// Origins come from the subject only: asm.<host>.* is the host's agent (an asm event
// whose body claims another origin, or an asm exposure.confirmed, is quarantined as a
// forgery); pwb.cloud.<host>.exposure is the cloud look-up and pwb.verifier.<host>.exposure
// the outside checker, which no host may publish. Backend events are not part of the
// host's sequence and are applied without touching the cursor.
//
// Errors: a message that cannot be decoded or that the store rejects as data (Store
// returns an error marked svc.Permanent) is quarantined by the caller; any other error
// is transient and retried.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
)

// Meta is where a message came from.
type Meta struct {
	Host, Kind string
	// Origin is the subject's: "" (agent), "cloud" or "verifier".
	Origin string
	// StreamSeq and StreamTime are the JetStream sequence and server time of the message.
	StreamSeq  uint64
	StreamTime time.Time
}

// maxRetired bounds the retired run ids kept per host.
const maxRetired = 8

// Cursor is a host's position in its agent's sequence.
type Cursor struct {
	RunID       string
	LastSeq     uint64
	NeedsResync bool
	BootID      string
	RunNumber   uint64
	// Retired are the host's previous run ids, newest last; their messages are skipped.
	Retired []string
}

// Event is one decoded message for the store. Cursor is nil for backend events, which
// must not move the host's cursor.
type Event struct {
	Meta   Meta
	Cursor *Cursor
	// One of *asmv1.Snapshot, *asmv1.ListenerEvent, *asmv1.ExposureEvent,
	// *asmv1.ExposureConfirmation, *asmv1.ProxyRoutes, *asmv1.HostEvent, *asmv1.Heartbeat,
	// *asmv1.TamperEvent.
	Msg proto.Message
}

// Store is the inventory's state. Apply must be atomic: the message's effect and the
// cursor are written together. An error that retrying cannot fix (bad data) must be
// marked with svc.Permanent.
type Store interface {
	Cursor(ctx context.Context, host string) (Cursor, bool, error)
	Apply(ctx context.Context, e Event) error
	// SetCursor writes only a host's cursor (a skipped message that still moves it).
	SetCursor(ctx context.Context, host string, c Cursor) error
	// SetSilent records a host going silent (since non-zero) or recovering (zero).
	SetSilent(ctx context.Context, host string, since time.Time) error
	// LastHeartbeats returns every host's last heartbeat time, to seed liveness.
	LastHeartbeats(ctx context.Context) (map[string]time.Time, error)
	// Forget removes a host's rows (host, listeners, proxies, exposure history) and records
	// mark, its pwb.inventory.<host>.forgotten announcement's place in the stream, in one
	// transaction (a mark of the same stream with a higher sequence is kept). existed
	// reports whether the host was stored.
	Forget(ctx context.Context, host string, mark Mark) (existed bool, err error)
	// ForgottenMark returns a host's forget mark (ok false: never forgotten).
	ForgottenMark(ctx context.Context, host string) (mark Mark, ok bool, err error)
	// PruneMarks drops the marks of another stream (one created at another time) and those
	// past the stream's last sequence (a stream reset), at start.
	PruneMarks(ctx context.Context, stream time.Time, lastSeq uint64) (int64, error)
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
	// Feed gates silence on the backend's own feed (nil: always judge).
	Feed *liveness.Feed
	// Changed, when set, is called after a message that may change what the cloud
	// look-up sees for the host (its listeners, exposure or host block).
	Changed func(host string)
	// Exposed, when set, is called after an agent or cloud exposure change of a listener
	// (the probe requester).
	Exposed func(host, key string)
	// Announce publishes a host's pwb.inventory.<host>.forgotten and returns its stream
	// sequence (Forget needs it; without it Forget is refused).
	Announce func(ctx context.Context, host string) (uint64, error)
	Now      func() time.Time

	// handle serialises Handle and Forget, so a message is never applied half before and
	// half after a forget; Forget waits for it under its context.
	handleOnce sync.Once
	handle     chan struct{}
	// stream is the ASM_EVENTS stream's identity (SetStream), stamped on forget marks.
	streamMu sync.Mutex
	stream   time.Time
	// liveMu guards Liveness and Feed: Handle and CheckSilence run on different goroutines.
	liveMu sync.Mutex
}

// Handle processes one message. A permanent error (svc.IsPermanent) means the message
// must be quarantined; any other error means retry.
func (c *Consumer) Handle(ctx context.Context, subject string, data []byte, m Meta) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	p, ok := bus.Parse(subject)
	if !ok {
		slog.Warn("inventory: skipping message on unexpected subject", "subject", subject)
		return nil
	}
	m.Host, m.Kind, m.Origin = p.Host, p.Kind, p.Origin
	if p.Origin == bus.OriginInventory {
		if p.Kind == bus.KindForgotten {
			return c.applyForgotten(ctx, p.Host, data, m.StreamSeq)
		}
		return nil
	}
	msg, err := decode(p, data)
	if err != nil {
		return svc.Permanent(err)
	}
	if msg == nil {
		return nil // a kind the inventory does not keep
	}
	if h := hostOf(msg); h != "" && h != p.Host {
		// The subject is what NATS permissions vouch for; a body naming another host is
		// an impersonation attempt or a bug.
		return svc.Permanent(fmt.Errorf("host_id %q differs from the subject's host", h))
	}
	if p.Origin != bus.OriginAgent {
		if stale, err := c.staleVerdict(ctx, p.Host, m.StreamSeq); err != nil || stale {
			return err
		}
		if err := c.Store.Apply(ctx, Event{Meta: m, Msg: msg}); err != nil {
			return err
		}
		c.changed(p.Host, p.Kind, p.Origin)
		if ev, ok := msg.(*asmv1.ExposureEvent); ok {
			c.exposed(p.Host, ev.GetListener())
		}
		return nil
	}
	c.feedReceived()
	ag := msg.(agentMsg)
	return c.handleAgent(ctx, m, ag)
}

type agentMsg interface {
	proto.Message
	GetRunId() string
	GetSeq() uint64
	GetBootId() string
	GetRunNumber() uint64
}

type runAction int

const (
	runSame runAction = iota
	runNew
	runSkip
)

// runOrder places a message's run against the host's current one.
func runOrder(cur Cursor, known bool, run, boot string, num uint64) runAction {
	switch {
	case !known || cur.RunID == "":
		return runNew
	case run == cur.RunID:
		return runSame
	case slices.Contains(cur.Retired, run):
		return runSkip
	case num > 0 && cur.RunNumber == 0:
		return runNew // the agent was upgraded to one that numbers its runs
	case num > 0:
		if boot != cur.BootID || num > cur.RunNumber {
			return runNew
		}
		return runSkip
	case cur.RunNumber > 0:
		return runSkip // an unnumbered run after numbered ones: a leftover from before an upgrade
	case run > cur.RunID:
		return runNew
	}
	return runSkip
}

func (c *Consumer) handleAgent(ctx context.Context, m Meta, msg agentMsg) error {
	run, seq := msg.GetRunId(), msg.GetSeq()
	cur, known, err := c.Store.Cursor(ctx, m.Host)
	if err != nil {
		return err
	}
	if !known {
		// An unknown host may be a forgotten one whose leftovers are still in the stream.
		if old, err := c.leftover(ctx, m.Host, m.StreamSeq); err != nil || old {
			return err
		}
	}
	switch runOrder(cur, known, run, msg.GetBootId(), msg.GetRunNumber()) {
	case runSkip:
		slog.Info("inventory: skipping message from an earlier agent run", "host", m.Host, "run", run, "current", cur.RunID, "seq", seq)
		return nil
	case runNew:
		retired := cur.Retired
		if cur.RunID != "" {
			retired = append(slices.Clone(retired), cur.RunID)
			if len(retired) > maxRetired {
				retired = retired[len(retired)-maxRetired:]
			}
		}
		cur = Cursor{RunID: run, NeedsResync: cur.NeedsResync, BootID: msg.GetBootId(), RunNumber: msg.GetRunNumber(), Retired: retired}
	case runSame:
		if seq <= cur.LastSeq {
			return nil // duplicate (redelivery)
		}
	}
	if _, ok := msg.(*asmv1.Heartbeat); ok {
		if err := c.heartbeat(ctx, m.Host); err != nil {
			return err
		}
	}

	_, isSnap := msg.(*asmv1.Snapshot)
	gap := seq != cur.LastSeq+1
	next := cur
	next.LastSeq = seq
	if isSnap {
		next.NeedsResync = false
	} else if gap {
		reloaded, err := c.reload(ctx, m.Host, next, seq)
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
	c.changed(m.Host, m.Kind, bus.OriginAgent)
	if ev, ok := msg.(*asmv1.ExposureEvent); ok {
		c.exposed(m.Host, ev.GetListener())
	}
	return nil
}

// heartbeat feeds liveness on the backend's own receive clock.
func (c *Consumer) heartbeat(ctx context.Context, host string) error {
	if c.Liveness == nil {
		return nil
	}
	now := c.now()
	c.liveMu.Lock()
	r := c.Liveness.Seen(host, now, now)
	c.liveMu.Unlock()
	if r != nil {
		slog.Info("host recovered", "host", host, "last_heartbeat", r.LastSeen)
		return c.Store.SetSilent(ctx, host, time.Time{})
	}
	return nil
}

func (c *Consumer) feedReceived() {
	if c.Feed == nil {
		return
	}
	c.liveMu.Lock()
	c.Feed.Received(c.now())
	c.liveMu.Unlock()
}

// SetConnected tells the feed gate about the NATS connection.
func (c *Consumer) SetConnected(ok bool) {
	if c.Feed == nil {
		return
	}
	c.liveMu.Lock()
	c.Feed.SetConnected(ok, c.now())
	c.liveMu.Unlock()
}

// reload applies the host's latest snapshot when it belongs to the cursor's run and is
// at or past seq, and reports whether it did.
func (c *Consumer) reload(ctx context.Context, host string, cur Cursor, seq uint64) (bool, error) {
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
	if snap.GetRunId() != cur.RunID || snap.GetSeq() < seq || snap.GetHostId() != host {
		return false, nil
	}
	sm.Host, sm.Kind = host, bus.KindSnapshot
	slog.Info("inventory: sequence gap; reloaded the host's latest snapshot", "host", host, "run", cur.RunID, "snapshot_seq", snap.GetSeq(), "at_seq", seq)
	next := cur
	next.LastSeq, next.NeedsResync = snap.GetSeq(), false
	if err := c.Store.Apply(ctx, Event{Meta: sm, Cursor: &next, Msg: snap}); err != nil {
		return false, err
	}
	c.changed(host, bus.KindSnapshot, bus.OriginAgent)
	return true, nil
}

func (c *Consumer) changed(host, kind, origin string) {
	if c.Changed == nil || origin != bus.OriginAgent {
		return
	}
	switch kind {
	case bus.KindHeartbeat, bus.KindProxyRoutes, bus.KindTamper:
		return
	}
	c.Changed(host)
}

func (c *Consumer) exposed(host string, l *asmv1.Listener) {
	if c.Exposed != nil && l.GetKey() != "" {
		c.Exposed(host, l.GetKey())
	}
}

// CheckSilence records hosts that went silent since the last call. While the backend's
// own feed is stalled (or in the grace after it recovers) no host is judged.
func (c *Consumer) CheckSilence(ctx context.Context) error {
	if c.Liveness == nil {
		return nil
	}
	now := c.now()
	c.liveMu.Lock()
	judge := true
	if c.Feed != nil {
		var ev liveness.FeedEvent
		ev, judge = c.Feed.Check(now)
		switch ev {
		case liveness.FeedStalled:
			slog.Error("inventory feed stalled: no messages from any host (or NATS down); host silence is not judged until it recovers")
		case liveness.FeedRecovered:
			slog.Info("inventory feed recovered; host silence judged again after the grace period", "grace", c.Feed.After)
		}
	}
	var silent []liveness.Transition
	if judge {
		silent = c.Liveness.Check(now)
	}
	c.liveMu.Unlock()
	for _, t := range silent {
		slog.Warn("host silent", "host", t.Host, "last_heartbeat", t.LastSeen, "after", c.Liveness.After)
		if err := c.Store.SetSilent(ctx, t.Host, t.At); err != nil {
			return err
		}
	}
	return nil
}

// SeedLiveness registers every known host as heard now (the backend's clock): a host that
// sends nothing within silent_after (after the start-up grace) is then silent.
func (c *Consumer) SeedLiveness(ctx context.Context) error {
	if c.Liveness == nil {
		return nil
	}
	last, err := c.Store.LastHeartbeats(ctx)
	if err != nil {
		return err
	}
	now := c.now()
	c.liveMu.Lock()
	defer c.liveMu.Unlock()
	for h := range last {
		c.Liveness.Seen(h, now, now)
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

// decode returns the message for a parsed subject, or nil for kinds the inventory
// ignores. Forged origins are errors.
func decode(p bus.Parsed, data []byte) (proto.Message, error) {
	var msg proto.Message
	switch p.Origin {
	case bus.OriginCloud:
		msg = &asmv1.ExposureEvent{}
	case bus.OriginVerifier:
		msg = &asmv1.ExposureConfirmation{}
	case bus.OriginAgent:
		switch p.Kind {
		case bus.KindOpened, bus.KindClosed, bus.KindOwnerChanged:
			msg = &asmv1.ListenerEvent{}
		case bus.KindExposureChanged:
			msg = &asmv1.ExposureEvent{}
		case bus.KindProxyRoutes:
			msg = &asmv1.ProxyRoutes{}
		case bus.KindSnapshot:
			msg = &asmv1.Snapshot{}
		case bus.KindHeartbeat:
			msg = &asmv1.Heartbeat{}
		case bus.KindHostChanged:
			msg = &asmv1.HostEvent{}
		case bus.KindTamper:
			msg = &asmv1.TamperEvent{}
		case bus.KindExposureConfirmed:
			return nil, errors.New("exposure.confirmed under asm.<host> is forged: verifier results are on pwb.verifier")
		default:
			return nil, nil
		}
	default:
		return nil, nil
	}
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	switch e := msg.(type) {
	case *asmv1.ExposureEvent:
		if p.Origin == bus.OriginAgent && e.GetOrigin() != "" {
			return nil, fmt.Errorf("agent exposure.changed claims origin %q: forged", e.GetOrigin())
		}
		e.Origin = p.Origin // the subject decides, never the body
	case *asmv1.ExposureConfirmation:
		e.Origin = bus.OriginVerifier
	}
	if p.Origin == bus.OriginAgent && msg.(agentMsg).GetRunId() == "" {
		return nil, errors.New("agent event without run_id")
	}
	return msg, nil
}
