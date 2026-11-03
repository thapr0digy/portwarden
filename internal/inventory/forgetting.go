package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// Mark is a forgotten host's announcement: its stream sequence and the identity of the
// stream it is in (the stream's creation time). A mark of another stream (the stream was
// deleted and created again, its sequences starting over) means nothing.
type Mark struct {
	Seq    uint64
	Stream time.Time
}

// ErrBadHost is a host id that is not one plain subject token (or is reserved).
var ErrBadHost = errors.New("bad host id")

// ErrNoStream means the stream's identity is not known yet (the inventory is starting).
var ErrNoStream = errors.New("the stream is not known yet; retry in a moment")

// forgetWait bounds how long Forget waits for the message being handled.
const forgetWait = 15 * time.Second

// ForgetResult is what Forget did.
type ForgetResult struct {
	Host string `json:"host"`
	// Existed is whether the inventory held the host (it is announced either way: the
	// alerter may still hold state for it).
	Existed bool `json:"existed"`
	// StreamSeq is the announcement's stream sequence: the host's messages stored before
	// it are skipped from now on; later ones make it a new host.
	StreamSeq uint64 `json:"stream_seq"`
}

// SetStream records the stream's identity (its creation time) once it is known; Forget
// is refused until then.
func (c *Consumer) SetStream(created time.Time) {
	c.streamMu.Lock()
	c.stream = created
	c.streamMu.Unlock()
}

func (c *Consumer) streamID() time.Time {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	return c.stream
}

func (c *Consumer) lock(ctx context.Context) error {
	c.handleOnce.Do(func() { c.handle = make(chan struct{}, 1) })
	select {
	case c.handle <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Consumer) unlock() { <-c.handle }

// Forget removes a decommissioned host (M8). It announces the host on
// pwb.inventory.<host>.forgotten first (so the alerter drops its marks and stops judging
// its silence), then removes its rows and stops judging its silence here. A failed
// announcement changes nothing; if the database step fails after it, the inventory's own
// consumer applies the announcement when it reaches it (and running Forget again also
// completes it). A host that sends again after its announcement is a new host.
func (c *Consumer) Forget(ctx context.Context, host string) (ForgetResult, error) {
	if err := natsauth.ValidHostID(host); err != nil {
		return ForgetResult{}, fmt.Errorf("%w: %v", ErrBadHost, err)
	}
	if c.Announce == nil {
		return ForgetResult{}, errors.New("inventory: forget needs the bus (no announcer)")
	}
	stream := c.streamID()
	if stream.IsZero() {
		return ForgetResult{}, ErrNoStream
	}
	wctx, cancel := context.WithTimeout(ctx, forgetWait)
	defer cancel()
	if err := c.lock(wctx); err != nil {
		return ForgetResult{}, fmt.Errorf("waiting for the message being handled: %w", err)
	}
	defer c.unlock()
	seq, err := c.Announce(ctx, host)
	if err != nil {
		return ForgetResult{}, fmt.Errorf("announce the forgotten host: %w", err)
	}
	existed, err := c.forget(ctx, host, Mark{Seq: seq, Stream: stream})
	if err != nil {
		return ForgetResult{}, fmt.Errorf("forget %s (announced at stream seq %d; the consumer will apply it, or run it again): %w", host, seq, err)
	}
	slog.Info("host forgotten", "host", host, "existed", existed, "stream_seq", seq)
	return ForgetResult{Host: host, Existed: existed, StreamSeq: seq}, nil
}

func (c *Consumer) forget(ctx context.Context, host string, mark Mark) (bool, error) {
	existed, err := c.Store.Forget(ctx, host, mark)
	if err != nil {
		return false, err
	}
	if c.Liveness != nil {
		c.liveMu.Lock()
		c.Liveness.Forget(host)
		c.liveMu.Unlock()
	}
	return existed, nil
}

// applyForgotten handles the inventory's own announcement from the stream: it applies a
// forget whose database step failed (or that another process announced), and is a no-op
// for one already applied.
func (c *Consumer) applyForgotten(ctx context.Context, host string, data []byte, seq uint64) error {
	var ev asmv1.HostForgotten
	if err := proto.Unmarshal(data, &ev); err != nil {
		return svc.Permanent(fmt.Errorf("decode: %w", err))
	}
	if ev.GetHostId() != host {
		return svc.Permanent(fmt.Errorf("host_id %q differs from the subject's host", ev.GetHostId()))
	}
	if mark, ok, err := c.mark(ctx, host); err != nil || (ok && mark.Seq >= seq) {
		return err
	}
	if _, err := c.forget(ctx, host, Mark{Seq: seq, Stream: c.streamID()}); err != nil {
		return err
	}
	slog.Info("host forgotten (applied from the stream)", "host", host, "stream_seq", seq)
	return nil
}

// mark returns a host's forget mark when it belongs to this stream.
func (c *Consumer) mark(ctx context.Context, host string) (Mark, bool, error) {
	mark, ok, err := c.Store.ForgottenMark(ctx, host)
	if err != nil || !ok {
		return Mark{}, false, err
	}
	if !mark.Stream.Equal(c.streamID()) {
		return Mark{}, false, nil // another stream's: its sequences mean nothing here
	}
	return mark, true, nil
}

// staleVerdict reports whether a backend event (a cloud or verifier verdict) concerns a
// forgotten host: stored before its announcement, or after it while the host has not come
// back (a look-up or probe started before the forget). Backend events are only ever about
// hosts the inventory holds, so neither may recreate one.
func (c *Consumer) staleVerdict(ctx context.Context, host string, streamSeq uint64) (bool, error) {
	mark, ok, err := c.mark(ctx, host)
	if err != nil || !ok {
		return false, err
	}
	if streamSeq != 0 && streamSeq < mark.Seq {
		return true, nil
	}
	if _, known, err := c.Store.Cursor(ctx, host); err != nil || known {
		return false, err
	}
	slog.Info("inventory: skipping a verdict for a forgotten host that has not come back", "host", host, "stream_seq", streamSeq)
	return true, nil
}

// leftover reports whether a message stored at streamSeq predates the host's forget mark
// (0, a message without stream metadata, is never a leftover).
func (c *Consumer) leftover(ctx context.Context, host string, streamSeq uint64) (bool, error) {
	if streamSeq == 0 {
		return false, nil
	}
	mark, ok, err := c.mark(ctx, host)
	if err != nil || !ok {
		return false, err
	}
	if streamSeq < mark.Seq {
		slog.Info("inventory: skipping a message stored before the host was forgotten", "host", host, "stream_seq", streamSeq, "forgotten_at_seq", mark.Seq)
		return true, nil
	}
	return false, nil
}
