// Package publish sends listener events to NATS JetStream.
//
// Changes and Snapshot only enqueue; one sender goroutine does all network I/O, so the
// caller (the agent loop draining the kernel ring buffer) never waits on the network.
package publish

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/listener-watch/gen/asm/v1"
	"github.com/thapr0digy/listener-watch/internal/model"
	"github.com/thapr0digy/listener-watch/internal/state"
)

const (
	streamName       = "ASM_EVENTS"
	defaultQueueMax  = 10_000
	publishTimeout   = 2 * time.Second
	closeFlushWindow = 2 * time.Second
	dedupeWindow     = 2 * time.Minute
	streamMaxAge     = 7 * 24 * time.Hour
)

// reconnectWait is the delay between connection attempts and between send retries.
// A variable so tests can shorten it.
var reconnectWait = time.Second

// Config configures a Publisher. Zero QueueMax means 10 000.
type Config struct {
	URL, CredsFile, CAFile, CertFile, KeyFile string
	HostID                                    string
	QueueMax                                  int
}

// Publisher implements agent.Sink on top of a JetStream stream.
type Publisher struct {
	hostID string
	runID  string
	nc     *nats.Conn
	js     jetstream.JetStream
	q      *queue

	mu       sync.Mutex // orders seq assignment with queue.push
	seq      uint64
	current  map[model.ListenerKey]state.Listener // listeners as of the last enqueued message
	haveSnap bool

	perms permTracker

	reconnected atomic.Bool
	wake        chan struct{}
	stop        chan struct{}
	stopOnce    sync.Once
	done        chan struct{}
}

// New connects to NATS and starts the sender. NATS being unreachable is not an error:
// the sender connects, ensures the stream and drains the queue once it is up.
// New fails only on bad configuration.
func New(ctx context.Context, cfg Config) (*Publisher, error) {
	if cfg.URL == "" || cfg.HostID == "" {
		return nil, errors.New("publish: URL and HostID are required")
	}
	if cfg.QueueMax <= 0 {
		cfg.QueueMax = defaultQueueMax
	}
	for _, f := range []string{cfg.CredsFile, cfg.CAFile, cfg.CertFile, cfg.KeyFile} {
		if err := readable(f); err != nil {
			return nil, err
		}
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("publish: CertFile and KeyFile must be set together")
	}

	p := &Publisher{
		hostID:  cfg.HostID,
		current: make(map[model.ListenerKey]state.Listener),
		runID:   ulid.Make().String(),
		q:       newQueue(cfg.QueueMax),
		wake:    make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	opts := []nats.Option{
		nats.Name("listener-watch"),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		// Turn off nats.go's own reconnect buffer so the bounded queue is the only
		// buffer and its drop counter is true.
		nats.ReconnectBufSize(-1),
		nats.ReconnectWait(reconnectWait),
		nats.ReconnectHandler(func(*nats.Conn) {
			p.reconnected.Store(true)
			p.signal()
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrPermissionViolation) {
				p.perms.record(err)
				return
			}
			slog.Warn("nats async error", "err", err)
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Warn("nats disconnected", "err", err)
		}),
	}
	if cfg.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.CredsFile))
	}
	if cfg.CAFile != "" {
		opts = append(opts, nats.RootCAs(cfg.CAFile))
	}
	if cfg.CertFile != "" {
		opts = append(opts, nats.ClientCert(cfg.CertFile, cfg.KeyFile))
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("publish: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("publish: jetstream: %w", err)
	}
	p.nc, p.js = nc, js

	go p.run()
	go func() {
		select {
		case <-ctx.Done():
			p.shutdown()
		case <-p.stop:
		}
	}()
	return p, nil
}

func readable(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return f.Close()
}

// Changes enqueues one event per change. It never blocks.
func (p *Publisher) Changes(changes []state.Change) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range changes {
		p.applyLocked(c)
		p.enqueueChange(c)
	}
}

// Snapshot enqueues the full listener set and remembers it for resending after a reconnect.
func (p *Publisher) Snapshot(listeners []state.Listener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = make(map[model.ListenerKey]state.Listener, len(listeners))
	for _, l := range listeners {
		p.current[l.Key] = copyListener(l)
	}
	p.haveSnap = true
	p.enqueueSnapshot(listeners)
}

// Heartbeat enqueues a liveness message carrying the drop counters.
func (p *Publisher) Heartbeat(ringbufDrops, foreignNetns uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, seq := p.nextIDLocked()
	p.enqueueLocked("heartbeat", id, seq, &asmv1.Heartbeat{
		EventId:             id,
		HostId:              p.hostID,
		RunId:               p.runID,
		Seq:                 seq,
		At:                  timestamppb.Now(),
		RingbufDrops:        ringbufDrops,
		QueueDrops:          p.q.Dropped(),
		DroppedForeignNetns: foreignNetns,
	})
}

// Close flushes what it can within a short window, then disconnects.
// Messages still queued after that are lost.
func (p *Publisher) Close() error {
	p.shutdown()
	<-p.done
	p.nc.Close()
	return nil
}

func (p *Publisher) shutdown() { p.stopOnce.Do(func() { close(p.stop) }) }

func (p *Publisher) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *Publisher) nextIDLocked() (string, uint64) {
	p.seq++
	return ulid.Make().String(), p.seq
}

func (p *Publisher) enqueueChange(c state.Change) {
	id, seq := p.nextIDLocked()
	kind, suffix := asmv1.Kind_OPENED, "listener.opened"
	if c.Kind == model.Closed {
		kind, suffix = asmv1.Kind_CLOSED, "listener.closed"
	}
	at := c.At
	if at.IsZero() {
		at = time.Now()
	}
	p.enqueueLocked(suffix, id, seq, &asmv1.ListenerEvent{
		EventId:    id,
		HostId:     p.hostID,
		RunId:      p.runID,
		Seq:        seq,
		ObservedAt: timestamppb.New(at),
		Kind:       kind,
		Source:     sourceToProto(c.Source),
		Listener:   listenerToProto(c.Key),
		Processes:  processesToProto(c.Procs),
	})
}

func (p *Publisher) enqueueSnapshot(listeners []state.Listener) {
	id, seq := p.nextIDLocked()
	states := make([]*asmv1.ListenerState, 0, len(listeners))
	for _, l := range listeners {
		states = append(states, &asmv1.ListenerState{
			Listener:  listenerToProto(l.Key),
			Processes: processesToProto(l.Procs),
		})
	}
	p.enqueueLocked("snapshot", id, seq, &asmv1.Snapshot{
		EventId:   id,
		HostId:    p.hostID,
		RunId:     p.runID,
		Seq:       seq,
		TakenAt:   timestamppb.Now(),
		Listeners: states,
	})
}

func (p *Publisher) enqueueLocked(suffix, id string, seq uint64, msg proto.Message) {
	data, err := proto.Marshal(msg)
	if err != nil {
		// Marshalling our own well-formed messages cannot fail; surface it if it does.
		slog.Error("marshal event", "subject", suffix, "err", err)
		return
	}
	p.q.push(outMsg{subject: "asm." + p.hostID + "." + suffix, id: id, seq: seq, data: data})
}

// applyLocked folds a change into the current listener set.
func (p *Publisher) applyLocked(c state.Change) {
	if c.Kind == model.Closed {
		delete(p.current, c.Key)
		return
	}
	p.current[c.Key] = copyListener(state.Listener{Key: c.Key, Procs: c.Procs})
}

func copyListener(l state.Listener) state.Listener {
	return state.Listener{Key: l.Key, Procs: slices.Clone(l.Procs)}
}

// resnapshot queues a snapshot of the current listener set (the last snapshot plus every
// change since) after a reconnect, so a consumer that missed events while the link was
// down can resynchronise without a stale snapshot undoing a later change.
func (p *Publisher) resnapshot() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.haveSnap {
		return
	}
	listeners := make([]state.Listener, 0, len(p.current))
	for _, l := range p.current {
		listeners = append(listeners, l)
	}
	slices.SortFunc(listeners, func(a, b state.Listener) int {
		return strings.Compare(a.Key.String(), b.Key.String())
	})
	p.enqueueSnapshot(listeners)
}

// run is the single sender goroutine. A message that fails stays at the head and is
// retried with the same event_id and seq; JetStream dedupes on Nats-Msg-Id.
func (p *Publisher) run() {
	defer close(p.done)
	streamReady := false
	var flushEnd time.Time
	failing := false

	for {
		stopping := isClosed(p.stop)
		if stopping && flushEnd.IsZero() {
			flushEnd = time.Now().Add(closeFlushWindow)
		}
		if stopping && time.Now().After(flushEnd) {
			return
		}
		if p.reconnected.Swap(false) {
			streamReady = false
			p.resnapshot()
		}
		m, ok := p.q.head()
		if !ok {
			if stopping {
				return
			}
			select {
			case <-p.q.ready:
			case <-p.wake:
			case <-p.stop:
			}
			continue
		}

		err := p.sendOne(m, &streamReady)
		var perm *permanentError
		if errors.As(err, &perm) {
			slog.Error("dropping message that can never be published",
				"subject", m.subject, "seq", m.seq, "event_id", m.id, "err", perm.err)
			p.q.discard(m.seq)
			continue
		}
		if err == nil {
			p.q.pop(m.seq)
			if failing {
				slog.Info("nats publishing resumed")
				failing = false
			}
			continue
		}
		if stopping {
			return
		}
		if !failing {
			slog.Warn("nats publish failed, will retry", "err", err)
			failing = true
		}
		select {
		case <-time.After(reconnectWait):
		case <-p.wake:
		case <-p.stop:
		}
	}
}

func (p *Publisher) sendOne(m outMsg, streamReady *bool) error {
	if !p.nc.IsConnected() {
		return nats.ErrDisconnected
	}
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	if !*streamReady {
		mark := p.perms.count()
		if err := p.ensureStream(ctx); err != nil {
			if !p.ensureRefused(err, mark) {
				return fmt.Errorf("ensure stream: %w", err)
			}
			slog.Error("cannot create or update stream; assuming an operator manages it",
				"stream", streamName, "err", err)
		}
		*streamReady = true
	}
	mark := p.perms.count()
	msg := &nats.Msg{Subject: m.subject, Data: m.data}
	if _, err := p.js.PublishMsg(ctx, msg, jetstream.WithMsgID(m.id)); err != nil {
		err = fmt.Errorf("publish %s: %w", m.subject, err)
		if errors.Is(err, jetstream.ErrNoStreamResponse) {
			*streamReady = false // stream vanished; re-ensure before the retry
		}
		if p.publishNeverSucceeds(err, m.subject, mark) {
			return &permanentError{err}
		}
		return err
	}
	return nil
}

// permanentError marks a failure that retrying cannot fix.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// publishNeverSucceeds reports whether err means this exact message can never be
// accepted (too large, bad subject, not permitted, over the stream's message limit).
// Timeouts, no responders and disconnects are transient and return false.
func (p *Publisher) publishNeverSucceeds(err error, subject string, permMark uint64) bool {
	if errors.Is(err, nats.ErrMaxPayload) || errors.Is(err, nats.ErrBadSubject) {
		return true
	}
	var api *jetstream.APIError
	if errors.As(err, &api) && api.ErrorCode == jetstream.JSErrCodeStreamMessageExceedsMaximum {
		return true
	}
	// The server reports a denied publish only through an async -ERR; the request itself
	// then just times out.
	return p.perms.denied(permMark, subject)
}

// ensureRefused reports whether a stream ensure failed in a way that retrying cannot fix:
// the user may not manage streams, or the existing stream's config is incompatible.
// Every other error (no leader, insufficient resources, timeouts) is transient.
func (p *Publisher) ensureRefused(err error, permMark uint64) bool {
	return configRefused(err) || p.perms.denied(permMark, "$JS.API.STREAM.")
}

// Error codes from nats-server v2.15.2 server/jetstream_errors_generated.go.
const (
	jsStreamInvalidConfig  jetstream.ErrorCode = 10052 // JSStreamInvalidConfigF
	jsStreamSubjectOverlap jetstream.ErrorCode = 10065 // JSStreamSubjectOverlapErr
	httpForbidden                              = 403
)

// configRefused reports whether err is the server refusing our stream definition for
// good: an existing stream with a different configuration (JSErrCodeStreamNameInUse),
// an invalid or overlapping configuration, or an explicit authorization failure.
func configRefused(err error) bool {
	var api *jetstream.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode {
	case jetstream.JSErrCodeStreamNameInUse, jsStreamInvalidConfig, jsStreamSubjectOverlap:
		return true
	}
	return api.Code == httpForbidden
}

// permTracker remembers permission violations that the server reports asynchronously.
type permTracker struct {
	mu   sync.Mutex
	n    uint64
	errs []string
}

func (t *permTracker) record(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n++
	t.errs = append(t.errs, err.Error())
	if len(t.errs) > 16 {
		t.errs = t.errs[1:]
	}
}

func (t *permTracker) count() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// denied reports whether a violation mentioning subject was recorded after mark.
func (t *permTracker) denied(mark uint64, subject string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	fresh := int(t.n - mark)
	if fresh > len(t.errs) {
		fresh = len(t.errs)
	}
	for _, e := range t.errs[len(t.errs)-fresh:] {
		if strings.Contains(e, subject) {
			return true
		}
	}
	return false
}

func (p *Publisher) ensureStream(ctx context.Context) error {
	_, err := p.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       streamName,
		Subjects:   []string{"asm.>"},
		Storage:    jetstream.FileStorage,
		MaxAge:     streamMaxAge,
		Duplicates: dedupeWindow,
	})
	return err
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func sourceToProto(s model.Source) asmv1.Source {
	if s == model.SourceBaseline {
		return asmv1.Source_BASELINE
	}
	return asmv1.Source_EBPF
}

func listenerToProto(k model.ListenerKey) *asmv1.Listener {
	return &asmv1.Listener{
		Netns: k.NetNS,
		Proto: k.Proto,
		Addr:  k.Addr.String(),
		Port:  uint32(k.Port),
		Key:   k.String(),
	}
}

func processesToProto(procs []model.Process) []*asmv1.Process {
	out := make([]*asmv1.Process, 0, len(procs))
	for _, p := range procs {
		out = append(out, &asmv1.Process{Pid: p.PID, Uid: p.UID, Comm: p.Comm, Exe: p.Exe})
	}
	return out
}
