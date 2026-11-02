// Package publish sends listener events to NATS JetStream.
//
// Changes and Snapshot only enqueue; one sender goroutine does all network I/O, so the
// caller (the agent loop draining the kernel ring buffer) never waits on the network.
// The queue is a spool (internal/spool): on disk when Config.SpoolDir is set, so
// messages not yet sent survive a restart and go out, with their original run_id and
// seq, before the new run's own.
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

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/spool"
	"github.com/thapr0digy/portwarden/internal/state"
)

const (
	streamName      = "ASM_EVENTS"
	defaultSpoolMax = 64 << 20
	// spoolSegmentBytes is the spool's segment size; a smaller SpoolMax caps it, so
	// the oldest segment can always be evicted to stay under the limit.
	spoolSegmentBytes = 4 << 20
	publishTimeout    = 2 * time.Second
	closeFlushWindow  = 2 * time.Second
	dedupeWindow      = 2 * time.Minute
	streamMaxAge      = 7 * 24 * time.Hour
)

// reconnectWait is the delay between connection attempts and between send retries.
// A variable so tests can shorten it.
var reconnectWait = time.Second

// Config configures a Publisher. SpoolDir "" keeps unsent messages in memory only,
// where SpoolMax counts each message as 1 KiB. Zero SpoolMax means 64 MiB.
type Config struct {
	URL, CredsFile, CAFile, CertFile, KeyFile string
	HostID                                    string
	SpoolDir                                  string
	SpoolMax                                  int64
}

// Publisher implements agent.Sink on top of a JetStream stream.
type Publisher struct {
	hostID string
	runID  string
	nc     *nats.Conn
	js     jetstream.JetStream
	q      *spool.Spool

	mu       sync.Mutex // orders seq assignment with q.Push
	seq      uint64
	current  map[model.ListenerKey]state.Listener // listeners as of the last enqueued message
	haveSnap bool
	// snapOverflowMark is q.Overflowed() just after the last snapshot was queued. A
	// higher count means a snapshot or change after it was lost to overflow.
	snapOverflowMark uint64

	// usingExistingLogged is touched only by the sender goroutine.
	usingExistingLogged bool

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
	if strings.ContainsAny(cfg.HostID, ".*> \t\r\n") {
		return nil, fmt.Errorf("publish: HostID %q is not a single subject token", cfg.HostID)
	}
	if cfg.SpoolMax < 0 {
		return nil, fmt.Errorf("publish: SpoolMax %d is negative", cfg.SpoolMax)
	}
	if cfg.SpoolMax == 0 {
		cfg.SpoolMax = defaultSpoolMax
	}
	for _, f := range []string{cfg.CredsFile, cfg.CAFile, cfg.CertFile, cfg.KeyFile} {
		if err := readable(f); err != nil {
			return nil, err
		}
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("publish: CertFile and KeyFile must be set together")
	}
	q, err := spool.Open(cfg.SpoolDir, cfg.SpoolMax, min(spoolSegmentBytes, cfg.SpoolMax))
	if err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}

	p := &Publisher{
		hostID:  cfg.HostID,
		current: make(map[model.ListenerKey]state.Listener),
		runID:   ulid.Make().String(),
		q:       q,
		wake:    make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	opts := []nats.Option{
		nats.Name("portwarden"),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		// Turn off nats.go's own reconnect buffer so the spool is the only buffer and
		// its drop counter is true.
		nats.ReconnectBufSize(-1),
		nats.ReconnectWait(reconnectWait),
		// Reply inboxes (request replies and JetStream publish acks) live under
		// _INBOX_<host>.>, so a host user's subscribe permission can be limited to its
		// own inboxes instead of _INBOX.>, which would let it read every consumer's
		// deliveries.
		nats.CustomInboxPrefix(InboxPrefix(cfg.HostID)),
		// With RetryOnFailedConnect the first successful connect runs ConnectedCB,
		// later ones ReconnectedCB.
		nats.ConnectHandler(func(*nats.Conn) { p.signal() }),
		nats.ReconnectHandler(func(*nats.Conn) {
			p.reconnected.Store(true)
			p.signal()
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrPermissionViolation) {
				if !p.perms.record(err) {
					slog.Warn("nats permission violation", "subject", violationSubject(err), "err", err)
				}
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
		_ = q.Close()
		return nil, fmt.Errorf("publish: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		_ = q.Close()
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

// InboxPrefix is the reply-inbox prefix the agent uses for hostID: _INBOX_<hostID>.
func InboxPrefix(hostID string) string { return "_INBOX_" + hostID }

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

// Heartbeat enqueues a liveness message carrying the ring buffer's and the spool's
// drop counters. dropped_foreign_netns is deprecated and always 0.
func (p *Publisher) Heartbeat(ringbufDrops uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, seq := p.nextIDLocked()
	p.enqueueLocked("heartbeat", id, seq, &asmv1.Heartbeat{
		EventId:      id,
		HostId:       p.hostID,
		RunId:        p.runID,
		Seq:          seq,
		At:           timestamppb.Now(),
		RingbufDrops: ringbufDrops,
		QueueDrops:   p.q.Dropped(),
	})
}

// Close flushes what it can within a short window, then disconnects. Messages still
// queued after that stay in the spool directory for the next run, or are lost in
// memory mode.
func (p *Publisher) Close() error {
	p.shutdown()
	<-p.done
	p.nc.Close()
	if err := p.q.Close(); err != nil {
		return fmt.Errorf("publish: close spool: %w", err)
	}
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
	var previous []*asmv1.Process
	switch c.Kind {
	case model.Closed:
		kind, suffix = asmv1.Kind_CLOSED, "listener.closed"
	case model.OwnerChanged:
		kind, suffix = asmv1.Kind_OWNER_CHANGED, "listener.owner_changed"
		previous = processesToProto(c.PrevProcs)
	}
	at := c.At
	if at.IsZero() {
		at = time.Now()
	}
	p.enqueueLocked(suffix, id, seq, &asmv1.ListenerEvent{
		EventId:           id,
		HostId:            p.hostID,
		RunId:             p.runID,
		Seq:               seq,
		ObservedAt:        timestamppb.New(at),
		Kind:              kind,
		Source:            sourceToProto(c.Source),
		Listener:          listenerToProto(c.Key),
		Processes:         processesToProto(c.Procs),
		PreviousProcesses: previous,
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
	// Read after the push: a drop the push itself caused is older than this snapshot.
	p.snapOverflowMark = p.q.Overflowed()
}

func (p *Publisher) enqueueLocked(suffix, id string, seq uint64, msg proto.Message) {
	data, err := proto.Marshal(msg)
	if err != nil {
		// Marshalling our own well-formed messages cannot fail; surface it if it does.
		slog.Error("marshal event", "subject", suffix, "err", err)
		return
	}
	p.q.Push(spool.Msg{Subject: "asm." + p.hostID + "." + suffix, ID: id, Seq: seq, Data: data})
}

// applyLocked folds a change into the current listener set; an OwnerChanged replaces
// the listener's processes, so a later resnapshot shows the new owners.
func (p *Publisher) applyLocked(c state.Change) {
	switch c.Kind {
	case model.Closed:
		delete(p.current, c.Key)
	case model.Opened, model.OwnerChanged:
		p.current[c.Key] = copyListener(state.Listener{Key: c.Key, Procs: c.Procs})
	}
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
	if p.haveSnap {
		p.resnapshotLocked()
	}
}

// resnapshotAfterOverflow queues a resnapshot when messages queued after the last
// snapshot (or that snapshot itself) were dropped for overflow, once the queue has
// drained; queuing the snapshot moves the mark, so one drop episode yields one
// snapshot.
func (p *Publisher) resnapshotAfterOverflow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Every push holds p.mu, so the queue is still empty here only if no message was
	// queued since the caller looked.
	if !p.haveSnap || p.q.Len() > 0 || p.q.Overflowed() == p.snapOverflowMark {
		return false
	}
	slog.Info("queue overflowed; queuing a fresh snapshot",
		"dropped_since_last_snapshot", p.q.Overflowed()-p.snapOverflowMark)
	p.resnapshotLocked()
	return true
}

func (p *Publisher) resnapshotLocked() {
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
// retried with the same event_id and seq; JetStream dedupes on Nats-Msg-Id. The loop
// looks at the head before it first waits, so messages a previous run left in the
// spool are sent without waiting for a new Push.
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
		m, ok := p.q.Head()
		if !ok {
			if stopping {
				return
			}
			if p.resnapshotAfterOverflow() {
				continue
			}
			select {
			case <-p.q.Ready():
			case <-p.wake:
			case <-p.stop:
			}
			continue
		}

		err := p.sendOne(m, &streamReady)
		var perm *permanentError
		if errors.As(err, &perm) {
			slog.Error("dropping message that can never be published",
				"subject", m.Subject, "seq", m.Seq, "event_id", m.ID, "err", perm.err)
			p.q.Discard(m.ID)
			continue
		}
		if err == nil {
			p.q.Pop(m.ID)
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

func (p *Publisher) sendOne(m spool.Msg, streamReady *bool) error {
	if !p.nc.IsConnected() {
		return nats.ErrDisconnected
	}
	if !*streamReady {
		// Its own deadline: a denied lookup (host users) times out, and must not use up
		// the publish's time.
		ensureCtx, cancelEnsure := context.WithTimeout(context.Background(), publishTimeout)
		mark := p.perms.expect(streamAPIPrefix)
		err := p.ensureStream(ensureCtx)
		p.perms.expect("")
		cancelEnsure()
		if err != nil {
			if !p.ensureRefused(err, mark) {
				return fmt.Errorf("ensure stream: %w", err)
			}
			slog.Error("cannot look up or create stream; assuming an operator manages it",
				"stream", streamName, "err", err)
		}
		*streamReady = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	mark := p.perms.expect(m.Subject)
	msg := &nats.Msg{Subject: m.Subject, Data: m.Data}
	_, err := p.js.PublishMsg(ctx, msg, jetstream.WithMsgID(m.ID))
	p.perms.expect("")
	if err != nil {
		err = fmt.Errorf("publish %s: %w", m.Subject, err)
		if errors.Is(err, jetstream.ErrNoStreamResponse) {
			*streamReady = false // stream vanished; re-ensure before the retry
		}
		if p.publishNeverSucceeds(err, m.Subject, mark) {
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

const streamAPIPrefix = "$JS.API.STREAM."

// ensureRefused reports whether a stream ensure failed in a way that retrying cannot fix:
// the user may not look up or create streams, or the server refuses the agent's config.
// Every other error (no leader, insufficient resources, timeouts) is transient.
func (p *Publisher) ensureRefused(err error, permMark uint64) bool {
	return configRefused(err) || p.perms.denied(permMark, streamAPIPrefix)
}

// Error codes from nats-server v2.15.2 server/jetstream_errors_generated.go.
const (
	jsStreamInvalidConfig  jetstream.ErrorCode = 10052 // JSStreamInvalidConfigF
	jsStreamSubjectOverlap jetstream.ErrorCode = 10065 // JSStreamSubjectOverlapErr
	httpForbidden                              = 403
)

// configRefused reports whether err is the server refusing our stream definition for
// good: an invalid or overlapping configuration, a name-in-use refusal (ensureStream
// already treats that one as an existing stream), or an explicit authorization failure.
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
	mu      sync.Mutex
	n       uint64
	errs    []string
	pending string // subject (or prefix) of the request in flight; "" when none
}

// expect sets the subject of the request about to be sent ("" when it is done) and
// returns the violation count to pass to denied.
func (t *permTracker) expect(subject string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = subject
	return t.n
}

// record stores a violation and reports whether it concerns the request in flight,
// whose caller reports the failure itself.
func (t *permTracker) record(err error) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n++
	t.errs = append(t.errs, err.Error())
	if len(t.errs) > 16 {
		t.errs = t.errs[1:]
	}
	return t.pending != "" && strings.Contains(err.Error(), t.pending)
}

func (t *permTracker) count() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// violationSubject extracts the quoted subject from a server permissions violation
// ("Permissions Violation for Subscription to \"_INBOX_x.*\""), or "" if there is none.
func violationSubject(err error) string {
	msg := err.Error()
	end := strings.LastIndex(msg, `"`)
	if end <= 0 {
		return ""
	}
	start := strings.LastIndex(msg[:end], `"`)
	if start < 0 {
		return ""
	}
	return msg[start+1 : end]
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

// ensureStream creates ASM_EVENTS with the agent's definition only when it does not
// exist. An existing stream is used as it is: an operator's retention, replicas or limits
// are never changed.
func (p *Publisher) ensureStream(ctx context.Context) error {
	_, err := p.js.Stream(ctx, streamName)
	if err == nil {
		p.logUsingExisting()
		return nil
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return err
	}
	_, err = p.js.CreateStream(ctx, jetstream.StreamConfig{
		Name:       streamName,
		Subjects:   []string{"asm.>"},
		Storage:    jetstream.FileStorage,
		MaxAge:     streamMaxAge,
		Duplicates: dedupeWindow,
	})
	if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
		// Someone else created it between the lookup and the create.
		p.logUsingExisting()
		return nil
	}
	if err == nil {
		slog.Info("created stream", "stream", streamName, "max_age", streamMaxAge)
	}
	return err
}

func (p *Publisher) logUsingExisting() {
	if !p.usingExistingLogged {
		p.usingExistingLogged = true
		slog.Info("using existing stream as-is; its configuration is not changed", "stream", streamName)
	}
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
	switch s {
	case model.SourceBaseline:
		return asmv1.Source_BASELINE
	case model.SourceReconcile:
		return asmv1.Source_RECONCILE
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
		out = append(out, processToProto(p))
	}
	return out
}

func processToProto(p model.Process) *asmv1.Process {
	out := &asmv1.Process{
		Pid: p.PID, Uid: p.UID, Comm: p.Comm, Exe: p.Exe,
		Cmdline: p.Cmdline, Sha256: p.SHA256,
		Unit: p.Unit, SocketUnit: p.SocketUnit, CgroupId: p.CgroupID,
	}
	if p.Container != (model.Container{}) {
		out.Container = &asmv1.Container{Runtime: p.Container.Runtime, Id: p.Container.ID}
	}
	return out
}
