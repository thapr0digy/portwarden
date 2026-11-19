// Package publish sends listener events to NATS JetStream or, with Config.Ingest, to
// Signal's ingest door over HTTPS (one or the other).
//
// Changes and Snapshot only enqueue; one sender goroutine does all network I/O, so the
// caller (the agent loop draining the kernel ring buffer) never waits on the network.
// The queue is a spool (internal/spool): on disk when Config.SpoolDir is set, so
// messages not yet sent survive a restart and go out, with their original run_id and
// seq, before the new run's own. The spool holds asm.v1 messages under their NATS
// subjects whatever the destination; the HTTPS sender converts them as it sends
// (signalEvent), so a spool written under one destination drains to the other. The host
// facts (HostAccess, SignIns, HostPackages) are the exception: Signal-only, spooled as
// Signal events and dropped by the NATS sender (access.go).
package publish

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/redact"
	"github.com/thapr0digy/portwarden/internal/spool"
	"github.com/thapr0digy/portwarden/internal/state"
)

const (
	defaultSpoolMax = 64 << 20
	// spoolSegmentBytes is the spool's segment size; a smaller SpoolMax caps it, so
	// the oldest segment can always be evicted to stay under the limit.
	spoolSegmentBytes = 4 << 20
	closeFlushWindow  = 2 * time.Second
)

// reconnectWait is the delay between connection attempts and between send retries.
// A variable so tests can shorten it.
var reconnectWait = time.Second

// Config configures a Publisher. SpoolDir "" keeps unsent messages in memory only,
// where SpoolMax counts each message as 1 KiB. Zero SpoolMax means 64 MiB.
//
// The destination is NATS (URL and its credential and TLS files) or, when Ingest is
// set, Signal's ingest door; the NATS fields must then be empty.
type Config struct {
	URL, CredsFile, CAFile, CertFile, KeyFile string
	// NkeyFile is an nkey user seed file (portwarden-natsauth mint), an alternative to
	// CredsFile for servers configured with nkey users.
	NkeyFile string
	HostID   string
	// BootID and RunNumber order this run among the host's runs (see
	// NextRunNumber); stamped on every message.
	BootID    string
	RunNumber uint64
	// AgentVersion and ExeSHA256 are the agent's identity (version.Version and the hex
	// SHA-256 of its executable, "" when unread), stamped on every heartbeat and host
	// block. Fixed for the run.
	AgentVersion string
	ExeSHA256    string
	SpoolDir     string
	SpoolMax     int64
	// LocalAddr, when set, is called with the local address of every TCP connection
	// made to NATS (the agent's own view of its outbound address). It must not block.
	LocalAddr func(netip.Addr)
	// OnDenied, when set, is called (from the sender goroutine) with the subject of a
	// message the server refused for lack of permission, before it is dropped. The agent
	// stops on it: wrong credentials for this host must show as silence, not as a
	// running agent whose messages vanish. It must not block.
	OnDenied func(subject string)
	// Ingest, when set, sends to Signal's ingest door instead of NATS.
	Ingest *IngestConfig
}

// Publisher implements agent.Sink on top of the spool and one transport (NATS or Signal).
type Publisher struct {
	hostID    string
	runID     string
	bootID    string
	runNumber uint64
	// agentVersion and exeSHA256 are Config.AgentVersion and Config.ExeSHA256.
	agentVersion string
	exeSHA256    string
	tr           transport
	q            *spool.Spool

	mu       sync.Mutex // orders seq assignment with q.Push
	seq      uint64
	current  map[model.ListenerKey]state.Listener // listeners as of the last enqueued message
	proxies  map[string]model.ProxyRoutes         // proxy route sets as of the last enqueued message
	haveSnap bool
	// snapOverflowMark is q.Overflowed() just after the last snapshot was queued. A
	// higher count means a snapshot or change after it was lost to overflow.
	snapOverflowMark uint64

	// host is the host block stamped on events and snapshots; hostSet is false until
	// the first SetHost.
	host    model.HostInfo
	hostSet bool

	// firewall is the firewall fingerprint (SetFirewall) stamped on host blocks and
	// heartbeats; nil until the first exposure view.
	firewall *string

	// tamper is the last tamper status (SetTamper), carried on heartbeats; nil until the
	// first pass.
	tamper *asmv1.TamperStatus

	// riders are the last full states queued that ride with the snapshot (HostAccess,
	// HostPackages), by suffix; a kind is absent until its first.
	riders map[string]rider

	onDenied func(subject string)

	wake     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
	// sendCtx bounds the sender's requests: it is cancelled closeFlushWindow after
	// shutdown starts, so Close never waits on a slow destination for longer.
	sendCtx    context.Context
	cancelSend context.CancelFunc
}

// New starts the sender. The destination being unreachable is not an error: the sender
// connects (NATS: and ensures the stream; Signal: and enrols) and drains the queue once it
// is up. New fails only on bad configuration.
func New(ctx context.Context, cfg Config) (*Publisher, error) {
	if cfg.HostID == "" {
		return nil, errors.New("publish: HostID is required")
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
	p := &Publisher{
		hostID:  cfg.HostID,
		current: make(map[model.ListenerKey]state.Listener),
		proxies: make(map[string]model.ProxyRoutes),
		riders:  make(map[string]rider),
		runID:   ulid.Make().String(),
		bootID:  cfg.BootID, runNumber: cfg.RunNumber,
		agentVersion: cfg.AgentVersion, exeSHA256: cfg.ExeSHA256,
		onDenied: cfg.OnDenied,
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	var err error
	switch {
	case cfg.Ingest != nil && (cfg.URL != "" || cfg.CredsFile != "" || cfg.NkeyFile != "" || cfg.CAFile != "" || cfg.CertFile != "" || cfg.KeyFile != ""):
		return nil, errors.New("publish: Ingest excludes the NATS settings")
	case cfg.Ingest != nil:
		p.tr, err = newIngest(cfg)
	case cfg.URL == "":
		return nil, errors.New("publish: URL or Ingest is required")
	default:
		p.tr, err = newNATS(cfg, p.signal)
	}
	if err != nil {
		return nil, err
	}
	// The spool is opened last, so a bad destination setting leaves nothing open.
	if p.q, err = spool.Open(cfg.SpoolDir, cfg.SpoolMax, min(spoolSegmentBytes, cfg.SpoolMax)); err != nil {
		p.tr.close()
		return nil, fmt.Errorf("publish: %w", err)
	}
	p.sendCtx, p.cancelSend = context.WithCancel(context.Background())

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

// Snapshot enqueues the full listener set and every proxy's route set, and remembers
// them for resending after a reconnect.
func (p *Publisher) Snapshot(listeners []state.Listener, proxies []model.ProxyRoutes) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = make(map[model.ListenerKey]state.Listener, len(listeners))
	for _, l := range listeners {
		p.current[l.Key] = copyListener(l)
	}
	p.proxies = make(map[string]model.ProxyRoutes, len(proxies))
	for _, r := range proxies {
		if !r.Removed {
			p.proxies[r.Proxy.ID] = r.Clone()
		}
	}
	p.haveSnap = true
	p.enqueueSnapshot(listeners, p.sortedProxiesLocked())
}

// ProxyRoutes enqueues one proxy.routes event per route set and folds it into the
// current state (a removed proxy leaves it).
func (p *Publisher) ProxyRoutes(sets []model.ProxyRoutes) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range sets {
		if r.Removed {
			delete(p.proxies, r.Proxy.ID)
		} else {
			p.proxies[r.Proxy.ID] = r.Clone()
		}
		p.enqueueProxyRoutesLocked(r)
	}
}

func (p *Publisher) sortedProxiesLocked() []model.ProxyRoutes {
	out := make([]model.ProxyRoutes, 0, len(p.proxies))
	for _, r := range p.proxies {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b model.ProxyRoutes) int { return strings.Compare(a.Proxy.ID, b.Proxy.ID) })
	return out
}

// ExposureChanges enqueues one exposure.changed event per change and folds the new
// exposure into the current listener set (for resnapshots).
func (p *Publisher) ExposureChanges(changes []state.ExposureChange) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range changes {
		if l, ok := p.current[c.Key]; ok {
			l.Exposure = cloneExposure(c.Exposure)
			p.current[c.Key] = l
		}
		id, seq := p.nextIDLocked()
		at := c.At
		if at.IsZero() {
			at = time.Now()
		}
		ev := &asmv1.ExposureEvent{
			EventId: id,
			HostId:  p.hostID,
			RunId:   p.runID, BootId: p.bootID, RunNumber: p.runNumber,
			Seq:        seq,
			ObservedAt: timestamppb.New(at),
			Listener:   listenerToProto(c.Key),
			Processes:  processesToProto(c.Procs),
			Exposure:   exposureToProto(c.Exposure),
			Trigger:    c.Trigger,
			Host:       p.hostProtoLocked(),
		}
		if c.Previous.Level != model.ExposureUnknown {
			ev.Previous = exposureToProto(c.Previous)
		}
		p.enqueueLocked("exposure.changed", id, seq, ev)
	}
}

// SetHost replaces the host block stamped on later events and snapshots. A change
// after the first call is published on host.changed.
func (p *Publisher) SetHost(h model.HostInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hostSet && p.host.Equal(h) {
		return
	}
	prev, wasSet := p.host, p.hostSet
	p.host, p.hostSet = h.Clone(), true
	if !wasSet {
		return
	}
	id, seq := p.nextIDLocked()
	p.enqueueLocked("host.changed", id, seq, &asmv1.HostEvent{
		EventId: id,
		HostId:  p.hostID,
		RunId:   p.runID, BootId: p.bootID, RunNumber: p.runNumber,
		Seq:        seq,
		ObservedAt: timestamppb.Now(),
		Host:       p.hostProtoLocked(),
		Previous:   p.withIdentity(hostToProto(prev)),
	})
}

// Stopping enqueues the run's clean-shutdown marker: a host.changed with stopping set
// and host == previous. The agent calls it on SIGTERM/SIGINT, before Close drains the
// spool; whatever Close cannot send goes out first on the next run, still ahead of that
// run's messages. Never called on an error exit, which consumers see as unclean.
func (p *Publisher) Stopping() {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, seq := p.nextIDLocked()
	p.enqueueLocked("host.changed", id, seq, &asmv1.HostEvent{
		EventId: id,
		HostId:  p.hostID,
		RunId:   p.runID, BootId: p.bootID, RunNumber: p.runNumber,
		Seq:        seq,
		ObservedAt: timestamppb.Now(),
		Host:       p.hostProtoLocked(),
		Previous:   p.hostProtoLocked(),
		Stopping:   true,
	})
}

// SetFirewall replaces the firewall fingerprint (exposure.View.FirewallDigest; "" while
// the firewall cannot be read in full) stamped on later host blocks and heartbeats. A
// change on its own publishes nothing: the next heartbeat carries it, so a busy ruleset
// (a ban list) costs no extra messages and host.changed keeps meaning the host block.
func (p *Publisher) SetFirewall(digest string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.firewall = &digest
}

func (p *Publisher) hostProtoLocked() *asmv1.HostInfo {
	if !p.hostSet {
		return nil
	}
	h := p.withIdentity(hostToProto(p.host))
	h.FirewallFingerprint = p.firewallLocked()
	return h
}

// withIdentity stamps the agent's version and executable hash on a host block.
func (p *Publisher) withIdentity(h *asmv1.HostInfo) *asmv1.HostInfo {
	h.AgentVersion, h.ExeSha256 = p.agentVersion, p.exeSHA256
	return h
}

// firewallLocked is the fingerprint for a message: a copy, nil before the first view.
func (p *Publisher) firewallLocked() *string {
	if p.firewall == nil {
		return nil
	}
	fp := *p.firewall
	return &fp
}

// Heartbeat enqueues a liveness message carrying the ring buffer's and the spool's
// drop counters and the last tamper status. dropped_foreign_netns is deprecated and
// always 0.
func (p *Publisher) Heartbeat(ringbufDrops uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, seq := p.nextIDLocked()
	p.enqueueLocked("heartbeat", id, seq, &asmv1.Heartbeat{
		EventId: id,
		HostId:  p.hostID,
		RunId:   p.runID, BootId: p.bootID, RunNumber: p.runNumber,
		Seq:          seq,
		At:           timestamppb.Now(),
		RingbufDrops: ringbufDrops,
		QueueDrops:   p.q.Dropped(),
		Tamper:       p.tamperLocked(),

		FirewallFingerprint: p.firewallLocked(),
		AgentVersion:        p.agentVersion,
		ExeSha256:           p.exeSHA256,
	})
}

// Close flushes what it can within a short window, then disconnects. Messages still
// queued after that stay in the spool directory for the next run, or are lost in
// memory mode.
func (p *Publisher) Close() error {
	p.shutdown()
	<-p.done
	p.cancelSend()
	p.tr.close()
	if err := p.q.Close(); err != nil {
		return fmt.Errorf("publish: close spool: %w", err)
	}
	return nil
}

func (p *Publisher) shutdown() {
	p.stopOnce.Do(func() {
		close(p.stop)
		time.AfterFunc(closeFlushWindow, p.cancelSend)
	})
}

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
		EventId: id,
		HostId:  p.hostID,
		RunId:   p.runID, BootId: p.bootID, RunNumber: p.runNumber,
		Seq:               seq,
		ObservedAt:        timestamppb.New(at),
		Kind:              kind,
		Source:            sourceToProto(c.Source),
		Listener:          listenerToProto(c.Key),
		Processes:         processesToProto(c.Procs),
		PreviousProcesses: previous,
		Exposure:          exposureToProto(c.Exposure),
		Host:              p.hostProtoLocked(),
		BehindProxy:       proxyRefsToProto(c.BehindProxy),
	})
}

func (p *Publisher) enqueueSnapshot(listeners []state.Listener, proxies []model.ProxyRoutes) {
	id, seq := p.nextIDLocked()
	states := make([]*asmv1.ListenerState, 0, len(listeners))
	for _, l := range listeners {
		states = append(states, &asmv1.ListenerState{
			Listener:    listenerToProto(l.Key),
			Processes:   processesToProto(l.Procs),
			Exposure:    exposureToProto(l.Exposure),
			BehindProxy: proxyRefsToProto(l.BehindProxy),
		})
	}
	// Route sets stay out of the snapshot (it must stay under max_payload whatever the
	// proxies hold): it carries their counts and digests, and each set follows it.
	var proxyStates []*asmv1.ProxyState
	for _, r := range proxies {
		proxyStates = append(proxyStates, proxyStateToProto(r))
	}
	p.enqueueLocked("snapshot", id, seq, &asmv1.Snapshot{
		EventId: id,
		HostId:  p.hostID,
		RunId:   p.runID, BootId: p.bootID, RunNumber: p.runNumber,
		Seq:       seq,
		TakenAt:   timestamppb.Now(),
		Listeners: states,
		Host:      p.hostProtoLocked(),
		Proxies:   proxyStates,
	})
	// Read after the push: a drop the push itself caused is older than this snapshot.
	p.snapOverflowMark = p.q.Overflowed()
	for _, r := range proxies {
		r.Trigger, r.At = model.ProxyTriggerSnapshot, time.Now()
		p.enqueueProxyRoutesLocked(r)
	}
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
		p.current[c.Key] = copyListener(state.Listener{Key: c.Key, Procs: c.Procs, Exposure: c.Exposure, BehindProxy: c.BehindProxy})
	}
}

func copyListener(l state.Listener) state.Listener {
	return state.Listener{Key: l.Key, Procs: slices.Clone(l.Procs), Exposure: cloneExposure(l.Exposure),
		BehindProxy: slices.Clone(l.BehindProxy)}
}

func cloneExposure(e model.Exposure) model.Exposure {
	e.Evidence = slices.Clone(e.Evidence)
	return e
}

// resnapshot queues a snapshot of the current listener set (the last snapshot plus every
// change since) after a reconnect, so a consumer that missed events while the link was
// down can resynchronise without a stale snapshot undoing a later change. The SSH access
// state and the package list go with it: Signal forgets their digests on the same resync.
func (p *Publisher) resnapshot() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.haveSnap {
		p.resnapshotLocked()
	}
	p.enqueueRidersLocked()
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
	p.enqueueSnapshot(listeners, p.sortedProxiesLocked())
}

// transport delivers spooled messages to the destination: NATS JetStream (nats.go) or
// Signal's ingest door (ingest.go). Only the sender goroutine calls deliver and resync.
type transport interface {
	// deliver offers msgs, the oldest queued messages in spool order (within
	// batchLimits), and says what became of them. ctx ends at the close deadline.
	deliver(ctx context.Context, msgs []spool.Msg) delivery
	// batchLimits is how many messages, and how many bytes of their Data, one deliver
	// takes at most.
	batchLimits() (n, bytes int)
	// maxMessage is the largest one message may be; proxy route sets are cut to half.
	maxMessage() int64
	// resync reports, once, that the receiver may have missed messages (a NATS
	// reconnect, Signal's RESYNC_SNAPSHOT), so a fresh snapshot must follow.
	resync() bool
	close()
}

// delivery is the outcome of one deliver.
type delivery struct {
	// sent is how many of the offered messages, from the first, the receiver has: they
	// are popped.
	sent int
	// undeliverable means the message after those can never be delivered: it is
	// dropped, and with denied (refused for lack of permission) OnDenied is called.
	undeliverable, denied bool
	// err says why the rest was not delivered; it is logged once per failing streak.
	err error
	// wait is how long to wait before the next attempt; 0 retries at once after a
	// success and after reconnectWait after a failure.
	wait time.Duration
	// halt stops sending for the rest of the run (Signal's STOP); the spool keeps
	// filling and drains on a later run.
	halt bool
}

// run is the single sender goroutine. Messages a delivery does not take stay at the head
// and are offered again with the same event_id and seq; the destination dedupes them
// (JetStream on Nats-Msg-Id, Signal on the event id and run cursor). The loop looks at the
// head before it first waits, so messages a previous run left in the spool are sent
// without waiting for a new Push.
func (p *Publisher) run() {
	defer close(p.done)
	var flushEnd time.Time
	failing, halted := false, false

	for {
		stopping := isClosed(p.stop)
		if stopping && flushEnd.IsZero() {
			flushEnd = time.Now().Add(closeFlushWindow)
		}
		if stopping && (halted || time.Now().After(flushEnd)) {
			return
		}
		if p.tr.resync() {
			p.resnapshot()
		}
		n, size := p.tr.batchLimits()
		var msgs []spool.Msg
		if !halted {
			msgs = p.q.Peek(n, size)
		}
		if len(msgs) == 0 {
			if stopping {
				return
			}
			if !halted && p.resnapshotAfterOverflow() {
				continue
			}
			select {
			case <-p.q.Ready():
			case <-p.wake:
			case <-p.stop:
			}
			continue
		}

		d := p.tr.deliver(p.sendCtx, msgs)
		for _, m := range msgs[:d.sent] {
			p.q.Pop(m.ID)
		}
		if d.undeliverable {
			m := msgs[d.sent]
			slog.Error("dropping message that can never be published",
				"subject", m.Subject, "seq", m.Seq, "event_id", m.ID, "err", d.err, "permission_denied", d.denied)
			p.q.Discard(m.ID)
			if d.denied && p.onDenied != nil {
				p.onDenied(m.Subject)
			}
			continue
		}
		if d.halt {
			halted = true
			slog.Error("the destination told this agent to stop sending; events are kept in the spool until a restart",
				"err", d.err, "queued", p.q.Len())
			continue
		}
		wait := d.wait
		if d.err == nil {
			if failing {
				slog.Info("publishing resumed")
				failing = false
			}
		} else {
			if !failing {
				slog.Warn("publish failed, will retry", "err", d.err)
				failing = true
			}
			if wait == 0 {
				wait = reconnectWait
			}
		}
		if wait == 0 {
			continue
		}
		if stopping {
			return
		}
		select {
		case <-time.After(wait):
		case <-p.wake:
		case <-p.stop:
		}
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

// exposureToProto converts an exposure; an unjudged one is nil (the field is unset).
func exposureToProto(e model.Exposure) *asmv1.Exposure {
	if e.Level == model.ExposureUnknown {
		return nil
	}
	var level asmv1.ExposureLevel
	switch e.Level {
	case model.ExposureLocal:
		level = asmv1.ExposureLevel_EXPOSURE_LOCAL
	case model.ExposureBound:
		level = asmv1.ExposureLevel_EXPOSURE_BOUND
	case model.ExposureHostFirewallOpen:
		level = asmv1.ExposureLevel_EXPOSURE_HOST_FIREWALL_OPEN
	case model.ExposureCloudOpen:
		level = asmv1.ExposureLevel_EXPOSURE_CLOUD_OPEN
	case model.ExposureConfirmed:
		level = asmv1.ExposureLevel_EXPOSURE_CONFIRMED
	}
	return &asmv1.Exposure{Level: level, Evidence: slices.Clone(e.Evidence)}
}

func hostToProto(h model.HostInfo) *asmv1.HostInfo {
	out := &asmv1.HostInfo{Cloud: h.Cloud, InstanceId: h.InstanceID, Region: h.Region, CloudResource: h.Resource, Conditions: slices.Clone(h.Conditions)}
	for _, ip := range h.PublicIPs {
		out.PublicIps = append(out.PublicIps, &asmv1.PublicIP{Ip: ip.IP.String(), Via: ip.Via, Dir: ip.Dir, Iface: ip.Iface})
	}
	return out
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
		Cmdline: redact.Cmdline(p.Cmdline), Sha256: p.SHA256,
		Unit: p.Unit, SocketUnit: p.SocketUnit, CgroupId: p.CgroupID,
	}
	if p.Container != (model.Container{}) {
		out.Container = &asmv1.Container{Runtime: p.Container.Runtime, Id: p.Container.ID}
	}
	return out
}
