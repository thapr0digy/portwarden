package inventory

import (
	"context"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/model"
)

// Caps on one probe request.
const (
	MaxProbeAddresses = 4
	MaxProbePorts     = 4
)

// ProbeRequester asks the verifier to probe listeners (pwb.probe.<host>.request). The
// addresses and ports come from the inventory's stored state for the listener and its
// host, read when the request is built, never from the event that triggered it. Work is
// queued in a bounded channel; when it is full a request is dropped and counted (the next
// change or the periodic reprobe asks again).
type ProbeRequester struct {
	State   ProbeState
	Publish PublishFunc
	// Reprobe: listeners not probed for this long are requested again (default 24 h),
	// checked every Sweep (default 10 min), at most SweepLimit per sweep (default 200).
	Reprobe, Sweep time.Duration
	SweepLimit     int
	Now            func() time.Time

	queue   chan probeWork
	Dropped atomic.Uint64
}

type probeWork struct{ host, key, reason string }

// NewProbeRequester returns a requester with a 1000-entry queue.
func NewProbeRequester(state ProbeState, publish PublishFunc) *ProbeRequester {
	return &ProbeRequester{State: state, Publish: publish, Reprobe: 24 * time.Hour, Sweep: 10 * time.Minute, SweepLimit: 200,
		queue: make(chan probeWork, 1000)}
}

// Notify queues a request for one listener (Consumer.Exposed). It never blocks.
func (r *ProbeRequester) Notify(host, key string) { r.enqueue(probeWork{host, key, "exposure"}) }

func (r *ProbeRequester) enqueue(w probeWork) {
	select {
	case r.queue <- w:
	default:
		if n := r.Dropped.Add(1); n == 1 || n%100 == 0 {
			slog.Warn("probe request queue full; request dropped", "host", w.host, "listener", w.key, "dropped_total", n)
		}
	}
}

// Run sends queued requests and sweeps for reprobes until ctx ends.
func (r *ProbeRequester) Run(ctx context.Context) {
	sweep := time.NewTicker(r.Sweep)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case w := <-r.queue:
			if err := r.Request(ctx, w.host, w.key, w.reason); err != nil && ctx.Err() == nil {
				slog.Warn("probe request failed", "host", w.host, "listener", w.key, "err", err)
			}
		case <-sweep.C:
			due, err := r.State.StaleProbes(ctx, r.now().Add(-r.Reprobe), r.SweepLimit)
			if err != nil {
				slog.Warn("reprobe sweep failed", "err", err)
				continue
			}
			for _, hk := range due {
				r.enqueue(probeWork{hk.Host, hk.Key, "reprobe"})
			}
		}
	}
}

// Request builds and publishes one request from stored state; a listener gone, or below
// bound, is skipped.
func (r *ProbeRequester) Request(ctx context.Context, host, key, reason string) error {
	in, ok, err := r.State.ProbeInput(ctx, host, key)
	if err != nil || !ok {
		return err
	}
	req := BuildProbeRequest(host, in, reason, r.now())
	if req == nil {
		return nil
	}
	return r.Publish(ctx, bus.ProbeSubject(host), req.GetEventId(), req)
}

func (r *ProbeRequester) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

var dnatRe = regexp.MustCompile(`^nat: dnat (tcp|udp)/(\d+) -> `)

// agentEvidenceV6Only is the agent's evidence for a v6-only [::] listener.
const agentEvidenceV6Only = model.EvidenceV6Only

// BuildProbeRequest turns stored state into a request: the bind address when it is a
// specific non-loopback one, else the host's stored inbound candidates of the bind's
// family (0.0.0.0: IPv4; ::, both, or IPv6 alone for a v6-only socket); the listener's port, or a mapped container listener's
// host ports. At most MaxProbeAddresses and MaxProbePorts. Nil below level bound.
func BuildProbeRequest(host string, in ProbeInput, reason string, now time.Time) *asmv1.ProbeRequest {
	if in.Level < 2 {
		return nil
	}
	bind, err := netip.ParseAddr(in.Addr)
	if err != nil || bind.Unmap().IsLoopback() {
		return nil
	}
	bind = bind.Unmap()
	var addrs []string
	if bind.IsUnspecified() {
		// The agent marks a [::] socket with IPV6_V6ONLY (M9): it takes no IPv4.
		v6only := bind.Is6() && slices.Contains(in.AgentEvidence, agentEvidenceV6Only)
		for _, s := range in.InboundIPs {
			a, err := netip.ParseAddr(s)
			if err != nil || (bind.Is4() && !a.Unmap().Is4()) || (v6only && a.Unmap().Is4()) {
				continue
			}
			if v := a.Unmap().String(); !slices.Contains(addrs, v) {
				addrs = append(addrs, v)
			}
		}
	} else {
		addrs = []string{bind.String()}
	}
	addrs = addrs[:min(len(addrs), MaxProbeAddresses)]
	proto := in.Proto
	var ports []uint32
	for _, e := range in.AgentEvidence {
		if m := dnatRe.FindStringSubmatch(e); m != nil {
			if n, err := strconv.ParseUint(m[2], 10, 16); err == nil && n > 0 && !slices.Contains(ports, uint32(n)) {
				ports, proto = append(ports, uint32(n)), m[1]
			}
		}
	}
	if len(ports) == 0 {
		ports = []uint32{uint32(in.Port)}
	}
	ports = ports[:min(len(ports), MaxProbePorts)]
	return &asmv1.ProbeRequest{
		EventId: bus.NewEventID(), HostId: host, RequestedAt: timestamppb.New(now),
		Listener: &asmv1.Listener{Netns: in.Netns, Proto: in.Proto, Addr: in.Addr, Port: uint32(in.Port), Key: in.Key},
		Level:    asmv1.ExposureLevel(in.Level), Addresses: addrs, Ports: ports, Proto: proto, Reason: reason,
		// Unspecified binds always also go to the verifier's own per-host list (it adds
		// host_addresses itself).
	}
}
