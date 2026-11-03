package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
)

// defaultMaxPayload is NATS's default max_payload, used until the server said its own.
const defaultMaxPayload = 1 << 20

// payloadBudgetLocked is how large one proxy.routes message may be: half the server's
// max_payload, so it never meets the limit and is dropped as unpublishable.
func (p *Publisher) payloadBudgetLocked() int {
	mp := int64(0)
	if p.nc != nil {
		mp = p.nc.MaxPayload()
	}
	if mp <= 0 {
		mp = defaultMaxPayload
	}
	return int(mp / 2)
}

// enqueueProxyRoutesLocked queues one proxy.routes event, cutting its routes (keeping
// the first ones, marked truncated with the total) until it fits the payload budget.
func (p *Publisher) enqueueProxyRoutesLocked(r model.ProxyRoutes) {
	id, seq := p.nextIDLocked()
	at := r.At
	if at.IsZero() {
		at = time.Now()
	}
	total := len(r.Routes)
	if r.Truncated {
		total = r.TotalRoutes
	}
	build := func(n int) *asmv1.ProxyRoutes {
		ev := &asmv1.ProxyRoutes{
			EventId: id, HostId: p.hostID, RunId: p.runID, BootId: p.bootID, RunNumber: p.runNumber, Seq: seq,
			ObservedAt: timestamppb.New(at), Proxy: proxyToProto(r.Proxy),
			Routes: routesToProto(r.Routes[:n]), Trigger: r.Trigger, Removed: r.Removed,
			Host: p.hostProtoLocked(),
		}
		if n < total {
			ev.Truncated, ev.TotalRoutes = true, uint32(total)
		}
		return ev
	}
	budget := p.payloadBudgetLocked()
	n := len(r.Routes)
	ev := build(n)
	for size := proto.Size(ev); size > budget && n > 0; size = proto.Size(ev) {
		n = min(n-1, n*budget/size*9/10)
		ev = build(max(n, 0))
	}
	if size := proto.Size(ev); size > budget {
		slog.Warn("proxy.routes over the payload budget even without routes", "proxy", r.Proxy.ID, "bytes", size, "budget", budget)
	}
	p.enqueueLocked("proxy.routes", id, seq, ev)
}

// proxyStateToProto is a proxy as a snapshot carries it: no routes, their count and
// digest.
func proxyStateToProto(r model.ProxyRoutes) *asmv1.ProxyState {
	routes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&asmv1.ProxyState{Routes: routesToProto(r.Routes)})
	sum := sha256.Sum256(routes)
	count := len(r.Routes)
	if r.Truncated {
		count = r.TotalRoutes
	}
	return &asmv1.ProxyState{Proxy: proxyToProto(r.Proxy), RouteCount: uint32(count),
		RoutesDigest: hex.EncodeToString(sum[:16]), Truncated: r.Truncated}
}

func proxyToProto(p model.ProxyInstance) *asmv1.Proxy {
	out := &asmv1.Proxy{
		Id: p.ID, Kind: p.Kind, Processes: processesToProto(p.Procs),
		ConfigPath: p.ConfigPath, ConfigFiles: p.Files, Notes: p.Notes,
		ProcessCount: uint32(max(p.ProcessCount, len(p.Procs))),
	}
	for _, k := range p.Listeners {
		out.Listeners = append(out.Listeners, listenerToProto(k))
	}
	return out
}

func routesToProto(routes []model.ProxyRoute) []*asmv1.ProxyRoute {
	out := make([]*asmv1.ProxyRoute, 0, len(routes))
	for _, r := range routes {
		pr := &asmv1.ProxyRoute{
			Listen: r.Listen, ServerNames: r.ServerNames, Path: r.Path, Kind: r.Kind,
			Target: r.Target, Upstream: r.Upstream, Root: r.Root, Source: r.Source,
			Inferred: r.Inferred, Notes: r.Notes,
		}
		for _, k := range r.Frontends {
			pr.Frontends = append(pr.Frontends, listenerToProto(k))
		}
		for _, b := range r.Backends {
			pr.Backends = append(pr.Backends, backendToProto(b))
		}
		out = append(out, pr)
	}
	return out
}

func backendToProto(b model.ProxyBackend) *asmv1.ProxyBackend {
	out := &asmv1.ProxyBackend{
		Address: b.Address, UnixPath: b.Unix, Config: b.Config, Seen: b.Seen,
		Connections: b.Connections, Note: b.Note,
	}
	if b.Addr.IsValid() {
		out.Ip, out.Port = b.Addr.Addr().String(), uint32(b.Addr.Port())
	}
	if b.Listener != nil {
		out.Listener = listenerToProto(*b.Listener)
		out.Processes = processesToProto(b.Procs)
	}
	if !b.LastSeen.IsZero() {
		out.LastSeen = timestamppb.New(b.LastSeen)
	}
	return out
}

func proxyRefsToProto(refs []model.ProxyRef) []*asmv1.ProxyRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*asmv1.ProxyRef, 0, len(refs))
	for _, r := range refs {
		pr := &asmv1.ProxyRef{
			ProxyId: r.ProxyID, Kind: r.Kind, Proxy: processToProto(r.Proxy),
			ServerNames: r.ServerNames, Path: r.Path, Config: r.Config, Seen: r.Seen,
		}
		for _, k := range r.Frontends {
			pr.Frontends = append(pr.Frontends, listenerToProto(k))
		}
		out = append(out, pr)
	}
	return out
}
