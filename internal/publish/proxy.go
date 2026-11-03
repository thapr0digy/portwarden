package publish

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
)

func proxyToProto(p model.ProxyInstance) *asmv1.Proxy {
	out := &asmv1.Proxy{
		Id: p.ID, Kind: p.Kind, Processes: processesToProto(p.Procs),
		ConfigPath: p.ConfigPath, ConfigFiles: p.Files, Notes: p.Notes,
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
