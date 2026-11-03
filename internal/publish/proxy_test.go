package publish

import (
	"net/netip"
	"testing"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

func testRoutes() model.ProxyRoutes {
	front := model.NewKey(4026531840, "tcp", netip.MustParseAddr("0.0.0.0"), 8080)
	back := model.NewKey(4026531840, "tcp", netip.MustParseAddr("127.0.0.1"), 8000)
	return model.ProxyRoutes{
		Proxy: model.ProxyInstance{
			ID: "nginx/4026531840//etc/nginx/nginx.conf", Kind: "nginx", NetNS: 4026531840,
			Procs:      []model.Process{{PID: 812, Comm: "nginx", Exe: "/usr/sbin/nginx"}},
			Listeners:  []model.ListenerKey{front},
			ConfigPath: "/etc/nginx/nginx.conf", Files: []string{"/etc/nginx/nginx.conf"},
		},
		Routes: []model.ProxyRoute{{
			Listen: []string{"*:8080"}, Frontends: []model.ListenerKey{front},
			ServerNames: []string{"api.example.com"}, Path: "/", Kind: model.RouteProxy,
			Target: "http://app", Upstream: "app", Source: "/etc/nginx/nginx.conf:12",
			Backends: []model.ProxyBackend{{
				Address: "127.0.0.1:8000", Addr: netip.MustParseAddrPort("127.0.0.1:8000"),
				Listener: &back, Procs: []model.Process{{PID: 1033, Comm: "gunicorn"}},
				Config: true, Seen: true, Connections: 7, LastSeen: time.Unix(1700000100, 0),
			}},
		}},
		Trigger: model.ProxyTriggerTraffic,
		At:      time.Unix(1700000200, 0),
	}
}

func TestProxyRoutesEventsAndSnapshots(t *testing.T) {
	port := freePort(t)
	startServer(t, port, t.TempDir())
	p := newPublisher(t, port)

	routes := testRoutes()
	p.ProxyRoutes([]model.ProxyRoutes{routes})
	c := openedChange(8000)
	c.BehindProxy = []model.ProxyRef{{ProxyID: routes.Proxy.ID, Kind: "nginx", Proxy: routes.Proxy.Procs[0],
		Frontends: routes.Proxy.Listeners, ServerNames: []string{"api.example.com"}, Path: "/", Config: true, Seen: true}}
	p.Changes([]state.Change{c})
	p.Snapshot(snapshotOf(22), []model.ProxyRoutes{routes})
	removed := routes
	removed.Removed, removed.Routes, removed.Trigger = true, nil, model.ProxyTriggerStopped
	p.ProxyRoutes([]model.ProxyRoutes{removed})

	msgs := readStream(t, port, 4)
	if msgs[0].subject != "asm."+testHost+".proxy.routes" {
		t.Fatalf("subject %q", msgs[0].subject)
	}
	var ev asmv1.ProxyRoutes
	mustUnmarshal(t, msgs[0].data, &ev)
	b := ev.GetRoutes()[0].GetBackends()[0]
	if ev.Seq != 1 || ev.Trigger != "traffic" || ev.Proxy.GetId() != routes.Proxy.ID || ev.Proxy.GetProcesses()[0].GetPid() != 812 ||
		ev.GetRoutes()[0].GetUpstream() != "app" || ev.GetRoutes()[0].GetFrontends()[0].GetPort() != 8080 ||
		b.GetIp() != "127.0.0.1" || b.GetPort() != 8000 || b.GetListener().GetKey() != "4026531840/tcp/127.0.0.1:8000" ||
		b.GetProcesses()[0].GetPid() != 1033 || !b.GetConfig() || !b.GetSeen() || b.GetConnections() != 7 ||
		b.GetLastSeen().AsTime().Unix() != 1700000100 || ev.ObservedAt.AsTime().Unix() != 1700000200 {
		t.Fatalf("proxy.routes = %v", &ev)
	}
	var le asmv1.ListenerEvent
	mustUnmarshal(t, msgs[1].data, &le)
	if len(le.BehindProxy) != 1 || le.BehindProxy[0].GetProxy().GetPid() != 812 || !le.BehindProxy[0].GetSeen() ||
		le.BehindProxy[0].GetFrontends()[0].GetPort() != 8080 {
		t.Fatalf("listener event behind_proxy = %v", le.BehindProxy)
	}
	var s asmv1.Snapshot
	mustUnmarshal(t, msgs[2].data, &s)
	if len(s.Proxies) != 1 || s.Proxies[0].GetProxy().GetKind() != "nginx" || len(s.Proxies[0].GetRoutes()) != 1 {
		t.Fatalf("snapshot proxies = %v", s.Proxies)
	}
	var gone asmv1.ProxyRoutes
	mustUnmarshal(t, msgs[3].data, &gone)
	if !gone.Removed || gone.Trigger != "stopped" || len(gone.Routes) != 0 {
		t.Fatalf("removed = %v", &gone)
	}
	p.mu.Lock()
	left := len(p.proxies)
	p.mu.Unlock()
	if left != 0 {
		t.Fatalf("a removed proxy stays in the resnapshot state")
	}
}
