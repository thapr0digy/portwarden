package publish

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"

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

	msgs := readStream(t, port, 5)
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
		b.GetLastSeen().AsTime().Unix() != 1700000100 || ev.ObservedAt.AsTime().Unix() != 1700000200 || ev.Truncated {
		t.Fatalf("proxy.routes = %v", &ev)
	}
	var le asmv1.ListenerEvent
	mustUnmarshal(t, msgs[1].data, &le)
	if len(le.BehindProxy) != 1 || le.BehindProxy[0].GetProxy().GetPid() != 812 || !le.BehindProxy[0].GetSeen() ||
		le.BehindProxy[0].GetFrontends()[0].GetPort() != 8080 {
		t.Fatalf("listener event behind_proxy = %v", le.BehindProxy)
	}
	// The snapshot carries each proxy's count and digest; the route set follows it.
	var s asmv1.Snapshot
	mustUnmarshal(t, msgs[2].data, &s)
	if len(s.Proxies) != 1 || s.Proxies[0].GetProxy().GetKind() != "nginx" || len(s.Proxies[0].GetRoutes()) != 0 ||
		s.Proxies[0].GetRouteCount() != 1 || len(s.Proxies[0].GetRoutesDigest()) != 32 {
		t.Fatalf("snapshot proxies = %v", s.Proxies)
	}
	var follow asmv1.ProxyRoutes
	mustUnmarshal(t, msgs[3].data, &follow)
	if follow.Trigger != "snapshot" || len(follow.Routes) != 1 || follow.Seq != s.Seq+1 {
		t.Fatalf("route set after the snapshot = %v", &follow)
	}
	var gone asmv1.ProxyRoutes
	mustUnmarshal(t, msgs[4].data, &gone)
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

// At a small max_payload a big route set is cut to fit half of it (marked truncated with
// the total), and the snapshot, which carries no routes, still gets through.
func TestProxyRoutesStayUnderMaxPayload(t *testing.T) {
	port := freePort(t)
	const maxPayload = 16 << 10
	startServerWith(t, &server.Options{Port: port, StoreDir: t.TempDir(), MaxPayload: maxPayload})
	p := newPublisher(t, port)
	waitConnected(t, p)
	big := testRoutes()
	for len(big.Routes) < 400 {
		big.Routes = append(big.Routes, big.Routes[0])
	}
	p.ProxyRoutes([]model.ProxyRoutes{big})
	p.Snapshot(snapshotOf(22), []model.ProxyRoutes{big})
	msgs := readStream(t, port, 3)
	var ev, follow asmv1.ProxyRoutes
	mustUnmarshal(t, msgs[0].data, &ev)
	if !ev.Truncated || ev.TotalRoutes != 400 || len(ev.Routes) == 0 || len(ev.Routes) >= 400 || len(msgs[0].data) > maxPayload/2 {
		t.Fatalf("truncated=%v total=%d routes=%d bytes=%d", ev.Truncated, ev.TotalRoutes, len(ev.Routes), len(msgs[0].data))
	}
	var s asmv1.Snapshot
	mustUnmarshal(t, msgs[1].data, &s)
	if len(s.Listeners) != 1 || s.Proxies[0].GetRouteCount() != 400 {
		t.Fatalf("snapshot = %v", &s)
	}
	mustUnmarshal(t, msgs[2].data, &follow)
	if follow.Trigger != "snapshot" || !follow.Truncated {
		t.Fatalf("follow = %v", &follow)
	}
}

func waitConnected(t *testing.T, p *Publisher) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !p.nc.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
