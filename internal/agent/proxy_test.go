package agent

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/state"
)

func (h *harness) proxyRoutes() []model.ProxyRoutes {
	h.t.Helper()
	select {
	case p := <-h.rec.proxies:
		return p
	case <-time.After(5 * time.Second):
		h.t.Fatal("no proxy routes published")
		return nil
	}
}

func loKey(port uint16) model.ListenerKey {
	return model.NewKey(4026531840, "tcp", netip.MustParseAddr("127.0.0.1"), port)
}

func nginxState(at time.Time, trigger string) proxy.State {
	return proxy.State{
		Instance: model.ProxyInstance{ID: "nginx/x", Kind: "nginx", NetNS: 4026531840,
			Procs: []model.Process{{PID: 812, Comm: "nginx"}}, Listeners: []model.ListenerKey{key(8080)}},
		Routes: []conf.Route{{Listen: []string{"*:8080"}, Path: "/", Kind: model.RouteProxy, Target: "http://127.0.0.1:8000",
			Backends: []conf.Backend{{Address: "127.0.0.1:8000", Addrs: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8000")}}}}},
		Trigger: trigger, At: at,
	}
}

func TestProxyRoutesJoinedPublishedAndOnBackendEvents(t *testing.T) {
	updates := make(chan proxy.Update, 4)
	var mu sync.Mutex
	var fed [][]state.Listener
	backend := func(kind model.Kind, cookie uint64, pid uint32) model.Observation {
		return model.Observation{Kind: kind, Cookie: cookie, Key: loKey(8000), At: time.Now(), Source: model.SourceEBPF,
			Proc: model.Process{PID: pid, Comm: "gunicorn"}}
	}
	baseline := []model.Observation{obs(model.Opened, 1, 8080, 812, model.SourceBaseline), backend(model.Opened, 2, 1033)}
	baseline[1].Source = model.SourceBaseline
	h := startWith(t, baseline, nil, Options{
		CloseGrace: time.Hour, Proxies: updates,
		ProxyListeners: func(ls []state.Listener) { mu.Lock(); fed = append(fed, ls); mu.Unlock() },
	})
	close(h.release)
	h.snapshot()
	mu.Lock()
	if len(fed) != 1 || len(fed[0]) != 2 {
		t.Fatalf("mapper fed %v", fed)
	}
	mu.Unlock()

	at := time.Now()
	updates <- proxy.Update{States: []proxy.State{nginxState(at, model.ProxyTriggerStarted)}}
	routes := h.proxyRoutes()
	if len(routes) != 1 || routes[0].Trigger != model.ProxyTriggerStarted {
		t.Fatalf("routes = %+v", routes)
	}
	b := routes[0].Routes[0].Backends[0]
	if b.Listener == nil || *b.Listener != loKey(8000) || b.Procs[0].PID != 1033 || routes[0].Routes[0].Frontends[0] != key(8080) {
		t.Fatalf("backend = %+v", b)
	}
	// The same view again publishes nothing.
	updates <- proxy.Update{States: []proxy.State{nginxState(at, model.ProxyTriggerStarted)}}

	// The backend restarts: its owner_changed names the route, and the route set (whose
	// backend process changed) goes out after it, triggered by the listener.
	h.send(backend(model.Closed, 2, 1033))
	h.send(backend(model.Opened, 3, 2000))
	ch := h.change()
	if len(ch) != 1 || ch[0].Kind != model.OwnerChanged || len(ch[0].BehindProxy) != 1 ||
		ch[0].BehindProxy[0].Proxy.PID != 812 || ch[0].BehindProxy[0].Path != "/" || !ch[0].BehindProxy[0].Config {
		t.Fatalf("owner_changed = %+v", ch)
	}
	routes = h.proxyRoutes()
	if routes[0].Trigger != model.ProxyTriggerListener || routes[0].Routes[0].Backends[0].Procs[0].PID != 2000 {
		t.Fatalf("routes after restart = %+v", routes[0])
	}
	calls := h.rec.calls()
	if i := slices.Index(calls, "changes"); i < 0 || calls[len(calls)-1] != "proxies" {
		t.Fatalf("calls = %v: the listener event goes before the route set", calls)
	}

	// The proxy goes away.
	updates <- proxy.Update{}
	routes = h.proxyRoutes()
	if len(routes) != 1 || !routes[0].Removed || routes[0].Trigger != model.ProxyTriggerStopped || routes[0].Proxy.ID != "nginx/x" {
		t.Fatalf("removal = %+v", routes)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(fed) < 2 {
		t.Fatalf("the mapper was not fed after the change")
	}
}

func TestSnapshotCarriesProxiesAndBehindProxy(t *testing.T) {
	updates := make(chan proxy.Update, 1)
	baseline := []model.Observation{obs(model.Opened, 1, 8080, 812, model.SourceBaseline),
		{Kind: model.Opened, Cookie: 2, Key: loKey(8000), At: t0, Source: model.SourceBaseline, Proc: model.Process{PID: 1033}}}
	h := startWith(t, baseline, nil, Options{Recheck: 20 * time.Millisecond, Proxies: updates})
	close(h.release)
	h.snapshot()
	updates <- proxy.Update{States: []proxy.State{nginxState(time.Now(), model.ProxyTriggerStarted)}}
	h.proxyRoutes()
	h.recheck()
	h.reply(baseline, nil)
	snap := h.snapshot()
	var refs []model.ProxyRef
	for _, l := range snap {
		if l.Key == loKey(8000) {
			refs = l.BehindProxy
		}
	}
	h.rec.mu.Lock()
	proxies := h.rec.snapProxies
	h.rec.mu.Unlock()
	if len(refs) != 1 || refs[0].ProxyID != "nginx/x" || len(proxies) != 1 || proxies[0].Proxy.ID != "nginx/x" {
		t.Fatalf("snapshot refs = %+v proxies = %+v", refs, proxies)
	}
}
