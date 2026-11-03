package proxy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/state"
)

const (
	hostNS = 4026531840
	ctrNS  = 4026532301
)

func lk(ns uint32, proto, addr string, port uint16) model.ListenerKey {
	return model.NewKey(ns, proto, netip.MustParseAddr(addr), port)
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

var (
	front443  = lk(hostNS, model.ProtoTCP, "0.0.0.0", 443)
	front443b = lk(hostNS, model.ProtoTCP, "::", 443)
	front80   = lk(hostNS, model.ProtoTCP, "0.0.0.0", 80)
	gunicorn  = lk(hostNS, model.ProtoTCP, "127.0.0.1", 8000)
	wildApp   = lk(hostNS, model.ProtoTCP, "::", 9000)
	ctrApp    = lk(ctrNS, model.ProtoTCP, "0.0.0.0", 80)
	otherLo   = lk(ctrNS, model.ProtoTCP, "127.0.0.1", 8000) // same port, other netns
)

func listeners() []state.Listener {
	p := func(pid uint32, comm string) []model.Process { return []model.Process{{PID: pid, Comm: comm}} }
	return []state.Listener{
		{Key: front443, Procs: p(812, "nginx")}, {Key: front443b, Procs: p(812, "nginx")}, {Key: front80, Procs: p(812, "nginx")},
		{Key: gunicorn, Procs: p(1033, "gunicorn")}, {Key: wildApp, Procs: p(1100, "app")},
		{Key: ctrApp, Procs: p(2000, "httpd")}, {Key: otherLo, Procs: p(2100, "ctr-lo")},
	}
}

var addrs = map[uint32][]netip.Addr{
	hostNS: {netip.MustParseAddr("192.168.5.15"), netip.MustParseAddr("127.0.0.1")},
	ctrNS:  {netip.MustParseAddr("172.17.0.2"), netip.MustParseAddr("127.0.0.1")},
}

func testState() State {
	return State{
		Instance: model.ProxyInstance{
			ID: "nginx/1//etc/nginx/nginx.conf", Kind: "nginx", NetNS: hostNS,
			Procs: []model.Process{{PID: 812, Comm: "nginx"}}, Listeners: []model.ListenerKey{front80, front443, front443b},
		},
		Routes: []conf.Route{
			{Listen: []string{"*:443", "[::]:443"}, ServerNames: []string{"api.example.com"}, Path: "/", Kind: model.RouteProxy,
				Backends: []conf.Backend{{Address: "localhost:8000", Addrs: []netip.AddrPort{ap("[::1]:8000"), ap("127.0.0.1:8000")}}}},
			{Listen: []string{"127.0.0.1:443"}, Path: "/admin", Kind: model.RouteProxy,
				Backends: []conf.Backend{{Address: "192.168.5.15:9000", Addrs: []netip.AddrPort{ap("192.168.5.15:9000")}}}},
			{Listen: []string{"*:80"}, Path: "/ctr", Kind: model.RouteProxy,
				Backends: []conf.Backend{{Address: "172.17.0.2:80", Addrs: []netip.AddrPort{ap("172.17.0.2:80")}}}},
			{Listen: []string{"*:80"}, Path: "/php", Kind: model.RouteFastCGI,
				Backends: []conf.Backend{{Address: "unix:/run/php.sock", Unix: "/run/php.sock"}}},
			{Listen: []string{"*:80"}, Path: "/dyn", Kind: model.RouteProxy,
				Backends: []conf.Backend{{Address: "$host", Note: "unresolved: variable $host"}}},
			{Listen: []string{"*:80"}, Path: "/db", Kind: model.RouteProxy,
				Backends: []conf.Backend{{Address: "10.0.0.9:8000", Addrs: []netip.AddrPort{ap("10.0.0.9:8000")}}}},
		},
		Observed: []Observed{
			{Addr: ap("127.0.0.1:8000"), Count: 5, Last: time.Unix(100, 0)},
			{Addr: ap("[::ffff:127.0.0.1]:8000"), Count: 2, Last: time.Unix(200, 0)}, // dual-stack socket
			{Addr: ap("127.0.0.1:7777"), Count: 1, Last: time.Unix(50, 0)},
			{Addr: ap("10.0.0.9:9999"), Count: 3, Last: time.Unix(60, 0)},
		},
		Trigger: model.ProxyTriggerTraffic,
	}
}

func TestJoinEndsRoutesAtListeners(t *testing.T) {
	got := Join(testState(), listeners(), addrs)
	if len(got.Routes) != 8 {
		t.Fatalf("routes = %d: %+v", len(got.Routes), got.Routes)
	}
	r := got.Routes
	// localhost: ::1 has no listener, 127.0.0.1 has gunicorn; both addresses' traffic counts.
	b := r[0].Backends[0]
	if b.Listener == nil || *b.Listener != gunicorn || b.Procs[0].PID != 1033 || !b.Config || !b.Seen ||
		b.Connections != 7 || !b.LastSeen.Equal(time.Unix(200, 0)) || b.Addr != ap("127.0.0.1:8000") {
		t.Errorf("gunicorn backend = %+v", b)
	}
	if len(r[0].Frontends) != 2 || r[0].Frontends[0] != front443 || r[0].Frontends[1] != front443b {
		t.Errorf("frontends = %v", r[0].Frontends)
	}
	// A specific listen address is served by the wildcard socket.
	if len(r[1].Frontends) != 2 {
		t.Errorf("127.0.0.1:443 frontends = %v", r[1].Frontends)
	}
	// A host address reaches a [::] listener in the same netns.
	if b := r[1].Backends[0]; b.Listener == nil || *b.Listener != wildApp || b.Seen {
		t.Errorf("host address backend = %+v", b)
	}
	// A container address reaches the container's wildcard listener.
	if b := r[2].Backends[0]; b.Listener == nil || *b.Listener != ctrApp {
		t.Errorf("container backend = %+v", b)
	}
	if b := r[3].Backends[0]; b.Unix != "/run/php.sock" || b.Listener != nil || b.Note != "" {
		t.Errorf("unix backend = %+v", b)
	}
	if b := r[4].Backends[0]; b.Listener != nil || b.Note != "unresolved: variable $host" {
		t.Errorf("unresolved backend = %+v", b)
	}
	// A remote address is never joined to a local listener on the same port.
	if b := r[5].Backends[0]; b.Listener != nil || b.Note != "no listener" {
		t.Errorf("remote backend = %+v", b)
	}
	// Observed destinations no route names are inferred routes.
	for i, want := range []string{"10.0.0.9:9999", "127.0.0.1:7777"} {
		rt := r[6+i]
		if !rt.Inferred || rt.Target != want || !rt.Backends[0].Seen || rt.Backends[0].Config || len(rt.Frontends) != 3 {
			t.Errorf("inferred %d = %+v", i, rt)
		}
	}
	behind := BehindProxy([]model.ProxyRoutes{got})
	refs := behind[gunicorn]
	if len(refs) != 1 || refs[0].Proxy.PID != 812 || refs[0].Path != "/" || !refs[0].Seen || !refs[0].Config ||
		refs[0].ServerNames[0] != "api.example.com" {
		t.Errorf("behind gunicorn = %+v", refs)
	}
	if len(behind[ctrApp]) != 1 || len(behind[otherLo]) != 0 {
		t.Errorf("behind = %+v", behind)
	}
}

func TestListenMatches(t *testing.T) {
	for _, c := range []struct {
		k      model.ListenerKey
		listen string
		want   bool
	}{
		{front80, "*:80", true},
		{front80, "*:81", false},
		{front80, "*:80/udp", false},
		{lk(hostNS, model.ProtoUDP, "127.0.0.1", 1053), "127.0.0.1:1053/udp", true},
		{gunicorn, "127.0.0.1:8000", true},
		{gunicorn, "10.0.0.1:8000", false},
		{gunicorn, "localhost:8000", true},
		{front443b, "[::]:443", true},
		{front80, "*:*", true},
		{front80, "unix:/run/x.sock", false},
	} {
		if got := listenMatches(c.k, c.listen); got != c.want {
			t.Errorf("listenMatches(%s, %s) = %v", c.k, c.listen, got)
		}
	}
}
