package mapper

import (
	"context"
	"io/fs"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy"
	"github.com/thapr0digy/portwarden/internal/proxy/admin"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/discover"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
	"github.com/thapr0digy/portwarden/internal/state"
)

// adminProcs is a root-run caddy (pid 900) and haproxy (pid 700, worker 701).
type adminProcs struct{ euid uint32 }

func (adminProcs) PPID(pid uint32) (uint32, bool) {
	if pid == 701 {
		return 700, true
	}
	return 1, true
}
func (adminProcs) Exe(pid uint32) string {
	switch pid {
	case 900, 950:
		return "/usr/bin/caddy"
	case 700, 701:
		return "/usr/sbin/haproxy"
	}
	return ""
}
func (adminProcs) Cmdline(pid uint32) []string {
	if pid == 700 {
		return []string{"/usr/sbin/haproxy", "-Ws", "-f", "/etc/haproxy/haproxy.cfg"}
	}
	return []string{"/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile"}
}
func (adminProcs) Environ(uint32) map[string]string                { return nil }
func (adminProcs) MountNS(uint32) (uint64, bool)                   { return 7, true }
func (adminProcs) ExeString(uint32, string, string) (string, bool) { return "", false }
func (adminProcs) Cgroup(uint32) string                            { return "/system.slice/x.service" }
func (p adminProcs) EUID(uint32) (uint32, bool)                    { return p.euid, true }
func (adminProcs) ExeOwner(uint32) (uint32, fs.FileMode, bool)     { return 0, 0o755, true }
func (adminProcs) OldestChildStart(uint32) (time.Time, bool)       { return time.Time{}, false }

func caddyListeners(pid uint32) []state.Listener {
	p := []model.Process{{PID: pid, Exe: "/usr/bin/caddy", Comm: "caddy"}}
	return []state.Listener{
		{Key: model.NewKey(hostNS, model.ProtoTCP, netip.MustParseAddr("127.0.0.1"), 2019), Procs: p},
		{Key: model.NewKey(hostNS, model.ProtoTCP, netip.MustParseAddr("0.0.0.0"), 80), Procs: p},
	}
}

func haproxyListeners() []state.Listener {
	return []state.Listener{{Key: model.NewKey(hostNS, model.ProtoTCP, netip.MustParseAddr("0.0.0.0"), 80),
		Procs: []model.Process{{PID: 701, Exe: "/usr/sbin/haproxy", Comm: "haproxy"}}}}
}

// fakeAdmin answers admin reads from a settable reply and records them.
type fakeAdmin struct {
	mu    sync.Mutex
	body  string
	err   error
	calls []string
	procs []admin.Proxy
}

func (f *fakeAdmin) set(body string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body, f.err = body, err
}

func (f *fakeAdmin) read(_ context.Context, p admin.Proxy, ep admin.Endpoint, q admin.Query) (admin.Answer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ep.String()+" "+q.HTTPPath+q.Command)
	f.procs = append(f.procs, p)
	if f.err != nil {
		return admin.Answer{}, f.err
	}
	return admin.Answer{Body: []byte(f.body), Via: ep.String()}, nil
}

func (f *fakeAdmin) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

const caddyConfig = `{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"match":[{"host":["a.example"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:9000"}]}]}]}}}}}`

func runAdminMapper(t *testing.T, euid uint32, f *files, fa *fakeAdmin, poll time.Duration) (*Mapper, func(string, func(proxy.Update) bool) proxy.Update) {
	t.Helper()
	m := New(Config{
		Procs: adminProcs{euid: euid}, SelfMountNS: 7,
		OpenRoot:   func(string) (rootfs.FS, error) { return fsView{f}, nil },
		NetnsAddrs: func(uint32, uint32) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil },
		Poll:       10 * time.Millisecond, Settle: 20 * time.Millisecond,
		Admin: &AdminConfig{Kinds: map[string]bool{discover.KindCaddy: true, discover.KindHAProxy: true},
			Poll: poll, Read: fa.read, SelfNetNS: hostNS},
	})
	updates := make(chan proxy.Update, 64)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go m.Run(ctx, func(u proxy.Update) { updates <- u })
	next := func(what string, ok func(proxy.Update) bool) proxy.Update {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case u := <-updates:
				if ok(u) {
					return u
				}
			case <-deadline:
				t.Fatalf("no update: %s", what)
			}
		}
	}
	return m, next
}

func instNotes(u proxy.Update) string {
	if len(u.States) != 1 {
		return ""
	}
	return strings.Join(u.States[0].Instance.Notes, "\n")
}

func TestCaddyRoutesFromAdmin(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/caddy/Caddyfile": []byte(":80 {\n reverse_proxy 127.0.0.1:9000\n}\n")}}
	fa := &fakeAdmin{body: caddyConfig}
	m, next := runAdminMapper(t, 0, f, fa, 30*time.Millisecond)
	m.Listeners(caddyListeners(900))
	u := next("caddy routes", func(u proxy.Update) bool { return len(u.States) == 1 && len(u.States[0].Routes) == 1 })
	rt := u.States[0].Routes[0]
	if rt.Target != "127.0.0.1:9000" || rt.ServerNames[0] != "a.example" || u.States[0].Trigger != model.ProxyTriggerConfig ||
		!strings.Contains(instNotes(u), "routes from the admin API at localhost:2019") {
		t.Fatalf("state = %+v", u.States[0])
	}
	fa.mu.Lock()
	p := fa.procs[0]
	if fa.calls[0] != "localhost:2019 /config/" || p.Master() != 900 || !p.SameNetNS || len(p.Listeners) != 2 {
		t.Errorf("read %q for %+v", fa.calls[0], p)
	}
	fa.mu.Unlock()

	// An unchanged answer publishes nothing new; a changed one does.
	before := fa.count()
	deadline := time.Now().Add(2 * time.Second)
	for fa.count() < before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	fa.set(strings.Replace(caddyConfig, "9000", "9001", 1), nil)
	next("changed", func(u proxy.Update) bool {
		return len(u.States) == 1 && len(u.States[0].Routes) == 1 && u.States[0].Routes[0].Target == "127.0.0.1:9001"
	})

	// A failed read drops the routes and says why: undetermined, not "no routes".
	fa.set("", &admin.Error{Reason: "127.0.0.1:2019 was accepted by a process outside the proxy", Mismatch: true})
	u = next("mismatch", func(u proxy.Update) bool { return len(u.States) == 1 && len(u.States[0].Routes) == 0 })
	if !strings.Contains(instNotes(u), "admin:peer mismatch (127.0.0.1:2019 was accepted by a process outside the proxy)") ||
		!strings.Contains(instNotes(u), "routes are inferred from observed connections") {
		t.Fatalf("notes = %s", instNotes(u))
	}
	// An answer that does not parse is undetermined too.
	fa.set("{", nil)
	u = next("bad json", func(u proxy.Update) bool {
		return strings.Contains(instNotes(u), "admin:undetermined localhost:2019: caddy config")
	})
	if len(u.States[0].Routes) != 0 {
		t.Errorf("routes from a broken answer: %+v", u.States[0].Routes)
	}
}

func TestCaddyAdminOffAndUntrusted(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/caddy/Caddyfile": []byte("{\n admin off\n}\n")}}
	fa := &fakeAdmin{body: caddyConfig}
	m, next := runAdminMapper(t, 0, f, fa, 0)
	m.Listeners(caddyListeners(900))
	u := next("off", func(u proxy.Update) bool { return strings.Contains(instNotes(u), "admin:off (/etc/caddy/Caddyfile:2)") })
	if len(u.States[0].Routes) != 0 || fa.count() != 0 {
		t.Fatalf("admin off was read: %d calls", fa.count())
	}

	fu := &files{m: conf.MemFS{}}
	fa2 := &fakeAdmin{body: caddyConfig}
	m2, next2 := runAdminMapper(t, 1000, fu, fa2, 10*time.Millisecond)
	m2.Listeners(caddyListeners(900))
	u = next2("untrusted", func(u proxy.Update) bool {
		return strings.Contains(instNotes(u), "config:untrusted master runs as uid 1000")
	})
	time.Sleep(50 * time.Millisecond)
	if fa2.count() != 0 {
		t.Fatalf("an untrusted proxy's admin interface was read %d times", fa2.count())
	}
}

const stateHeader = "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port\n"

func TestHAProxyRuntimeOverlay(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/haproxy/haproxy.cfg": []byte("global\n stats socket /run/haproxy/admin.sock level admin\nfrontend f\n bind :80\n default_backend app\nbackend app\n server s1 127.0.0.1:8000\n")}}
	fa := &fakeAdmin{body: stateHeader + "3 app 1 s1 127.0.0.1 2 0 1 1 1 1 0 3 7 0 0 0 - 8000 - 0 0 - - 0\n3 app 2 extra 127.0.0.1 2 0 1 1 1 1 0 3 7 0 0 0 - 8100 - 0 0 - - 0\n"}
	m, next := runAdminMapper(t, 0, f, fa, 0)
	m.Listeners(haproxyListeners())
	u := next("runtime", func(u proxy.Update) bool {
		return len(u.States) == 1 && len(u.States[0].Routes) == 1 && len(u.States[0].Routes[0].Backends) == 2
	})
	if b := u.States[0].Routes[0].Backends[1]; b.Address != "127.0.0.1:8100" || b.Note != "added at runtime" {
		t.Errorf("runtime backend = %+v", b)
	}
	if !strings.Contains(instNotes(u), "runtime state from unix:/run/haproxy/admin.sock") {
		t.Errorf("notes = %s", instNotes(u))
	}
	fa.mu.Lock()
	if fa.calls[0] != "unix:/run/haproxy/admin.sock show servers state" || fa.procs[0].Exe != "/usr/sbin/haproxy" {
		t.Errorf("read %q", fa.calls)
	}
	fa.mu.Unlock()
}

// Every failure of the admin read leaves the config routes as read and adds one
// "admin:" note; nothing is removed.
func TestAdminFailureIsUndetermined(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/haproxy/haproxy.cfg": []byte("global\n stats socket ipv4@127.0.0.1:9999\nfrontend f\n bind :80\n default_backend app\nbackend app\n server s1 127.0.0.1:8000\n")}}
	for _, err := range []error{
		&admin.Error{Reason: "127.0.0.1:9999 is not a listener the proxy holds"},
		&admin.Error{Reason: "127.0.0.1:9999: no answer within 2s"},
		&admin.Error{Reason: "x", Mismatch: true},
		admin.Skip("socket not writable by the agent; not read"),
	} {
		fa := &fakeAdmin{err: err}
		m, next := runAdminMapper(t, 0, f, fa, 0)
		m.Listeners(haproxyListeners())
		want := err.(*admin.Error).Note()
		u := next(want, func(u proxy.Update) bool { return strings.Contains(instNotes(u), want) })
		if rs := u.States[0].Routes; len(rs) != 1 || len(rs[0].Backends) != 1 || rs[0].Backends[0].Address != "127.0.0.1:8000" {
			t.Errorf("%s: routes = %+v", want, rs)
		}
	}
	// No stats socket at all: said once, nothing read.
	fn := &files{m: conf.MemFS{"/etc/haproxy/haproxy.cfg": []byte("frontend f\n bind :80\n default_backend app\nbackend app\n server s1 127.0.0.1:8000\n")}}
	fa := &fakeAdmin{}
	m, next := runAdminMapper(t, 0, fn, fa, 0)
	m.Listeners(haproxyListeners())
	next("no socket", func(u proxy.Update) bool {
		return strings.Contains(instNotes(u), "admin:no stats socket in the config")
	})
	if fa.count() != 0 {
		t.Errorf("%d reads without an endpoint", fa.count())
	}
}

// A restart (new master) forgets the old process's answer before the new one is read.
func TestAdminAnswerDroppedOnRestart(t *testing.T) {
	f := &files{m: conf.MemFS{}}
	fa := &fakeAdmin{body: caddyConfig}
	m, next := runAdminMapper(t, 0, f, fa, 0)
	m.Listeners(caddyListeners(900))
	next("first", func(u proxy.Update) bool { return len(u.States) == 1 && len(u.States[0].Routes) == 1 })
	fa.set("", &admin.Error{Reason: "localhost:2019: connection refused"})
	m.Listeners(caddyListeners(950))
	u := next("restart", func(u proxy.Update) bool {
		return len(u.States) == 1 && u.States[0].Instance.Master().PID == 950 && strings.Contains(instNotes(u), "connection refused")
	})
	if len(u.States[0].Routes) != 0 {
		t.Errorf("the old master's routes survived the restart: %+v", u.States[0].Routes)
	}
}
