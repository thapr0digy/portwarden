package mapper

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
	"github.com/thapr0digy/portwarden/internal/state"
)

const hostNS = 4026531840

type procs struct{}

func (procs) PPID(pid uint32) (uint32, bool) {
	if pid == 801 || pid == 851 {
		return pid - 1, true
	}
	return 1, true
}
func (procs) Exe(pid uint32) string {
	switch pid {
	case 800, 801, 850, 851:
		return "/usr/sbin/nginx"
	}
	return ""
}
func (procs) Cmdline(uint32) []string                         { return []string{"nginx: master process /usr/sbin/nginx"} }
func (procs) Environ(uint32) map[string]string                { return nil }
func (procs) MountNS(uint32) (uint64, bool)                   { return 7, true }
func (procs) ExeString(uint32, string, string) (string, bool) { return "", false }
func (procs) Cgroup(uint32) string                            { return "/system.slice/nginx.service" }

// files is a MemFS the test edits while the mapper reads it.
type files struct {
	mu sync.Mutex
	m  conf.MemFS
}

func (f *files) set(p, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[p] = []byte(data)
}

type fsView struct{ f *files }

func (v fsView) ReadFile(p string) ([]byte, error) {
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	return v.f.m.ReadFile(p)
}
func (v fsView) ReadDir(p string) ([]string, error) {
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	return v.f.m.ReadDir(p)
}
func (v fsView) Stat(p string) (rootfs.Info, error) {
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	return v.f.m.Stat(p)
}
func (v fsView) Close() error { return nil }

type conns struct {
	mu      sync.Mutex
	cgroups []string
	pids    []uint32
	list    []Conn
}

func (c *conns) SetCgroups(p []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cgroups = slices.Clone(p)
	return nil
}
func (c *conns) SetPIDs(p []uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pids = slices.Clone(p)
	return nil
}
func (c *conns) Read() ([]Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.list), nil
}

func nginxListeners(master uint32) []state.Listener {
	k := model.NewKey(hostNS, model.ProtoTCP, netip.MustParseAddr("0.0.0.0"), 8080)
	return []state.Listener{{Key: k, Procs: []model.Process{
		{PID: master, Exe: "/usr/sbin/nginx", Comm: "nginx"}, {PID: master + 1, Exe: "/usr/sbin/nginx", Comm: "nginx"}}}}
}

const confV1 = "events {}\nhttp { server { listen 8080; location / { proxy_pass http://127.0.0.1:8000; } } }\n"
const confV2 = "events {}\nhttp { server { listen 8080; location / { proxy_pass http://127.0.0.1:8001; } } }\n"

func TestMapperReadsReloadsAndObserves(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/nginx/nginx.conf": []byte(confV1)}}
	c := &conns{}
	m := New(Config{
		Procs: procs{}, SelfMountNS: 7,
		OpenRoot:   func(string) (rootfs.FS, error) { return fsView{f}, nil },
		NetnsAddrs: func(uint32, uint32) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil },
		Conns:      c, Poll: 10 * time.Millisecond, Settle: 40 * time.Millisecond,
	})
	updates := make(chan proxy.Update, 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	target := func(u proxy.Update) string {
		if len(u.States) != 1 || len(u.States[0].Routes) != 1 {
			return ""
		}
		return u.States[0].Routes[0].Target
	}

	m.Listeners(nginxListeners(800))
	u := next("started", func(u proxy.Update) bool { return target(u) == "http://127.0.0.1:8000" })
	s := u.States[0]
	if s.Trigger != model.ProxyTriggerStarted || s.Instance.ID != "nginx/4026531840//etc/nginx/nginx.conf" ||
		!slices.Equal(s.Instance.Files, []string{"/etc/nginx/nginx.conf"}) || len(u.NetnsAddrs[hostNS]) != 1 {
		t.Fatalf("first update = %+v", u)
	}
	c.mu.Lock()
	if !slices.Equal(c.cgroups, []string{"/system.slice/nginx.service"}) || !slices.Equal(c.pids, []uint32{800, 801}) {
		t.Errorf("tracking = %v %v", c.cgroups, c.pids)
	}
	c.mu.Unlock()

	// A config edit is read once it holds still.
	f.set("/etc/nginx/nginx.conf", confV2+"# grown\n")
	u = next("config", func(u proxy.Update) bool { return target(u) == "http://127.0.0.1:8001" })
	if u.States[0].Trigger != model.ProxyTriggerConfig {
		t.Fatalf("trigger = %q", u.States[0].Trigger)
	}

	// Observed connections, attributed by the counted tgid.
	c.mu.Lock()
	c.list = []Conn{{Proxy: 800, Addr: netip.MustParseAddrPort("127.0.0.1:8001"), Count: 3, Last: time.Now()},
		{Proxy: 999, Addr: netip.MustParseAddrPort("127.0.0.1:9"), Count: 1}}
	c.mu.Unlock()
	u = next("traffic", func(u proxy.Update) bool { return len(u.States) == 1 && len(u.States[0].Observed) == 1 })
	if o := u.States[0].Observed[0]; o.Count != 3 || u.States[0].Trigger != model.ProxyTriggerTraffic {
		t.Fatalf("observed = %+v trigger %q", o, u.States[0].Trigger)
	}
	// A count that drops (the kernel entry was evicted) keeps the total.
	c.mu.Lock()
	c.list = []Conn{{Proxy: 800, Addr: netip.MustParseAddrPort("127.0.0.1:8001"), Count: 2, Last: time.Now()}}
	c.mu.Unlock()
	u = next("count", func(u proxy.Update) bool { return len(u.States) == 1 && u.States[0].Observed[0].Count == 5 })

	// A restart (new master pid) re-reads; the proxy going away empties the set.
	m.Listeners(nginxListeners(850))
	u = next("restart", func(u proxy.Update) bool {
		return len(u.States) == 1 && u.States[0].Instance.Master().PID == 850 && u.States[0].Trigger == model.ProxyTriggerListener
	})
	if u.States[0].Observed[0].Count != 5 {
		t.Errorf("observed history lost on restart: %+v", u.States[0].Observed)
	}
	m.Listeners(nil)
	next("gone", func(u proxy.Update) bool { return len(u.States) == 0 })
	c.mu.Lock()
	if len(c.cgroups) != 0 || len(c.pids) != 0 {
		t.Errorf("tracking after removal = %v %v", c.cgroups, c.pids)
	}
	c.mu.Unlock()
}
