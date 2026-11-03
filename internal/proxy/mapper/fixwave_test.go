package mapper

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/proxy"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

// procsAs is procs with a chosen master uid and oldest worker start.
type procsAs struct {
	procs
	uid   uint32
	child time.Time
}

func (p procsAs) EUID(uint32) (uint32, bool) { return p.uid, true }
func (p procsAs) OldestChildStart(uint32) (time.Time, bool) {
	return p.child, !p.child.IsZero()
}

func runMapper(t *testing.T, cfg Config) (*Mapper, chan proxy.Update) {
	t.Helper()
	cfg.Poll, cfg.Settle = 10*time.Millisecond, 20*time.Millisecond
	m := New(cfg)
	updates := make(chan proxy.Update, 64)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go m.Run(ctx, func(u proxy.Update) { updates <- u })
	return m, updates
}

func waitUpdate(t *testing.T, updates chan proxy.Update, what string, ok func(proxy.Update) bool) proxy.Update {
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

func notes(u proxy.Update) string {
	if len(u.States) == 0 {
		return ""
	}
	return strings.Join(u.States[0].Instance.Notes, " | ")
}

func TestUntrustedMasterGetsNoConfigAndNoHook(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/nginx/nginx.conf": []byte(confV1)}}
	c := &conns{}
	m, updates := runMapper(t, Config{Procs: procsAs{uid: 1000}, SelfMountNS: 7, Conns: c,
		OpenRoot: func(string) (rootfs.FS, error) { return fsView{f}, nil }})
	m.Listeners(nginxListeners(800))
	u := waitUpdate(t, updates, "untrusted", func(u proxy.Update) bool { return len(u.States) == 1 })
	if len(u.States[0].Routes) != 0 || !strings.Contains(notes(u), "config:untrusted master runs as uid 1000") {
		t.Fatalf("state = %+v", u.States[0])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pids) != 0 || len(c.cgroups) != 0 {
		t.Fatalf("an untrusted proxy was tracked: %v %v", c.pids, c.cgroups)
	}
}

func TestConfigFilesNotOwnedByRootAreNotPublished(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/nginx/nginx.conf": []byte(confV1)}, owner: 1000}
	m, updates := runMapper(t, Config{Procs: procs{}, SelfMountNS: 7,
		OpenRoot: func(string) (rootfs.FS, error) { return fsView{f}, nil }})
	m.Listeners(nginxListeners(800))
	u := waitUpdate(t, updates, "untrusted files", func(u proxy.Update) bool { return len(u.States) == 1 })
	if len(u.States[0].Routes) != 0 || !strings.Contains(notes(u), "config:untrusted /etc/nginx/nginx.conf owned by uid 1000") {
		t.Fatalf("state = %+v", u.States[0])
	}
}

func TestPublishedConfigTextIsRedacted(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/nginx/nginx.conf": []byte("http { server { listen 8080; location / { proxy_pass http://127.0.0.1:8000/?token=abc; } location /r { return 302 https://x/?t=1; } } }\n")}}
	m, updates := runMapper(t, Config{Procs: procs{}, SelfMountNS: 7,
		OpenRoot: func(string) (rootfs.FS, error) { return fsView{f}, nil }})
	m.Listeners(nginxListeners(800))
	u := waitUpdate(t, updates, "routes", func(u proxy.Update) bool { return len(u.States) == 1 && len(u.States[0].Routes) == 2 })
	if r := u.States[0].Routes; r[0].Target != "http://127.0.0.1:8000/" || r[1].Target != "302" {
		t.Fatalf("targets = %q %q", r[0].Target, r[1].Target)
	}
}

func TestFailedAttachIsRetriedAndReported(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/nginx/nginx.conf": []byte(confV1)}}
	c := &conns{failCg: 2}
	m, updates := runMapper(t, Config{Procs: procs{}, SelfMountNS: 7, Conns: c,
		OpenRoot: func(string) (rootfs.FS, error) { return fsView{f}, nil }})
	m.Listeners(nginxListeners(800))
	waitUpdate(t, updates, "reported", func(u proxy.Update) bool {
		return strings.Contains(notes(u), "observed connections unavailable: attach refused")
	})
	waitUpdate(t, updates, "recovered", func(u proxy.Update) bool {
		return len(u.States) == 1 && !strings.Contains(notes(u), "unavailable")
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cgroups) != 1 {
		t.Fatalf("cgroups after retry = %v", c.cgroups)
	}
}

// Counts are kept per kernel key: dropping one worker's key does not recount the rest.
func TestCountsPerKernelKey(t *testing.T) {
	f := &files{m: conf.MemFS{"/etc/nginx/nginx.conf": []byte(confV1)}}
	c := &conns{}
	dst := netip.MustParseAddrPort("127.0.0.1:8000")
	m, updates := runMapper(t, Config{Procs: procs{}, SelfMountNS: 7, Conns: c,
		OpenRoot: func(string) (rootfs.FS, error) { return fsView{f}, nil }})
	m.Listeners(nginxListeners(800))
	set := func(list ...Conn) {
		c.mu.Lock()
		c.list = list
		c.mu.Unlock()
	}
	count := func(u proxy.Update) uint64 {
		if len(u.States) != 1 || len(u.States[0].Observed) != 1 {
			return 0
		}
		return u.States[0].Observed[0].Count
	}
	now := time.Now()
	set(Conn{Proxy: 800, Addr: dst, Count: 500, Last: now}, Conn{Proxy: 801, Addr: dst, Count: 1000, Last: now})
	waitUpdate(t, updates, "1500", func(u proxy.Update) bool { return count(u) == 1500 })
	set(Conn{Proxy: 800, Addr: dst, Count: 505, Last: now}) // 801's key was dropped
	waitUpdate(t, updates, "1505", func(u proxy.Update) bool { return count(u) == 1505 })
}

func TestPendingReloadUntilWorkersAreNewer(t *testing.T) {
	edited := time.Now()
	f := &files{m: conf.MemFS{"/etc/nginx/nginx.conf": []byte(confV1)}, mtime: edited}
	p := procsAs{child: edited.Add(-time.Hour)}
	m, updates := runMapper(t, Config{Procs: p, SelfMountNS: 7,
		OpenRoot: func(string) (rootfs.FS, error) { return fsView{f}, nil }})
	m.Listeners(nginxListeners(800))
	waitUpdate(t, updates, "pending", func(u proxy.Update) bool { return strings.Contains(notes(u), "pending reload") })
}
