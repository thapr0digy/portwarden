package discover

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/state"
)

type fakeProc struct {
	ppid    uint32
	exe     string
	cmdline []string
	env     map[string]string
	mntns   uint64
	bin     string
	cgroup  string
}

type fakeProcs map[uint32]fakeProc

func (f fakeProcs) PPID(pid uint32) (uint32, bool) { p, ok := f[pid]; return p.ppid, ok }
func (f fakeProcs) Exe(pid uint32) string          { return f[pid].exe }
func (f fakeProcs) Cmdline(pid uint32) []string    { return f[pid].cmdline }
func (f fakeProcs) Environ(pid uint32) map[string]string {
	return f[pid].env
}
func (f fakeProcs) MountNS(pid uint32) (uint64, bool) { p, ok := f[pid]; return p.mntns, ok }
func (f fakeProcs) ExeString(pid uint32, prefix, stop string) (string, bool) {
	return scanFor(strings.NewReader(f[pid].bin), []byte(prefix), stop, maxValue)
}
func (f fakeProcs) Cgroup(pid uint32) string { return f[pid].cgroup }

const hostNS = 4026531840

func key(port uint16) model.ListenerKey {
	return model.NewKey(hostNS, model.ProtoTCP, netip.MustParseAddr("0.0.0.0"), port)
}

func TestFindGroupsUnderMasterAndLocatesConfig(t *testing.T) {
	procs := fakeProcs{
		1:   {exe: "/usr/lib/systemd/systemd"},
		800: {ppid: 1, exe: "/usr/sbin/nginx", cmdline: []string{"nginx: master process /usr/sbin/nginx -c /etc/nginx/alt.conf -g daemon on;"}, mntns: 7, cgroup: "/system.slice/nginx.service"},
		801: {ppid: 800, exe: "/usr/sbin/nginx", mntns: 7},
		802: {ppid: 800, exe: "/usr/sbin/nginx", mntns: 7},
		900: {ppid: 1, exe: "/usr/sbin/apache2", cmdline: []string{"/usr/sbin/apache2", "-k", "start", "-DSSL"}, env: map[string]string{"APACHE_LOG_DIR": "/var/log/apache2"}, mntns: 7,
			bin: `xx -D HTTPD_ROOT="/etc/apache2"` + "\x00" + ` -D SERVER_CONFIG_FILE="apache2.conf"`},
		901: {ppid: 900, exe: "/usr/sbin/apache2", mntns: 7},
		960: {ppid: 1, exe: "/bin/httpd", cmdline: []string{"httpd", "-f", "-p", "80"}, mntns: 9, bin: "BusyBox v1.36"},
		950: {ppid: 1, exe: "/usr/sbin/haproxy", cmdline: []string{"/usr/sbin/haproxy", "-Ws", "-f", "/etc/haproxy/haproxy.cfg", "-f", "/etc/haproxy/conf.d", "-p", "/run/haproxy.pid"}, mntns: 7},
		951: {ppid: 950, exe: "/usr/sbin/haproxy", mntns: 7},
		990: {ppid: 1, exe: "/usr/bin/python3", mntns: 7},
	}
	nginxProc := func(pid uint32) model.Process { return model.Process{PID: pid, Exe: "/usr/sbin/nginx", Comm: "nginx"} }
	listeners := []state.Listener{
		{Key: key(80), Procs: []model.Process{nginxProc(802), nginxProc(800), nginxProc(801)}},
		{Key: key(443), Procs: []model.Process{nginxProc(800), nginxProc(801)}},
		{Key: key(8080), Procs: []model.Process{{PID: 901, Exe: "/usr/sbin/apache2"}}},
		{Key: key(8404), Procs: []model.Process{{PID: 951, Exe: "/usr/sbin/haproxy"}}},
		{Key: key(8000), Procs: []model.Process{{PID: 990, Exe: "/usr/bin/python3"}}},
		{Key: key(8001), Procs: []model.Process{{PID: 960, Exe: "/bin/httpd"}}}, // BusyBox, not Apache
	}
	enriched := false
	got := Find(listeners, procs, 7, func(p model.Process) model.Process { enriched = true; p.Unit = "x.service"; return p })
	if len(got) != 3 {
		t.Fatalf("instances = %+v", got)
	}
	byKind := map[string]Instance{}
	for _, in := range got {
		byKind[in.Kind] = in
	}
	n := byKind[KindNginx]
	if n.ID != "nginx/4026531840//etc/nginx/alt.conf" || n.NginxConf != "/etc/nginx/alt.conf" || n.Root != "/" ||
		!slices.Equal(n.PIDs, []uint32{800, 801, 802}) || n.Master().PID != 800 || len(n.Listeners) != 2 ||
		n.Cgroup != "/system.slice/nginx.service" {
		t.Errorf("nginx = %+v", n)
	}
	a := byKind[KindApache]
	if a.Master().PID != 900 || !enriched || a.Master().Unit != "x.service" || a.Apache.ServerRoot != "/etc/apache2" ||
		a.Apache.MainFile() != "/etc/apache2/apache2.conf" || !slices.Equal(a.Apache.Defines, []string{"SSL"}) ||
		a.Apache.Env["APACHE_LOG_DIR"] != "/var/log/apache2" {
		t.Errorf("apache = %+v", a)
	}
	h := byKind[KindHAProxy]
	if !slices.Equal(h.HAProxyFile, []string{"/etc/haproxy/haproxy.cfg", "/etc/haproxy/conf.d"}) || h.Master().PID != 950 {
		t.Errorf("haproxy = %+v", h)
	}
}

func TestNginxDefaultsAndContainerRoot(t *testing.T) {
	procs := fakeProcs{
		500: {ppid: 400, exe: "/usr/sbin/nginx", cmdline: []string{"nginx: master process nginx -g daemon off;"}, mntns: 99,
			bin: "configure arguments: --prefix=/etc/nginx --conf-path=/etc/nginx/nginx.conf --sbin-path=x"},
		400: {ppid: 1, exe: "/usr/bin/containerd-shim-runc-v2", mntns: 7},
	}
	l := []state.Listener{{Key: key(80), Procs: []model.Process{{PID: 500, Exe: "/usr/sbin/nginx", Container: model.Container{Runtime: "docker", ID: "abc"}}}}}
	got := Find(l, procs, 7, nil)
	if len(got) != 1 || got[0].Root != "/proc/500/root" || got[0].NginxConf != "/etc/nginx/nginx.conf" ||
		got[0].ID != "nginx/4026531840//etc/nginx/nginx.conf@abc" {
		t.Fatalf("container nginx = %+v", got)
	}
	none := func(string, string) string { return "" }
	if c := nginxConf([]string{"nginx: master process nginx -p /opt/n/ -c conf/n.conf"}, none); c != "/opt/n/conf/n.conf" {
		t.Errorf("relative -c = %q", c)
	}
	if c := nginxConf(nil, none); c != "/etc/nginx/nginx.conf" {
		t.Errorf("default = %q", c)
	}
	if o := apacheOptions([]string{"/usr/sbin/httpd", "-DFOREGROUND"}, "/usr/sbin/httpd", nil, none); o.MainFile() != "/etc/httpd/conf/httpd.conf" {
		t.Errorf("httpd default = %q", o.MainFile())
	}
	if KindOf("/usr/local/openresty/nginx/sbin/nginx (deleted)", "") != KindNginx || KindOf("", "caddy") != KindCaddy || KindOf("/bin/sh", "nginx") != "" {
		t.Error("KindOf")
	}
}

func TestProcFS(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "42")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "42 (my (odd) proc) S 7 42 42 0")
	write("cmdline", "/usr/sbin/nginx\x00-c\x00/x.conf\x00")
	write("environ", "A=1\x00B=x=y\x00")
	write("cgroup", "0::/system.slice/nginx.service\n")
	p := NewProcFS(root)
	if pp, ok := p.PPID(42); !ok || pp != 7 {
		t.Errorf("PPID = %d %v", pp, ok)
	}
	if c := p.Cmdline(42); !slices.Equal(c, []string{"/usr/sbin/nginx", "-c", "/x.conf"}) {
		t.Errorf("cmdline = %q", c)
	}
	if e := p.Environ(42); e["A"] != "1" || e["B"] != "x=y" {
		t.Errorf("environ = %v", e)
	}
	if c := p.Cgroup(42); c != "/system.slice/nginx.service" {
		t.Errorf("cgroup = %q", c)
	}
}

// scanFor finds values across read boundaries and refuses ones without a terminator.
func TestScanForStreams(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 70<<10) // the prefix straddles the first 64 KiB read
	data = append(data, []byte(` -D HTTPD_ROOT="/etc/apache2" more`)...)
	if v, ok := scanFor(bytes.NewReader(data), []byte(` -D HTTPD_ROOT="`), `"`, 4096); !ok || v != "/etc/apache2" {
		t.Fatalf("scanFor = %q %v", v, ok)
	}
	if _, ok := scanFor(strings.NewReader(`a -D HTTPD_ROOT="unterminated`), []byte(` -D HTTPD_ROOT="`), `"`, 4096); ok {
		t.Fatal("an unterminated value must not be found")
	}
	if v, ok := scanFor(strings.NewReader("args: --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf\x00"), []byte(" --conf-path="), configureStop, 4096); !ok || v != "/etc/nginx/nginx.conf" {
		t.Fatalf("value at the end = %q %v", v, ok)
	}
}
