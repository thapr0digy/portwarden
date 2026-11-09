package haproxy

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

// header is HAProxy 2.8's "show servers state" header (version 1).
const header = "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port\n"

func stateLine(be, name, addr, op, adm, port string) string {
	return "3 " + be + " 1 " + name + " " + addr + " " + op + " " + adm + " 1 1 10 1 0 3 7 0 0 0 - " + port + " - 0 0 - - 0\n"
}

func TestServersStateHeaderOrder(t *testing.T) {
	// The columns are found by name: a version with the columns shuffled and one more
	// still parses.
	shuffled := "1\n# srv_port extra be_name srv_name srv_addr srv_admin_state srv_op_state\n8000 x app s1 127.0.0.1 1 2\n"
	got, err := ParseServersState([]byte(shuffled))
	if err != nil || len(got) != 1 || got[0].Addr != netip.MustParseAddrPort("127.0.0.1:8000") || !got[0].Maint || got[0].Down {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{"", "2\n# be_name\n", "1\nno header\n", "1\n# be_name srv_name\n", "No such command.\n"} {
		if _, err := ParseServersState([]byte(bad)); !errors.Is(err, ErrServersState) {
			t.Errorf("%q: err = %v, want ErrServersState", bad, err)
		}
	}
	if _, err := ParseServersState([]byte(header + "3 app 1\n")); err == nil {
		t.Error("a short line was accepted")
	}
}

func TestServersStateStates(t *testing.T) {
	dump := header + stateLine("app", "s1", "127.0.0.1", "2", "0", "8000") +
		stateLine("app", "s2", "::1", "0", "0", "8001") +
		stateLine("app", "s3", "10.0.0.1", "2", "8", "8002") +
		stateLine("app", "s4", "-", "0", "32", "0")
	got, err := ParseServersState([]byte(dump))
	if err != nil || len(got) != 4 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got[1].Addr != netip.MustParseAddrPort("[::1]:8001") || !got[1].Down {
		t.Errorf("s2 = %+v", got[1])
	}
	if !got[2].Drain || got[2].Maint {
		t.Errorf("s3 = %+v", got[2])
	}
	if got[3].Addr.IsValid() || !got[3].Maint {
		t.Errorf("s4 = %+v", got[3])
	}
}

// The overlay can only add or annotate: a file server absent at runtime is kept (noted),
// a runtime-only server is added, a changed address replaces the file's (noted).
func TestHAProxyOverlayNeverRemoves(t *testing.T) {
	fsys := conf.MemFS{"/etc/haproxy/haproxy.cfg": []byte(`global
  stats socket /run/haproxy/admin.sock mode 660 level admin
  stats socket ipv4@127.0.0.1:9999 level operator
  stats socket abns@hidden
frontend f
  bind :80
  default_backend app
backend app
  server s1 127.0.0.1:8000
  server s2 127.0.0.1:8001
  server gone 127.0.0.1:8002
  server named app.internal:8003
  server-template web 2 127.0.0.1:8100
`)}
	res := Load(fsys, []string{DefaultConfig})
	if len(res.AdminSockets) != 2 || res.AdminSockets[0] != (conf.AdminSocket{Network: "unix", Addr: "/run/haproxy/admin.sock", Level: "admin", Source: "/etc/haproxy/haproxy.cfg:2"}) ||
		res.AdminSockets[1].Network != "tcp" || res.AdminSockets[1].Addr != "127.0.0.1:9999" {
		t.Fatalf("admin sockets = %+v", res.AdminSockets)
	}
	dump := header + stateLine("app", "s1", "127.0.0.1", "2", "0", "8000") +
		stateLine("app", "s2", "127.0.0.9", "2", "1", "8001") +
		stateLine("app", "named", "10.1.2.3", "2", "0", "8003") +
		stateLine("app", "web1", "127.0.0.1", "2", "0", "8100") +
		stateLine("app", "web2", "127.0.0.1", "2", "0", "8100") +
		stateLine("app", "extra", "127.0.0.1", "2", "0", "8200") +
		stateLine("other", "x", "127.0.0.1", "2", "0", "1")
	rs, err := ParseServersState([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	got := conf.Render(conf.Result{Routes: Overlay(res.Routes, rs)})
	want := `*:80 names= path="default" proxy "app" upstream=app
    -> 127.0.0.1:8000 127.0.0.1:8000
    -> 127.0.0.9:8001 127.0.0.9:8001 (runtime address (file: 127.0.0.1:8001); maint (runtime))
    -> 127.0.0.1:8002 127.0.0.1:8002 (not in runtime state)
    -> 10.1.2.3:8003 10.1.2.3:8003 (runtime address (file: app.internal:8003))
    -> 127.0.0.1:8100 127.0.0.1:8100 (server-template)
    -> 127.0.0.1:8100 127.0.0.1:8100 (server-template web (runtime))
    -> 127.0.0.1:8100 127.0.0.1:8100 (server-template web (runtime))
    -> 127.0.0.1:8200 127.0.0.1:8200 (added at runtime)
    @ /etc/haproxy/haproxy.cfg:5
`
	if got != want {
		t.Errorf("overlay:\n%s\nwant:\n%s", got, want)
	}
	if n := len(Overlay(res.Routes, nil)[0].Backends); n != 5 {
		t.Errorf("an empty runtime answer changed the backends: %d", n)
	}
}

// The recorded answers of the VM's HAProxy (dev/proxy-fixtures.sh), folded into the
// fixture's routes, match the reviewed golden file.
func TestServersStateGolden(t *testing.T) {
	dumps, _ := filepath.Glob("testdata/*/servers-state.txt")
	if len(dumps) == 0 {
		t.Fatal("no recorded servers state")
	}
	for _, f := range dumps {
		dir := filepath.Dir(f)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			rs, err := ParseServersState(b)
			if err != nil {
				t.Fatal(err)
			}
			cfgs, _ := filepath.Glob(filepath.Join(dir, "root/etc/*/haproxy.cfg"))
			main := strings.TrimPrefix(cfgs[0], filepath.Join(dir, "root"))
			res := Load(rootfs.Walker(filepath.Join(dir, "root")), []string{main})
			res.Routes = Overlay(res.Routes, rs)
			got := conf.Render(res)
			golden := filepath.Join(dir, "runtime-routes.txt")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("routes differ from %s (go test -update to rewrite after review):\n%s", golden, got)
			}
		})
	}
}
