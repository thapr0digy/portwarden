package haproxy

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

var update = flag.Bool("update", false, "rewrite the routes.txt golden files")

// Each fixture was accepted by `haproxy -c` (haproxy-c.txt) and its routes match the
// reviewed golden file.
func TestRoutesFromConfigs(t *testing.T) {
	dirs, _ := filepath.Glob("testdata/*/haproxy-c.txt")
	if len(dirs) == 0 {
		t.Fatal("no fixtures")
	}
	for _, f := range dirs {
		dir := filepath.Dir(f)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			check, _ := os.ReadFile(f)
			if !strings.Contains(string(check), "Configuration file is valid") {
				t.Fatalf("haproxy -c rejected the fixture:\n%s", check)
			}
			cfgs, _ := filepath.Glob(filepath.Join(dir, "root/etc/*/haproxy.cfg"))
			if len(cfgs) != 1 {
				t.Fatalf("config = %v", cfgs)
			}
			main := strings.TrimPrefix(cfgs[0], filepath.Join(dir, "root"))
			res := Load(rootfs.Walker(filepath.Join(dir, "root")), []string{main})
			got := conf.Render(res)
			golden := filepath.Join(dir, "routes.txt")
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

func TestDirectoryOfCfgFiles(t *testing.T) {
	fsys := conf.MemFS{
		"/etc/haproxy/conf.d/20-be.cfg": []byte("backend b\n  server s 127.0.0.1:81\n"),
		"/etc/haproxy/conf.d/10-fe.cfg": []byte("frontend f # comment\n  bind \"*:8080\"\n  default_backend b\n  use_backend nowhere if TRUE\n"),
		"/etc/haproxy/conf.d/x.txt":     []byte("frontend ignored\n  bind :1\n"),
	}
	got := conf.Render(Load(fsys, []string{"/etc/haproxy/conf.d"}))
	for _, want := range []string{
		"*:8080 names= path=\"if TRUE\" proxy \"nowhere\" upstream=nowhere\n    -> nowhere (unresolved: no backend nowhere)",
		"*:8080 names= path=\"default\" proxy \"b\" upstream=b\n    -> 127.0.0.1:81 127.0.0.1:81",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ignored") {
		t.Errorf("a non-.cfg file was read:\n%s", got)
	}
}
