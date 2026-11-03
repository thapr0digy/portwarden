package apache

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

var update = flag.Bool("update", false, "rewrite the routes.txt golden files")

// ubuntuEnv is what /etc/apache2/envvars exports, as a master started by apachectl has it.
var ubuntuEnv = map[string]string{
	"APACHE_RUN_USER": "www-data", "APACHE_RUN_GROUP": "www-data",
	"APACHE_PID_FILE": "/var/run/apache2/apache2.pid", "APACHE_RUN_DIR": "/var/run/apache2",
	"APACHE_LOCK_DIR": "/var/lock/apache2", "APACHE_LOG_DIR": "/var/log/apache2",
}

type fixture struct {
	dir   string
	opts  Options
	files []string // apache2 -t -D DUMP_INCLUDES, in order
	sRaw  string   // apache2 -S
}

var (
	serverRootLine = regexp.MustCompile(`(?m)^ServerRoot: "([^"]+)"`)
	includeLine    = regexp.MustCompile(`(?m)^\s*\((?:\*|\d+)\) (/\S+)$`)
)

func fixtures(t *testing.T) []fixture {
	t.Helper()
	dirs, _ := filepath.Glob("testdata/*/apache2-S.txt")
	if len(dirs) == 0 {
		t.Fatal("no fixtures")
	}
	var out []fixture
	for _, f := range dirs {
		dir := filepath.Dir(f)
		s, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		inc, err := os.ReadFile(filepath.Join(dir, "apache2-includes.txt"))
		if err != nil {
			t.Fatal(err)
		}
		m := serverRootLine.FindStringSubmatch(string(s))
		if m == nil {
			t.Fatalf("%s: no ServerRoot line", f)
		}
		fx := fixture{dir: dir, sRaw: string(s), opts: Options{ServerRoot: m[1], ConfigFile: DebianConfig, Env: ubuntuEnv}}
		for _, im := range includeLine.FindAllStringSubmatch(string(inc), -1) {
			if !slices.Contains(fx.files, im[1]) {
				fx.files = append(fx.files, im[1])
			}
		}
		out = append(out, fx)
	}
	return out
}

func TestLoaderReadsWhatApacheIncludes(t *testing.T) {
	for _, fx := range fixtures(t) {
		t.Run(filepath.Base(fx.dir), func(t *testing.T) {
			res := Load(rootfs.Walker(filepath.Join(fx.dir, "root")), fx.opts)
			if !slices.Equal(res.Files, fx.files) {
				t.Fatalf("files = %v\nDUMP_INCLUDES = %v", res.Files, fx.files)
			}
			if len(res.Notes) != 0 {
				t.Errorf("notes = %v", res.Notes)
			}
		})
	}
}

// Every (address, file:line) pair `apache2 -S` lists is a virtual host the loader found,
// and the other way round.
func TestVirtualHostsMatchApacheS(t *testing.T) {
	src := regexp.MustCompile(`\((/[^)]+:\d+)\)`)
	for _, fx := range fixtures(t) {
		t.Run(filepath.Base(fx.dir), func(t *testing.T) {
			var want []string
			addr := ""
			for _, line := range strings.Split(fx.sRaw, "\n") {
				if line == "" || strings.HasPrefix(line, "VirtualHost configuration") {
					continue
				}
				if line[0] != ' ' {
					addr = strings.Fields(line)[0]
				}
				if m := src.FindStringSubmatch(line); m != nil && !slices.Contains(want, addr+" "+m[1]) {
					want = append(want, addr+" "+m[1])
				}
			}
			_, vhosts := load(rootfs.Walker(filepath.Join(fx.dir, "root")), fx.opts)
			var got []string
			for _, v := range vhosts {
				for _, a := range v.addrs {
					got = append(got, a+" "+v.source)
				}
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("vhosts = %v\napache2 -S = %v", got, want)
			}
		})
	}
}

func TestRoutesFromConfigs(t *testing.T) {
	for _, fx := range fixtures(t) {
		t.Run(filepath.Base(fx.dir), func(t *testing.T) {
			got := conf.Render(Load(rootfs.Walker(filepath.Join(fx.dir, "root")), fx.opts))
			golden := filepath.Join(fx.dir, "routes.txt")
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
