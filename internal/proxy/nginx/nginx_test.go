package nginx

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

var update = flag.Bool("update", false, "rewrite the routes.txt golden files")

// cases are the testdata directories that hold a recorded `nginx -T` (nginx-T.txt) and,
// for most, the config tree it was recorded from (root/).
func cases(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob("testdata/*/nginx-T.txt")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for i, d := range dirs {
		dirs[i] = filepath.Dir(d)
	}
	return dirs
}

func dump(t *testing.T, dir string) (string, conf.MemFS, []string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "nginx-T.txt"))
	if err != nil {
		t.Fatal(err)
	}
	main, files, order, err := ParseDump(b)
	if err != nil {
		t.Fatal(err)
	}
	return main, files, order
}

// The loader, reading the config tree itself, must load exactly the files nginx -T
// dumped, in the same order, with the same content.
func TestLoaderReadsWhatNginxDumps(t *testing.T) {
	for _, dir := range cases(t) {
		root := filepath.Join(dir, "root")
		if _, err := os.Stat(root); err != nil {
			continue
		}
		t.Run(filepath.Base(dir), func(t *testing.T) {
			main, files, order := dump(t, dir)
			res := Load(rootfs.Walker(root), main)
			if !slices.Equal(res.Files, order) {
				t.Fatalf("files = %v\nnginx -T = %v", res.Files, order)
			}
			for _, f := range res.Files {
				got, err := rootfs.Walker(root).ReadFile(f)
				if err != nil || string(got) != string(files[f]) {
					t.Errorf("%s differs from the dump (%v)", f, err)
				}
			}
			if len(res.Notes) != 0 {
				t.Errorf("notes = %v", res.Notes)
			}
		})
	}
}

// Routes parsed from each recorded dump match the reviewed golden file.
func TestRoutesFromDumps(t *testing.T) {
	for _, dir := range cases(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			main, files, _ := dump(t, dir)
			got := Render(Load(files, main))
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

// Render prints routes one per line for golden files.
func Render(res conf.Result) string {
	var b strings.Builder
	for _, r := range res.Routes {
		fmt.Fprintf(&b, "%s names=%s path=%q %s %q", strings.Join(r.Listen, ","), strings.Join(r.ServerNames, ","), r.Path, r.Kind, r.Target)
		if r.Upstream != "" {
			fmt.Fprintf(&b, " upstream=%s", r.Upstream)
		}
		if r.Root != "" {
			fmt.Fprintf(&b, " root=%s", r.Root)
		}
		for _, be := range r.Backends {
			fmt.Fprintf(&b, "\n    -> %s", be.Address)
			for _, a := range be.Addrs {
				fmt.Fprintf(&b, " %s", a)
			}
			if be.Unix != "" {
				fmt.Fprintf(&b, " unix=%s", be.Unix)
			}
			if be.Note != "" {
				fmt.Fprintf(&b, " (%s)", be.Note)
			}
		}
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "\n    note: %s", n)
		}
		fmt.Fprintf(&b, "\n    @ %s\n", r.Source)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(&b, "config note: %s\n", n)
	}
	return b.String()
}
