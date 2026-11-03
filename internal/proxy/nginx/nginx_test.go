package nginx

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
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
			got := conf.Render(Load(files, main))
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
