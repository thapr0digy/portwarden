package fuzzcheck

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// ProxyBudget is what one proxy config load may spend. It is tied to the read limit, not
// to the input: a short tree can include the same file many times and read up to
// conf.MaxTotalBytes legitimately. Loads allocate about 60 bytes per byte read (nginx at
// the read limit, the densest measured), so 100 per byte read is above any load within
// the limits, and far below a blow-up.
var ProxyBudget = Budget{Time: 2 * time.Second, Base: 100 * conf.MaxTotalBytes}

// ProxyHeapLimit bounds the heap one proxy config load may grow by. The agent's
// Kubernetes limit is 256 MiB (deploy/kubernetes/daemonset.yaml) for everything it holds;
// one load, which any container's image controls, may take at most a third of it.
const ProxyHeapLimit = 85 << 20

// AtReadLimit runs load, which must read up to conf.MaxTotalBytes and be cut off there,
// and fails t when it exceeds ProxyBudget or grows the heap past ProxyHeapLimit.
func AtReadLimit(t testing.TB, load func() conf.Result) {
	t.Helper()
	var res conf.Result
	var s Spent
	peak, before := PeakHeap(func() { s = Bounded(t, ProxyBudget, conf.MaxTotalBytes, func() { res = load() }) })
	if !strings.Contains(strings.Join(res.Notes, "\n"), "cut off") {
		t.Fatalf("the load must reach the read limit; notes = %q", res.Notes)
	}
	if grew := peak - min(peak, before); grew > ProxyHeapLimit {
		t.Errorf("heap grew by %d MiB, limit %d MiB", grew>>20, ProxyHeapLimit>>20)
	}
	t.Logf("%d routes, %v, %d MiB allocated, heap peak %d MiB over %d MiB", len(res.Routes), s.Time, s.Bytes>>20, (peak-min(peak, before))>>20, before>>20)
}

// ProxySeeds packs every testdata/*/root tree of a loader's package into a fuzz seed,
// with the tree's main config (the one file matching mainGlob inside root) first.
func ProxySeeds(t testing.TB, mainGlob string) [][]byte {
	t.Helper()
	roots, _ := filepath.Glob("testdata/*/root")
	var out [][]byte
	for _, root := range roots {
		mains, _ := filepath.Glob(filepath.Join(root, mainGlob))
		if len(mains) != 1 {
			continue
		}
		fsys, err := conf.LoadTree(root)
		if err != nil {
			t.Fatal(err)
		}
		main := "/" + filepath.ToSlash(strings.TrimPrefix(mains[0], root+string(filepath.Separator)))
		out = append(out, conf.EncodeFiles(main, fsys))
	}
	if len(out) == 0 {
		t.Fatalf("no testdata/*/root/%s seeds", mainGlob)
	}
	return out
}

// ProxyResult fails t when a load's result breaks the conf limits or names a source
// outside the files it read.
func ProxyResult(t testing.TB, res conf.Result) {
	t.Helper()
	if len(res.Notes) > conf.MaxNotes+1 {
		t.Errorf("%d notes, limit %d", len(res.Notes), conf.MaxNotes+1)
	}
	if len(res.Watch) > conf.MaxWatch {
		t.Errorf("%d watched paths, limit %d", len(res.Watch), conf.MaxWatch)
	}
	if len(res.Files) > conf.MaxFiles {
		t.Errorf("%d files read, limit %d", len(res.Files), conf.MaxFiles)
	}
	for _, r := range res.Routes {
		if r.Source == "" {
			continue
		}
		file := r.Source
		if i := strings.LastIndexByte(file, ':'); i > 0 {
			file = file[:i]
		}
		if !slices.Contains(res.Files, file) {
			t.Errorf("route source %q is not among the files read %v", r.Source, res.Files)
		}
	}
}
