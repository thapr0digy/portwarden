package procinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

const hex64 = "abababababababababababababababababababababababababababababababab"

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeProc builds <proc>/<pid>/{exe,cmdline,cgroup} and returns the exe target.
func fakeProc(t *testing.T, proc string, pid int, exeContent string) string {
	t.Helper()
	dir := filepath.Join(proc, "42")
	target := filepath.Join(t.TempDir(), "nginx")
	writeFile(t, target, exeContent)
	writeFile(t, filepath.Join(dir, "cmdline"), "nginx: master\x00-g\x00")
	writeFile(t, filepath.Join(dir, "cgroup"), "0::/system.slice/nginx.service\n")
	if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestEnrichReadsProc(t *testing.T) {
	proc := t.TempDir()
	target := fakeProc(t, proc, 42, "binary-bytes")
	sum := sha256.Sum256([]byte("binary-bytes"))

	got := NewResolver(proc, t.TempDir(), 1<<20).Enrich(model.Process{PID: 42})

	if got.Exe != target {
		t.Errorf("Exe = %q, want %q", got.Exe, target)
	}
	if want := []string{"nginx: master", "-g"}; !reflect.DeepEqual(got.Cmdline, want) {
		t.Errorf("Cmdline = %q, want %q", got.Cmdline, want)
	}
	if got.Unit != "nginx.service" {
		t.Errorf("Unit = %q", got.Unit)
	}
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %q", got.SHA256)
	}
}

func TestEnrichExitedProcessUsesCgroupID(t *testing.T) {
	cg := t.TempDir()
	dir := filepath.Join(cg, "system.slice", "docker-"+hex64+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := fi.Sys().(*syscall.Stat_t).Ino

	got := NewResolver(t.TempDir(), cg, 1<<20).Enrich(model.Process{PID: 42, CgroupID: uint64(id)})

	if got.Unit != "docker-"+hex64+".scope" {
		t.Errorf("Unit = %q", got.Unit)
	}
	if got.Container != (model.Container{Runtime: "docker", ID: hex64}) {
		t.Errorf("Container = %+v", got.Container)
	}
	if got.Exe != "" || got.Cmdline != nil || got.SHA256 != "" {
		t.Errorf("exited process got proc fields: %+v", got)
	}
}

func TestHashCachedByFileIdentity(t *testing.T) {
	proc := t.TempDir()
	fakeProc(t, proc, 42, "binary-bytes")
	r := NewResolver(proc, t.TempDir(), 1<<20)

	if first := r.Enrich(model.Process{PID: 42}); first.SHA256 == "" || len(r.hashes) != 1 {
		t.Fatalf("SHA256 = %q, cached %d", first.SHA256, len(r.hashes))
	}
	// An unchanged file is served from the cache, not hashed again.
	for id := range r.hashes {
		r.hashes[id] = "cached"
	}
	if second := r.Enrich(model.Process{PID: 42}); second.SHA256 != "cached" {
		t.Errorf("SHA256 = %q, want the cached value", second.SHA256)
	}
}

func TestHashSkipsOversize(t *testing.T) {
	proc := t.TempDir()
	fakeProc(t, proc, 42, strings.Repeat("x", 100))

	got := NewResolver(proc, t.TempDir(), 99).Enrich(model.Process{PID: 42})

	if got.SHA256 != "" {
		t.Errorf("SHA256 = %q, want empty", got.SHA256)
	}
	if got.Exe == "" {
		t.Error("Exe should still be filled")
	}
}

func TestEnrichKeepsGivenFields(t *testing.T) {
	proc := t.TempDir()
	fakeProc(t, proc, 42, "binary-bytes")
	given := model.Process{
		PID: 42, Exe: "/probe/exe", Cmdline: []string{"probe"}, SHA256: "given",
		Unit: "probe.service", Container: model.Container{Runtime: "x", ID: "y"},
	}

	got := NewResolver(proc, t.TempDir(), 1<<20).Enrich(given)

	if !got.Equal(given) {
		t.Errorf("Enrich overwrote fields: %+v", got)
	}
}

func TestCgroupIDRewalkRateLimited(t *testing.T) {
	cg := t.TempDir()
	now := time.Unix(100, 0)
	r := NewResolver(t.TempDir(), cg, 1<<20)
	r.now = func() time.Time { return now }

	r.Enrich(model.Process{PID: 1, CgroupID: 999999999}) // first miss walks
	dir := filepath.Join(cg, "system.slice", "late.service")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dir)
	id := uint64(fi.Sys().(*syscall.Stat_t).Ino)

	if got := r.Enrich(model.Process{PID: 1, CgroupID: id}); got.Unit != "" {
		t.Errorf("rewalked inside 10s window: %q", got.Unit)
	}
	now = now.Add(11 * time.Second)
	if got := r.Enrich(model.Process{PID: 1, CgroupID: id}); got.Unit != "late.service" {
		t.Errorf("Unit after window = %q", got.Unit)
	}
}

func TestHashCacheMissesOnInPlaceRewrite(t *testing.T) {
	proc := t.TempDir()
	target := fakeProc(t, proc, 42, "binary-AAAA")
	r := NewResolver(proc, t.TempDir(), 1<<20)
	first := r.Enrich(model.Process{PID: 42})
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	mtime := fi.ModTime()

	time.Sleep(20 * time.Millisecond) // past coarse ctime granularity
	// Same inode, same size, mtime put back: only ctime tells the versions apart.
	if err := os.WriteFile(target, []byte("binary-BBBB"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(target, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	second := r.Enrich(model.Process{PID: 42})

	sum := sha256.Sum256([]byte("binary-BBBB"))
	if second.SHA256 != hex.EncodeToString(sum[:]) || second.SHA256 == first.SHA256 {
		t.Fatalf("SHA256 after rewrite = %q, want hash of new content (first %q)", second.SHA256, first.SHA256)
	}
}
