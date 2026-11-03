package procinfo

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

// rewalkInterval is the minimum gap between two walks of the cgroup tree.
const rewalkInterval = 10 * time.Second

// Resolver enriches a model.Process from /proc and the cgroup v2 tree.
type Resolver struct {
	procRoot, cgroupRoot string
	hashMax              int64

	open func(string) (*os.File, error) // test seam: opens an exe for hashing
	now  func() time.Time               // test seam: clock for the rewalk limit

	// hostCgroup maps a /proc cgroup path to the host's (cgroupns.Translator.Host);
	// nil is the identity.
	hostCgroup func(string) string

	mu       sync.Mutex
	hashes   map[fileID]string
	cgroups  map[uint64]string // cgroup id (dir inode) -> path relative to cgroupRoot
	lastWalk time.Time
}

// NewResolver reads process details under procRoot ("/proc") and resolves cgroup
// ids against cgroupRoot ("/sys/fs/cgroup"). Executables larger than hashMax
// bytes are not hashed.
func NewResolver(procRoot, cgroupRoot string, hashMax int64) *Resolver {
	return &Resolver{
		procRoot: procRoot, cgroupRoot: cgroupRoot, hashMax: hashMax,
		open: os.Open, now: time.Now,
		hashes: make(map[fileID]string),
	}
}

// SetCgroupTranslator sets how /proc cgroup paths become host paths when the agent runs
// in a private cgroup namespace (cgroupns.Translator.Host). Call it before Enrich.
func (r *Resolver) SetCgroupTranslator(host func(string) string) { r.hostCgroup = host }

// Enrich fills the empty Exe, Cmdline, SHA256, Unit and Container fields of p from
// /proc/<pid>, or from p.CgroupID when the process has already exited. It never
// fails: whatever cannot be read stays empty. Fields already set are kept.
func (r *Resolver) Enrich(p model.Process) model.Process {
	dir := filepath.Join(r.procRoot, strconv.FormatUint(uint64(p.PID), 10))
	exe := filepath.Join(dir, "exe")

	if p.Exe == "" {
		if target, err := os.Readlink(exe); err == nil {
			p.Exe = target
		}
	}
	if len(p.Cmdline) == 0 {
		p.Cmdline = readCmdline(filepath.Join(dir, "cmdline"))
	}
	if p.SHA256 == "" {
		p.SHA256 = r.hashExe(exe)
	}
	if p.Unit == "" || p.Container == (model.Container{}) {
		if path, ok := r.cgroupPath(dir, p.CgroupID); ok {
			unit, c := ParseCgroupPath(path)
			if p.Unit == "" {
				p.Unit = unit
			}
			if p.Container == (model.Container{}) {
				p.Container = c
			}
		}
	}
	return p
}

// readCmdline splits /proc/<pid>/cmdline on NULs; nil when unreadable or empty.
func readCmdline(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	b = bytes.TrimSuffix(b, []byte{0})
	return strings.Split(string(b), "\x00")
}

// cgroupPath returns the cgroup v2 path of the process, from its /proc cgroup file
// or, when that is gone, from the cgroup id.
func (r *Resolver) cgroupPath(procDir string, id uint64) (string, bool) {
	if b, err := os.ReadFile(filepath.Join(procDir, "cgroup")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if path, ok := strings.CutPrefix(line, "0::"); ok {
				if r.hostCgroup != nil {
					path = r.hostCgroup(path)
				}
				return path, true
			}
		}
	}
	if id == 0 {
		return "", false
	}
	return r.lookupCgroupID(id)
}

// lookupCgroupID maps a cgroup id (the inode of its directory) to its path,
// walking the cgroup tree on a miss at most once per rewalkInterval.
func (r *Resolver) lookupCgroupID(id uint64) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path, ok := r.cgroups[id]; ok {
		return path, true
	}
	if now := r.now(); r.cgroups == nil || now.Sub(r.lastWalk) >= rewalkInterval {
		r.cgroups = r.walkCgroups()
		r.lastWalk = now
	}
	path, ok := r.cgroups[id]
	return path, ok
}

func (r *Resolver) walkCgroups() map[uint64]string {
	ids := make(map[uint64]string)
	// Errors on single entries (cgroups vanish while walking) are skipped.
	_ = filepath.WalkDir(r.cgroupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(r.cgroupRoot, path)
		if err != nil {
			return nil
		}
		if rel == "." {
			rel = ""
		}
		ids[uint64(st.Ino)] = "/" + filepath.ToSlash(rel)
		return nil
	})
	return ids
}
