package discover

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// maxExeBytes bounds the read of a proxy binary for its compiled-in defaults.
const maxExeBytes = 64 << 20

// ProcFS reads /proc (CAP_SYS_PTRACE lets the agent read other users' exe, environ and
// ns links). Binaries are cached by file identity.
type ProcFS struct {
	Root string // "/proc"

	mu   sync.Mutex
	bins map[binKey][]byte
}

type binKey struct {
	dev, ino uint64
	size     int64
	mtime    time.Time
}

// NewProcFS reads under root ("/proc").
func NewProcFS(root string) *ProcFS { return &ProcFS{Root: root, bins: make(map[binKey][]byte)} }

func (p *ProcFS) path(pid uint32, name string) string {
	return filepath.Join(p.Root, strconv.FormatUint(uint64(pid), 10), name)
}

// PPID reads the parent from /proc/<pid>/stat (the field after the state, after the
// last ')' since comm may hold spaces and parentheses).
func (p *ProcFS) PPID(pid uint32) (uint32, bool) {
	b, err := os.ReadFile(p.path(pid, "stat"))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[1], 10, 32)
	return uint32(v), err == nil
}

func (p *ProcFS) Exe(pid uint32) string {
	s, err := os.Readlink(p.path(pid, "exe"))
	if err != nil {
		return ""
	}
	return s
}

func (p *ProcFS) Cmdline(pid uint32) []string {
	return nulFields(p.path(pid, "cmdline"))
}

func (p *ProcFS) Environ(pid uint32) map[string]string {
	env := make(map[string]string)
	for _, kv := range nulFields(p.path(pid, "environ")) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

// MountNS is the inode of /proc/<pid>/ns/mnt.
func (p *ProcFS) MountNS(pid uint32) (uint64, bool) {
	return nsInode(p.path(pid, "ns/mnt"))
}

// SelfMountNS is the agent's own mount namespace.
func (p *ProcFS) SelfMountNS() (uint64, bool) {
	return nsInode(filepath.Join(p.Root, "self/ns/mnt"))
}

func nsInode(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true
}

// ExeBytes reads the process's executable through /proc/<pid>/exe (at most 64 MiB; nil
// when larger or unreadable), cached by its identity.
func (p *ProcFS) ExeBytes(pid uint32) []byte {
	f, err := os.Open(p.path(pid, "exe"))
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() > maxExeBytes {
		return nil
	}
	key := binKey{size: fi.Size(), mtime: fi.ModTime()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		key.dev, key.ino = uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // int32 on darwin
	}
	p.mu.Lock()
	b, ok := p.bins[key]
	p.mu.Unlock()
	if ok {
		return b
	}
	b, err = io.ReadAll(io.LimitReader(f, maxExeBytes))
	if err != nil {
		return nil
	}
	p.mu.Lock()
	if len(p.bins) >= 8 {
		clear(p.bins)
	}
	p.bins[key] = b
	p.mu.Unlock()
	return b
}

// Cgroup is the cgroup v2 path from /proc/<pid>/cgroup.
func (p *ProcFS) Cgroup(pid uint32) string {
	b, err := os.ReadFile(p.path(pid, "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return path
		}
	}
	return ""
}

func nulFields(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	return strings.Split(string(bytes.TrimSuffix(b, []byte{0})), "\x00")
}
