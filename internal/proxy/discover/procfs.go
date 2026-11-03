package discover

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// maxExeBytes bounds the scan of a proxy binary for its compiled-in defaults.
const maxExeBytes = 64 << 20

// ProcFS reads /proc (CAP_SYS_PTRACE lets the agent read other users' exe, environ and
// ns links).
type ProcFS struct {
	Root string // "/proc"

	mu    sync.Mutex
	found map[binKey]scanResult
}

type binKey struct {
	dev, ino     uint64
	size         int64
	mtime        time.Time
	prefix, stop string
}

type scanResult struct {
	value string
	ok    bool
}

// NewProcFS reads under root ("/proc").
func NewProcFS(root string) *ProcFS { return &ProcFS{Root: root, found: make(map[binKey]scanResult)} }

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

// ExeString finds prefix in the process's executable (read through /proc/<pid>/exe, at
// most 64 MiB, streamed) and returns what follows it up to the first byte of stop (at
// most 4096 bytes). Results are cached by file identity and prefix, never the file.
func (p *ProcFS) ExeString(pid uint32, prefix, stop string) (string, bool) {
	f, err := os.Open(p.path(pid, "exe"))
	if err != nil {
		return "", false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", false
	}
	key := binKey{size: fi.Size(), mtime: fi.ModTime(), prefix: prefix, stop: stop}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		key.dev, key.ino = uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // int32 on darwin
	}
	p.mu.Lock()
	r, ok := p.found[key]
	p.mu.Unlock()
	if ok {
		return r.value, r.ok
	}
	v, found := scanFor(io.LimitReader(f, maxExeBytes), []byte(prefix), stop, maxValue)
	p.mu.Lock()
	if len(p.found) >= 256 {
		clear(p.found)
	}
	p.found[key] = scanResult{v, found}
	p.mu.Unlock()
	return v, found
}

const maxValue = 4096

// scanFor streams r looking for prefix and returns the bytes after it up to a byte of
// stop, if that comes within max bytes.
func scanFor(r io.Reader, prefix []byte, stop string, max int) (string, bool) {
	const chunk = 64 << 10
	buf := make([]byte, 0, chunk+len(prefix)+max)
	tmp := make([]byte, chunk)
	eof := false
	for {
		if !eof {
			n, err := r.Read(tmp)
			buf = append(buf, tmp[:n]...)
			eof = err != nil
		}
		if i := bytes.Index(buf, prefix); i >= 0 {
			rest := buf[i+len(prefix):]
			if j := bytes.IndexAny(rest, stop); j >= 0 && j <= max {
				return string(rest[:j]), true
			}
			if len(rest) > max || eof {
				return "", false
			}
			continue // the value runs past what was read
		}
		if eof {
			return "", false
		}
		if keep := len(prefix) - 1; len(buf) > keep {
			buf = append(buf[:0], buf[len(buf)-keep:]...)
		}
	}
}

// EUID reads the effective uid from /proc/<pid>/status.
func (p *ProcFS) EUID(pid uint32) (uint32, bool) {
	b, err := os.ReadFile(p.path(pid, "status"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(rest)
			if len(f) < 2 {
				return 0, false
			}
			v, err := strconv.ParseUint(f[1], 10, 32)
			return uint32(v), err == nil
		}
	}
	return 0, false
}

// ExeOwner stats /proc/<pid>/exe, which is the file the process runs.
func (p *ProcFS) ExeOwner(pid uint32) (uint32, fs.FileMode, bool) {
	fi, err := os.Stat(p.path(pid, "exe"))
	if err != nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, fi.Mode().Perm(), true
}

// OldestChildStart reads the children of the process's main thread
// (/proc/<pid>/task/<pid>/children) and returns the earliest start time among them.
func (p *ProcFS) OldestChildStart(pid uint32) (time.Time, bool) {
	b, err := os.ReadFile(p.path(pid, "task/"+strconv.FormatUint(uint64(pid), 10)+"/children"))
	if err != nil {
		return time.Time{}, false
	}
	boot, ok := p.bootTime()
	if !ok {
		return time.Time{}, false
	}
	var oldest time.Time
	for _, f := range strings.Fields(string(b)) {
		c, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			continue
		}
		st, err := os.ReadFile(p.path(uint32(c), "stat"))
		if err != nil {
			continue
		}
		i := bytes.LastIndexByte(st, ')')
		if i < 0 {
			continue
		}
		fields := strings.Fields(string(st[i+1:]))
		if len(fields) < 20 {
			continue
		}
		ticks, err := strconv.ParseUint(fields[19], 10, 64) // starttime, field 22
		if err != nil {
			continue
		}
		start := boot.Add(time.Duration(ticks) * time.Second / clockTicks)
		if oldest.IsZero() || start.Before(oldest) {
			oldest = start
		}
	}
	return oldest, !oldest.IsZero()
}

// clockTicks is USER_HZ, 100 on every Linux the agent supports.
const clockTicks = 100

func (p *ProcFS) bootTime() (time.Time, bool) {
	b, err := os.ReadFile(filepath.Join(p.Root, "stat"))
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			v, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			return time.Unix(v, 0), err == nil
		}
	}
	return time.Time{}, false
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
