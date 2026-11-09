// Package conf holds what the proxy config parsers share: the parsed route types, the
// limits on reading, glob expansion as glob(3) does it, an in-memory FS for recorded
// dumps, and static name resolution (no DNS).
package conf

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Limits on one proxy's configuration. Every limit, when hit, cuts the load off with
// one note; nothing grows past them, however hostile the config.
const (
	// MaxFiles bounds the files a load tries to read (failures count too).
	MaxFiles = 4096
	// MaxTotalBytes bounds the bytes read. A load's heap peaks at up to 27 times the bytes
	// it reads (HAProxy's routes, nginx's directive tree), and any container's image
	// controls its proxy config: 2 MiB keeps one load near 55 MiB, well inside the agent's
	// 256 MiB Kubernetes limit (16 MiB took 276 MiB). Stock configs are 10 to 60 KiB, and
	// only the first 500 routes are published (proxy.MaxRoutes).
	MaxTotalBytes = 2 << 20
	MaxDepth      = 32
	// MaxOps bounds the filesystem operations of one load: every read, stat and
	// directory entry looked at.
	MaxOps = 20000
	// MaxGlobMatches bounds the paths one include pattern expands to.
	MaxGlobMatches = 4096
	// MaxNotes and MaxWatch bound the notes kept and the paths watched for changes.
	MaxNotes = 64
	MaxWatch = 4096
	// MaxExpansions bounds the targets one variable-built address expands to.
	MaxExpansions = 64
)

// Backend is one configured destination of a route.
type Backend struct {
	// Address as written: "127.0.0.1:8000", "unix:/run/app.sock", "app:8000", "$backend".
	Address string
	// Addrs are the resolved destinations (a name can resolve to several).
	Addrs []netip.AddrPort
	Unix  string
	// Note says why it is unresolved, or a server flag ("backup", "down").
	Note string
	// Server is the backend's name in the proxy, where it has one (an HAProxy server, a
	// server-template's prefix); used to match runtime state, not published.
	Server string
}

// Route is one routing rule as the config states it.
type Route struct {
	Listen      []string
	ServerNames []string
	Path        string
	Kind        string
	Target      string
	Upstream    string
	Root        string
	Source      string
	Notes       []string
	Backends    []Backend
}

// Result is a parsed configuration.
type Result struct {
	Routes []Route
	// Files lists every file read, in include order, once each.
	Files []string
	// Watch lists the files and directories whose change means the config may have
	// changed: every file read, every directory a glob listed, and every include
	// target that was missing.
	Watch []string
	Notes []string
	// Untrusted lists why files read are not trustworthy: not owned by root, or
	// writable by group or others.
	Untrusted []string
	// Newest is the latest modification time of the files read.
	Newest time.Time
	// AdminSockets are the runtime API endpoints the config declares (HAProxy's
	// "stats socket"), for the admin reader; never published as routes.
	AdminSockets []AdminSocket
}

// AdminSocket is a runtime/admin API endpoint a config declares.
type AdminSocket struct {
	// Network is "unix" (Addr is a path inside the proxy's root) or "tcp" (Addr is
	// host:port, host possibly empty or "*" for every address).
	Network, Addr string
	// Level is the access level written ("admin", "operator", "user"; "" when absent).
	Level string
	// Source is file:line.
	Source string
}

type fileID struct{ dev, ino uint64 }

// Reader tracks one load: its budget, include stack, notes, watch list and trust.
type Reader struct {
	files     []string
	watch     []string
	notes     []string
	untrusted []string
	newest    time.Time
	total     int
	attempts  int
	ops       int
	seenRd    map[string]bool
	seenW     map[string]bool
	stack     map[fileID]bool
	limited   bool
	moreNotes int
	watchCut  bool
}

// NewReader starts a load.
func NewReader() *Reader {
	return &Reader{seenRd: make(map[string]bool), seenW: make(map[string]bool), stack: make(map[fileID]bool)}
}

// Note records a problem (deduplicated; past MaxNotes only counted).
func (r *Reader) Note(format string, args ...any) {
	n := fmt.Sprintf(format, args...)
	if slices.Contains(r.notes, n) {
		return
	}
	if len(r.notes) >= MaxNotes {
		r.moreNotes++
		return
	}
	r.notes = append(r.notes, n)
}

// cut stops the load with one note.
func (r *Reader) cut(why string) {
	if !r.limited {
		r.limited = true
		r.Note("config cut off: %s", why)
	}
}

// Op spends one filesystem operation; false once the budget (or another limit) is
// spent.
func (r *Reader) Op() bool {
	if r.limited {
		return false
	}
	if r.ops >= MaxOps {
		r.cut(fmt.Sprintf("more than %d file operations", MaxOps))
		return false
	}
	r.ops++
	return true
}

// Spend counts n bytes the load produced without reading them (an expanded Apache
// macro) against MaxTotalBytes; false, with the load cut off, once that is exceeded.
func (r *Reader) Spend(n int) bool {
	if r.limited {
		return false
	}
	if r.total+n > MaxTotalBytes {
		r.cut(fmt.Sprintf("more than %d bytes", MaxTotalBytes))
		return false
	}
	r.total += n
	return true
}

// Watch adds a path to the watch list (bounded).
func (r *Reader) Watch(p string) {
	if r.seenW[p] {
		return
	}
	if len(r.watch) >= MaxWatch {
		if !r.watchCut {
			r.watchCut = true
			r.Note("watch list cut off at %d paths", MaxWatch)
		}
		return
	}
	r.seenW[p] = true
	r.watch = append(r.watch, p)
}

// Read reads a file within the limits; ok is false (with a note) when it cannot be
// read, a limit is reached, or it is already being included (a cycle).
func (r *Reader) Read(fsys FS, p string) ([]byte, bool) {
	b, ok, leave := r.Enter(fsys, p)
	leave()
	return b, ok
}

// Enter reads a file and puts it on the include stack until leave is called, so an
// include of a file already being read is refused as a cycle (by device and inode).
func (r *Reader) Enter(fsys FS, p string) (data []byte, ok bool, leave func()) {
	noop := func() {}
	r.Watch(p)
	if !r.Op() {
		return nil, false, noop
	}
	if r.attempts >= MaxFiles {
		r.cut(fmt.Sprintf("more than %d files", MaxFiles))
		return nil, false, noop
	}
	r.attempts++
	b, in, err := fsys.ReadFileInfo(p)
	if err != nil {
		r.Note("unreadable %s", ErrText(err))
		return nil, false, noop
	}
	id := fileID{in.Dev, in.Ino}
	if r.stack[id] {
		r.Note("include cycle at %s", p)
		return nil, false, noop
	}
	if r.total+len(b) > MaxTotalBytes {
		r.cut(fmt.Sprintf("more than %d bytes", MaxTotalBytes))
		return nil, false, noop
	}
	r.total += len(b)
	if !r.seenRd[p] {
		r.seenRd[p] = true
		r.files = append(r.files, p)
		switch {
		case in.Uid != 0:
			r.untrusted = append(r.untrusted, fmt.Sprintf("%s owned by uid %d", p, in.Uid))
		case in.Writable():
			r.untrusted = append(r.untrusted, fmt.Sprintf("%s writable by group or others (%v)", p, in.Mode))
		}
	}
	if in.ModTime.After(r.newest) {
		r.newest = in.ModTime
	}
	r.stack[id] = true
	return b, true, func() { delete(r.stack, id) }
}

// Finish returns the files, watch list, notes and trust findings of the load.
func (r *Reader) Finish(routes []Route) Result {
	notes := slices.Clone(r.notes)
	if r.moreNotes > 0 {
		notes = append(notes, fmt.Sprintf("... and %d more notes", r.moreNotes))
	}
	return Result{Routes: routes, Files: r.files, Watch: r.watch, Notes: notes, Untrusted: r.untrusted, Newest: r.newest}
}
