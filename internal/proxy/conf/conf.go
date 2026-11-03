// Package conf holds what the proxy config parsers share: the parsed route types, the
// limits on reading, glob expansion as glob(3) does it, an in-memory FS for recorded
// dumps, and static name resolution (no DNS).
package conf

import (
	"fmt"
	"net/netip"
	"slices"
)

// Limits on one proxy's configuration: a config past them is cut off with a note.
const (
	MaxFiles      = 4096
	MaxTotalBytes = 16 << 20
	MaxDepth      = 32
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
}

// Reader tracks the files of one load: limits, include depth, notes, watch list.
type Reader struct {
	files   []string
	watch   []string
	notes   []string
	total   int
	seenRd  map[string]bool
	seenW   map[string]bool
	limited bool
}

// NewReader starts a load.
func NewReader() *Reader {
	return &Reader{seenRd: make(map[string]bool), seenW: make(map[string]bool)}
}

// Note records a problem (deduplicated).
func (r *Reader) Note(format string, args ...any) {
	n := fmt.Sprintf(format, args...)
	if !slices.Contains(r.notes, n) {
		r.notes = append(r.notes, n)
	}
}

// Watch adds a path to the watch list.
func (r *Reader) Watch(p string) {
	if !r.seenW[p] {
		r.seenW[p] = true
		r.watch = append(r.watch, p)
	}
}

// Read reads a file through fsys within the limits; ok is false (with a note) when it
// cannot be read or a limit is reached.
func (r *Reader) Read(fsys FS, p string) ([]byte, bool) {
	r.Watch(p)
	if r.limited {
		return nil, false
	}
	if len(r.files) >= MaxFiles {
		r.limited = true
		r.Note("config cut off: more than %d files", MaxFiles)
		return nil, false
	}
	b, err := fsys.ReadFile(p)
	if err != nil {
		r.Note("unreadable %s", ErrText(err))
		return nil, false
	}
	if r.total+len(b) > MaxTotalBytes {
		r.limited = true
		r.Note("config cut off: more than %d bytes", MaxTotalBytes)
		return nil, false
	}
	r.total += len(b)
	if !r.seenRd[p] {
		r.seenRd[p] = true
		r.files = append(r.files, p)
	}
	return b, true
}

// Finish returns the files, watch list and notes of the load.
func (r *Reader) Finish(routes []Route) Result {
	return Result{Routes: routes, Files: r.files, Watch: r.watch, Notes: r.notes}
}
