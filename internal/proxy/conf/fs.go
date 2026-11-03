package conf

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

// FS is the read access the loaders need (rootfs.FS without Close).
type FS interface {
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]string, error)
	Stat(path string) (rootfs.Info, error)
}

// MemFS serves recorded files (a proxy's own dump) by absolute path; directories are
// implied by the paths.
type MemFS map[string][]byte

func (m MemFS) ReadFile(p string) ([]byte, error) {
	if b, ok := m[path.Clean(p)]; ok {
		return b, nil
	}
	if m.isDir(p) {
		return nil, &fs.PathError{Op: "read", Path: p, Err: errors.New("is a directory")}
	}
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}

func (m MemFS) ReadDir(p string) ([]string, error) {
	dir := strings.TrimSuffix(path.Clean(p), "/") + "/"
	seen := make(map[string]bool)
	var names []string
	for f := range m {
		rest, ok := strings.CutPrefix(f, dir)
		if !ok || rest == "" {
			continue
		}
		name, _, _ := strings.Cut(rest, "/")
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 && !m.isDir(p) {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	slices.Sort(names)
	return names, nil
}

func (m MemFS) Stat(p string) (rootfs.Info, error) {
	if b, ok := m[path.Clean(p)]; ok {
		return rootfs.Info{Size: int64(len(b)), ModTime: time.Unix(0, 0)}, nil
	}
	if m.isDir(p) {
		return rootfs.Info{Dir: true}, nil
	}
	return rootfs.Info{}, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
}

func (m MemFS) isDir(p string) bool {
	dir := strings.TrimSuffix(path.Clean(p), "/") + "/"
	if dir == "//" {
		return len(m) > 0
	}
	for f := range m {
		if strings.HasPrefix(f, dir) {
			return true
		}
	}
	return false
}

// ErrText renders an fs error as "<path>: <reason>" with the reason in lower case, as
// strerror prints it (e.g. "/etc/x: permission denied").
func ErrText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Path + ": " + pe.Err.Error()
	}
	return err.Error()
}
