package rootfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxLinkHops = 40

// errTooManyLinks mirrors ELOOP.
var errTooManyLinks = errors.New("too many levels of symbolic links")

// Walker resolves paths under root in user space, one component at a time, treating
// root as "/" for absolute symlinks and "..". It is portable (tests run it on macOS);
// on Linux Open uses openat2(RESOLVE_IN_ROOT) instead, which the kernel resolves
// without the race between resolving and opening.
func Walker(root string) FS { return walker{root: filepath.Clean(root)} }

type walker struct{ root string }

func (w walker) Close() error { return nil }

func (w walker) ReadFile(p string) ([]byte, error) {
	b, _, err := w.ReadFileInfo(p)
	return b, err
}

func (w walker) ReadFileInfo(p string) ([]byte, Info, error) {
	host, err := w.resolve(p)
	if err != nil {
		return nil, Info{}, err
	}
	fi, err := os.Stat(host)
	if err != nil {
		return nil, Info{}, w.rename(err, p)
	}
	if !fi.Mode().IsRegular() {
		// Checked before opening: opening a FIFO would block.
		return nil, Info{}, &fs.PathError{Op: "read", Path: p, Err: errors.New("not a regular file")}
	}
	f, err := os.Open(host)
	if err != nil {
		return nil, Info{}, w.rename(err, p)
	}
	defer f.Close()
	ofi, err := f.Stat()
	if err != nil {
		return nil, Info{}, w.rename(err, p)
	}
	b, err := readBounded(f)
	if err != nil {
		return nil, Info{}, &fs.PathError{Op: "read", Path: p, Err: err}
	}
	return b, infoOf(ofi), nil
}

func (w walker) ReadDir(p string) ([]string, error) {
	host, err := w.resolve(p)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(host)
	if err != nil {
		return nil, w.rename(err, p)
	}
	defer f.Close()
	names, err := sortedNames(f)
	if err != nil {
		return nil, w.rename(err, p)
	}
	return names, nil
}

func (w walker) Stat(p string) (Info, error) {
	host, err := w.resolve(p)
	if err != nil {
		return Info{}, err
	}
	fi, err := os.Stat(host)
	if err != nil {
		return Info{}, w.rename(err, p)
	}
	return infoOf(fi), nil
}

// rename reports errors with the in-root path, not the host path.
func (w walker) rename(err error, p string) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return &fs.PathError{Op: pe.Op, Path: p, Err: pe.Err}
	}
	return err
}

// resolve maps an in-root path to a host path whose every component is a real
// directory or file (no symlink left), never above root.
func (w walker) resolve(p string) (string, error) {
	if !path.IsAbs(p) {
		return "", &fs.PathError{Op: "open", Path: p, Err: errors.New("path is not absolute")}
	}
	var done []string // resolved components under root
	todo := splitPath(p)
	hops := 0
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case ".":
			continue
		case "..":
			if len(done) > 0 {
				done = done[:len(done)-1]
			}
			continue
		}
		host := filepath.Join(w.root, filepath.Join(done...), c)
		fi, err := os.Lstat(host)
		if err != nil {
			if len(todo) == 0 {
				// The last component may not exist; the caller's open reports it.
				return host, nil
			}
			return "", w.rename(err, p)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			done = append(done, c)
			continue
		}
		hops++
		if hops > maxLinkHops {
			return "", &fs.PathError{Op: "open", Path: p, Err: errTooManyLinks}
		}
		target, err := os.Readlink(host)
		if err != nil {
			return "", w.rename(err, p)
		}
		if path.IsAbs(target) {
			done = nil
		}
		todo = append(splitPath(target), todo...)
	}
	return filepath.Join(w.root, filepath.Join(done...)), nil
}

func splitPath(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// String is for debugging.
func (w walker) String() string { return fmt.Sprintf("walker(%s)", w.root) }
