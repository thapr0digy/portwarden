// Package rootfs reads files as a process sees them: every path, and every symbolic link
// on the way, resolves inside a root directory ("/" for the host, /proc/<pid>/root for a
// container), so a container's absolute symlink cannot reach the host's files.
package rootfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"syscall"
	"time"
)

// MaxFileSize bounds a single ReadFile.
const MaxFileSize = 4 << 20

// ErrTooLarge is returned by ReadFile for a file over MaxFileSize.
var ErrTooLarge = errors.New("file too large")

// Info is what Stat returns: enough to notice a file being replaced or edited.
type Info struct {
	Dir     bool
	Size    int64
	ModTime time.Time
	Dev     uint64
	Ino     uint64
	// Uid owns the file; Mode holds its permission bits (as the root sees them).
	Uid  uint32
	Mode fs.FileMode
}

// Writable reports whether anyone but the owner may write the file.
func (i Info) Writable() bool { return i.Mode&0o022 != 0 }

// FS reads files under a root. Paths are absolute as the process inside the root sees
// them; symbolic links are followed inside the root.
type FS interface {
	ReadFile(path string) ([]byte, error)
	// ReadFileInfo reads a file and returns the Info of the very file read (fstat of
	// the open descriptor, so owner and mode cannot be swapped in between).
	ReadFileInfo(path string) ([]byte, Info, error)
	// ReadDir returns the entry names, sorted.
	ReadDir(path string) ([]string, error)
	Stat(path string) (Info, error)
	Close() error
}

func infoOf(fi fs.FileInfo) Info {
	in := Info{Dir: fi.IsDir(), Size: fi.Size(), ModTime: fi.ModTime(), Mode: fi.Mode().Perm()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		in.Dev, in.Ino = uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // int32 on darwin
		in.Uid = st.Uid
	}
	return in
}

func readBounded(f *os.File) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileSize {
		return nil, fmt.Errorf("%w: over %d bytes", ErrTooLarge, MaxFileSize)
	}
	return b, nil
}

// MaxDirEntries bounds the names one ReadDir returns.
const MaxDirEntries = 32768

func sortedNames(f *os.File) ([]string, error) {
	names, err := f.Readdirnames(MaxDirEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}
