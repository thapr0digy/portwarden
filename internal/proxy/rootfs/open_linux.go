//go:build linux

package rootfs

import (
	"errors"
	"io/fs"
	"os"
	"path"

	"golang.org/x/sys/unix"
)

// Open returns an FS rooted at root, resolved by the kernel: openat2 with
// RESOLVE_IN_ROOT treats root as "/" for every absolute symlink and "..", and
// RESOLVE_NO_MAGICLINKS refuses /proc magic links inside it. When openat2 is not
// available (ENOSYS), it falls back to Walker.
func Open(root string) (FS, error) {
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: root, Err: err}
	}
	k := &kernelFS{root: fd}
	if _, err := k.openat2("/", unix.O_PATH); errors.Is(err, unix.ENOSYS) {
		_ = unix.Close(fd)
		return Walker(root), nil
	}
	return k, nil
}

type kernelFS struct{ root int }

func (k *kernelFS) Close() error { return unix.Close(k.root) }

func (k *kernelFS) openat2(p string, flags uint64) (*os.File, error) {
	if !path.IsAbs(p) {
		return nil, &fs.PathError{Op: "open", Path: p, Err: errors.New("path is not absolute")}
	}
	fd, err := unix.Openat2(k.root, p, &unix.OpenHow{
		Flags:   flags | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), nil
}

func (k *kernelFS) ReadFile(p string) ([]byte, error) {
	f, err := k.openat2(p, unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: p, Err: errors.New("not a regular file")}
	}
	b, err := readBounded(f)
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: p, Err: err}
	}
	return b, nil
}

func (k *kernelFS) ReadDir(p string) ([]string, error) {
	f, err := k.openat2(p, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return sortedNames(f)
}

func (k *kernelFS) Stat(p string) (Info, error) {
	f, err := k.openat2(p, unix.O_PATH)
	if err != nil {
		return Info{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Info{}, err
	}
	return infoOf(fi), nil
}
