//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path"
	"strconv"

	"golang.org/x/sys/unix"
)

// MaxFDs bounds the descriptors looked at per process when checking who holds a socket.
const MaxFDs = 65536

// ProcHost is the production Host, reading procRoot ("/proc").
type ProcHost struct {
	ProcRoot string
	// PPIDFunc and ExeFunc read a process's parent and executable (discover.ProcFS).
	PPIDFunc func(uint32) (uint32, bool)
	ExeFunc  func(uint32) string
}

func (h ProcHost) PPID(pid uint32) (uint32, bool) { return h.PPIDFunc(pid) }
func (h ProcHost) Exe(pid uint32) string          { return h.ExeFunc(pid) }

func (h ProcHost) pidPath(pid uint32, name string) string {
	return path.Join(h.ProcRoot, strconv.FormatUint(uint64(pid), 10), name)
}

// DialUnix opens the socket file inside root with openat2(RESOLVE_IN_ROOT |
// RESOLVE_NO_MAGICLINKS) as an O_PATH descriptor and connects through
// /proc/self/fd/<n>, so the path is resolved as the proxy sees it and no symlink can
// lead the agent out of the proxy's root. Kernels without openat2 are refused.
func (h ProcHost) DialUnix(ctx context.Context, root, p string) (net.Conn, error) {
	rfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: root, Err: err}
	}
	defer unix.Close(rfd)
	fd, err := unix.Openat2(rfd, p, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &fs.PathError{Op: "stat", Path: p, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, &fs.PathError{Op: "connect", Path: p, Err: errors.New("not a socket")}
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(fd))
}

// DialTCP connects to a literal address (no name is ever resolved).
func (ProcHost) DialTCP(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", a.String())
}

// PeerPID reads SO_PEERCRED: the pid that created the listening socket at listen() time,
// as the agent's pid namespace numbers it.
func (ProcHost) PeerPID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	if cred.Pid <= 0 {
		return 0, fmt.Errorf("no peer pid (%d)", cred.Pid)
	}
	return uint32(cred.Pid), nil
}

// SocketInode scans /proc/<pid>/net/tcp and tcp6 (the netns of pid) for the socket with
// this local and remote address; a dual-stack listener's IPv4 connections are listed in
// tcp6 with mapped addresses.
func (h ProcHost) SocketInode(pid uint32, local, remote netip.AddrPort) (uint64, error) {
	var firstErr error
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		inode, err := scanTCP(h.pidPath(pid, f), local, remote)
		if err == nil && inode != 0 {
			return inode, nil
		}
		if err != nil && firstErr == nil && !errors.Is(err, os.ErrNotExist) {
			firstErr = err
		}
	}
	return 0, firstErr
}

func scanTCP(file string, local, remote netip.AddrPort) (uint64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return findSocket(f, local, remote)
}

// HoldsSocket looks through /proc/<pid>/fd for socket:[inode].
func (h ProcHost) HoldsSocket(pid uint32, inode uint64) (bool, error) {
	dir := h.pidPath(pid, "fd")
	d, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer d.Close()
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	seen := 0
	for seen < MaxFDs {
		names, err := d.Readdirnames(1024)
		for _, n := range names {
			if target, err := os.Readlink(dir + "/" + n); err == nil && target == want {
				return true, nil
			}
		}
		seen += len(names)
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	return false, fmt.Errorf("more than %d descriptors", MaxFDs)
}
