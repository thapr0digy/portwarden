//go:build linux

package baseline

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// maxDumpRetries bounds how often one family's dump is repeated after the kernel
// flags it NLM_F_DUMP_INTR (the listening table changed while it was walked).
const maxDumpRetries = 3

// dumpBufferSize holds any single dump datagram: the kernel sizes each one by the
// reader's last receive buffer, at most 32 KiB (netlink_dump), plus headroom.
const dumpBufferSize = 64 << 10

// Listeners dumps every TCP listening socket, IPv4 then IPv6, through a
// NETLINK_SOCK_DIAG socket. The socket belongs to the agent's own network namespace,
// which is the host namespace, so no namespace filter is needed. Listing needs no
// capability.
func Listeners() ([]diagSocket, error) {
	var all []diagSocket
	for _, family := range []uint8{afInet, afInet6} {
		socks, err := dumpFamily(family)
		if err != nil {
			return nil, err
		}
		all = append(all, socks...)
	}
	return all, nil
}

// dumpFamily runs the dump, repeating it while the kernel reports it interrupted.
func dumpFamily(family uint8) ([]diagSocket, error) {
	for attempt := 0; ; attempt++ {
		socks, err := dumpOnce(family)
		if errors.Is(err, errDumpInterrupted) && attempt < maxDumpRetries {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("dump TCP listeners of family %d: %w", family, err)
		}
		return socks, nil
	}
}

func dumpOnce(family uint8) ([]diagSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("open NETLINK_SOCK_DIAG socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Sendto(fd, buildDumpRequest(family), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("send inet_diag request: %w", err)
	}

	var all []diagSocket
	buf := make([]byte, dumpBufferSize)
	for {
		n, _, recvFlags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("receive inet_diag reply: %w", err)
		}
		if recvFlags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("inet_diag reply truncated to %d bytes", len(buf))
		}
		socks, done, err := parseMessages(buf[:n])
		if err != nil {
			return nil, err
		}
		all = append(all, socks...)
		if done {
			return all, nil
		}
	}
}
