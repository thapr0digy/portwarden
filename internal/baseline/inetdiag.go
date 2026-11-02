// Package baseline takes the snapshot of TCP listeners and bound UDP sockets at agent
// start: a listen-only inet_diag dump and a BPF iter/udp pass for the host network
// namespace's sockets, and a BPF task_file iterator for the processes that own sockets
// in any namespace.
package baseline

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// Netlink and inet_diag values, checked against the 6.8 headers (linux/netlink.h,
// linux/sock_diag.h, linux/inet_diag.h). They are spelled out here because
// golang.org/x/sys/unix defines them only for linux and has no inet_diag structs, and
// this file must build on macOS; inetdiag_linux_test.go compares them with x/sys/unix.
const (
	nlmsgHdrLen      = 16   // sizeof(struct nlmsghdr)
	nlmsgAlignTo     = 4    // NLMSG_ALIGNTO
	nlmFRequest      = 0x01 // NLM_F_REQUEST
	nlmFDump         = 0x300
	nlmFDumpIntr     = 0x10 // NLM_F_DUMP_INTR: the dump raced a table change
	nlmsgError       = 0x2
	nlmsgDone        = 0x3
	sockDiagByFamily = 20

	afInet     = 2
	afInet6    = 10
	ipprotoTCP = 6
	tcpListen  = 10 // TCP_LISTEN in include/net/tcp_states.h

	// struct inet_diag_req_v2: family, protocol, ext, pad (u8 each), states (u32),
	// then struct inet_diag_sockid (48 bytes).
	sizeofInetDiagReqV2 = 56
	// struct inet_diag_msg: family, state, timer, retrans (u8 each), inet_diag_sockid,
	// then expires, rqueue, wqueue, uid, inode (u32 each). Attributes follow it.
	sizeofInetDiagMsg = 72

	// Offsets into struct inet_diag_msg (the sockid starts at 4).
	msgSportOffset  = 4  // __be16 idiag_sport
	msgSrcOffset    = 8  // __be32 idiag_src[4]
	msgCookieOffset = 44 // __u32 idiag_cookie[2]
	msgInodeOffset  = 68 // __u32 idiag_inode
)

// errDumpInterrupted means the kernel flagged the dump NLM_F_DUMP_INTR: the socket
// table changed while it was walked, so the reply may be missing sockets.
var errDumpInterrupted = errors.New("inet_diag dump interrupted (NLM_F_DUMP_INTR)")

// diagSocket is one listening socket from the inet_diag dump.
type diagSocket struct {
	Cookie uint64
	Family uint8
	Addr   netip.Addr
	Port   uint16
	Inode  uint32
}

// buildDumpRequest returns a SOCK_DIAG_BY_FAMILY dump request for TCP sockets of the
// given address family in state LISTEN only. With no other state requested, the kernel
// walks just the listening hash (inet_diag_dump_icsk skips the established hash when
// idiag_states has no bit besides TCPF_LISTEN).
func buildDumpRequest(family uint8) []byte {
	b := make([]byte, nlmsgHdrLen+sizeofInetDiagReqV2)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(b[6:], nlmFRequest|nlmFDump)
	binary.NativeEndian.PutUint32(b[8:], 1) // sequence number; one request per socket

	req := b[nlmsgHdrLen:]
	req[0] = family
	req[1] = ipprotoTCP
	binary.NativeEndian.PutUint32(req[4:], 1<<tcpListen)
	return b
}

// parseDump decodes a complete dump reply, which must end with NLMSG_DONE.
func parseDump(b []byte) ([]diagSocket, error) {
	socks, done, err := parseMessages(b)
	if err != nil {
		return nil, err
	}
	if !done {
		return nil, errors.New("inet_diag reply ends without NLMSG_DONE")
	}
	return socks, nil
}

// parseMessages decodes the netlink messages in one received datagram. done reports
// that it held the NLMSG_DONE that ends the dump; anything after it is ignored.
func parseMessages(b []byte) (socks []diagSocket, done bool, err error) {
	for len(b) > 0 {
		if len(b) < nlmsgHdrLen {
			return nil, false, fmt.Errorf("truncated netlink header: %d bytes", len(b))
		}
		msgLen := binary.NativeEndian.Uint32(b[0:])
		msgType := binary.NativeEndian.Uint16(b[4:])
		flags := binary.NativeEndian.Uint16(b[6:])
		if msgLen < nlmsgHdrLen || uint64(msgLen) > uint64(len(b)) {
			return nil, false, fmt.Errorf("netlink message length %d out of range (%d bytes left)", msgLen, len(b))
		}
		if flags&nlmFDumpIntr != 0 {
			return nil, false, errDumpInterrupted
		}
		payload := b[nlmsgHdrLen:msgLen]

		switch msgType {
		case nlmsgDone:
			if err := payloadErrno(payload); err != nil {
				return nil, false, fmt.Errorf("inet_diag dump failed: %w", err)
			}
			return socks, true, nil
		case nlmsgError:
			err := payloadErrno(payload)
			if err == nil {
				err = errors.New("unexpected netlink ACK")
			}
			return nil, false, fmt.Errorf("inet_diag request rejected: %w", err)
		case sockDiagByFamily:
			s, err := decodeDiagMsg(payload)
			if err != nil {
				return nil, false, err
			}
			socks = append(socks, s)
		}

		next := (int(msgLen) + nlmsgAlignTo - 1) &^ (nlmsgAlignTo - 1)
		b = b[min(next, len(b)):]
	}
	return socks, false, nil
}

// payloadErrno reads the negative errno that starts NLMSG_ERROR and NLMSG_DONE
// payloads; nil when it is 0 or absent.
func payloadErrno(payload []byte) error {
	if len(payload) < 4 {
		return nil
	}
	if code := int32(binary.NativeEndian.Uint32(payload)); code < 0 {
		return syscall.Errno(-code)
	}
	return nil
}

func decodeDiagMsg(m []byte) (diagSocket, error) {
	if len(m) < sizeofInetDiagMsg {
		return diagSocket{}, fmt.Errorf("truncated inet_diag_msg: %d bytes, want %d", len(m), sizeofInetDiagMsg)
	}
	s := diagSocket{
		Family: m[0],
		Port:   binary.BigEndian.Uint16(m[msgSportOffset:]),
		Cookie: uint64(binary.NativeEndian.Uint32(m[msgCookieOffset:])) |
			uint64(binary.NativeEndian.Uint32(m[msgCookieOffset+4:]))<<32,
		Inode: binary.NativeEndian.Uint32(m[msgInodeOffset:]),
	}
	switch s.Family {
	case afInet:
		s.Addr = netip.AddrFrom4([4]byte(m[msgSrcOffset:]))
	case afInet6:
		s.Addr = netip.AddrFrom16([16]byte(m[msgSrcOffset:]))
	default:
		return diagSocket{}, fmt.Errorf("inet_diag_msg with unknown family %d", s.Family)
	}
	return s, nil
}
