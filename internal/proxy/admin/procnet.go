package admin

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// findSocket reads the /proc/net/tcp format ("sl local rem st … uid timeout inode",
// after a header line) and returns the inode of the socket with this local and remote
// address; 0 when there is none, or it has no inode yet (not accepted).
func findSocket(r io.Reader, local, remote netip.AddrPort) (uint64, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 512), 4096)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		l, ok1 := parseProcAddr(f[1])
		rm, ok2 := parseProcAddr(f[2])
		if !ok1 || !ok2 || l != local || rm != remote {
			continue
		}
		return strconv.ParseUint(f[9], 10, 64)
	}
	return 0, sc.Err()
}

// parseProcAddr decodes "0100007F:1F90" (IPv4) or a 32-digit IPv6 address: each 32-bit
// word in host byte order (little-endian on every architecture the agent ships for).
// IPv4-mapped IPv6 addresses are unmapped.
func parseProcAddr(s string) (netip.AddrPort, bool) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	b, err := hex.DecodeString(hexAddr)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), true
}
