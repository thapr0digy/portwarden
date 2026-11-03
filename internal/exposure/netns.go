package exposure

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

// ProcNetnsAddrs returns the local addresses of the network namespace process pid is
// in, read from /proc/<pid>/net/fib_trie (IPv4) and /proc/<pid>/net/if_inet6 (IPv6),
// loopback excluded. Reading another user's process needs CAP_SYS_PTRACE.
func ProcNetnsAddrs(procRoot string) func(pid uint32) ([]netip.Addr, error) {
	return func(pid uint32) ([]netip.Addr, error) {
		dir := procRoot + "/" + strconv.FormatUint(uint64(pid), 10) + "/net/"
		trie, err := os.ReadFile(dir + "fib_trie")
		if err != nil {
			return nil, err
		}
		addrs := FibTrieLocal(trie)
		// IPv6 may be disabled in the namespace: no if_inet6 is no IPv6 address.
		if inet6, err := os.ReadFile(dir + "if_inet6"); err == nil {
			v6, err := IfInet6(inet6)
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, v6...)
		}
		return addrs, nil
	}
}

// FibTrieLocal extracts the host's own (LOCAL, /32 host) IPv4 addresses from a fib_trie
// dump, loopback excluded, sorted and deduplicated.
func FibTrieLocal(data []byte) []netip.Addr {
	var out []netip.Addr
	var last netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if a, ok := strings.CutPrefix(line, "|-- "); ok {
			last, _ = netip.ParseAddr(a)
			continue
		}
		if strings.HasPrefix(line, "/32 host LOCAL") && last.IsValid() && !last.IsLoopback() {
			out = append(out, last)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// IfInet6 extracts the non-loopback, non-link-local IPv6 addresses from
// /proc/net/if_inet6 ("<32 hex> <ifindex> <prefixlen> <scope> <flags> <name>").
func IfInet6(data []byte) ([]netip.Addr, error) {
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		raw, err := hex.DecodeString(f[0])
		if err != nil || len(raw) != 16 {
			return nil, fmt.Errorf("if_inet6: bad address %q", f[0])
		}
		a := netip.AddrFrom16([16]byte(raw))
		if a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out), nil
}
