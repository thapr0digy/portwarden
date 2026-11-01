//go:build linux

package baseline

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The portable constants in inetdiag.go must agree with golang.org/x/sys/unix.
func TestConstantsMatchXSysUnix(t *testing.T) {
	pairs := []struct {
		name      string
		got, want int
	}{
		{"NLMSG_HDRLEN", nlmsgHdrLen, unix.NLMSG_HDRLEN},
		{"NLMSG_ALIGNTO", nlmsgAlignTo, unix.NLMSG_ALIGNTO},
		{"NLM_F_REQUEST", nlmFRequest, unix.NLM_F_REQUEST},
		{"NLM_F_DUMP", nlmFDump, unix.NLM_F_DUMP},
		{"NLM_F_DUMP_INTR", nlmFDumpIntr, unix.NLM_F_DUMP_INTR},
		{"NLMSG_ERROR", nlmsgError, unix.NLMSG_ERROR},
		{"NLMSG_DONE", nlmsgDone, unix.NLMSG_DONE},
		{"SOCK_DIAG_BY_FAMILY", sockDiagByFamily, unix.SOCK_DIAG_BY_FAMILY},
		{"AF_INET", afInet, unix.AF_INET},
		{"AF_INET6", afInet6, unix.AF_INET6},
		{"IPPROTO_TCP", ipprotoTCP, unix.IPPROTO_TCP},
		{"TCP_LISTEN", tcpListen, unix.BPF_TCP_LISTEN},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Errorf("%s = %#x, x/sys/unix has %#x", p.name, p.got, p.want)
		}
	}
}
