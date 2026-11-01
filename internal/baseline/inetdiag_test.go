package baseline

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"syscall"
	"testing"
)

func TestBuildDumpRequestAsksListenOnly(t *testing.T) {
	for _, family := range []uint8{afInet, afInet6} {
		req := buildDumpRequest(family)
		if len(req) != nlmsgHdrLen+sizeofInetDiagReqV2 {
			t.Fatalf("family %d: request is %d bytes, want %d", family, len(req), nlmsgHdrLen+sizeofInetDiagReqV2)
		}
		if got := binary.NativeEndian.Uint32(req[0:4]); got != uint32(len(req)) {
			t.Errorf("nlmsg_len = %d, want %d", got, len(req))
		}
		if got := binary.NativeEndian.Uint16(req[4:6]); got != sockDiagByFamily {
			t.Errorf("nlmsg_type = %d, want SOCK_DIAG_BY_FAMILY", got)
		}
		flags := binary.NativeEndian.Uint16(req[6:8])
		if flags&nlmFRequest == 0 || flags&nlmFDump != nlmFDump {
			t.Errorf("nlmsg_flags = %#x, want NLM_F_REQUEST|NLM_F_DUMP", flags)
		}

		body := req[nlmsgHdrLen:]
		if body[0] != family {
			t.Errorf("sdiag_family = %d, want %d", body[0], family)
		}
		if body[1] != ipprotoTCP {
			t.Errorf("sdiag_protocol = %d, want TCP", body[1])
		}
		if got := binary.NativeEndian.Uint32(body[4:8]); got != 1<<10 {
			t.Errorf("idiag_states = %#x, want 1<<TCP_LISTEN", got)
		}
	}
}

// testdata/dump-v4-v6.bin was recorded from a 6.8 kernel (arm64, little-endian) in a
// fresh netns listening on 127.0.0.1:8080 and [::1]:9090: the AF_INET reply's socket
// message followed by the whole AF_INET6 reply (socket message, then NLMSG_DONE).
func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/dump-v4-v6.bin")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseDumpFixture(t *testing.T) {
	got, err := parseDump(readFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []diagSocket{
		{Cookie: 0x22f1, Family: afInet, Addr: netip.MustParseAddr("127.0.0.1"), Port: 8080, Inode: 48251},
		{Cookie: 0x22f2, Family: afInet6, Addr: netip.MustParseAddr("::1"), Port: 9090, Inode: 48252},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sockets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("socket %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseDumpFlagsInterrupted(t *testing.T) {
	b := readFixture(t)
	const doneOffset = 0x100 // the NLMSG_DONE header of the fixture
	if typ := binary.NativeEndian.Uint16(b[doneOffset+4:]); typ != nlmsgDone {
		t.Fatalf("fixture: message at %#x has type %d, want NLMSG_DONE", doneOffset, typ)
	}
	flags := binary.NativeEndian.Uint16(b[doneOffset+6:])
	binary.NativeEndian.PutUint16(b[doneOffset+6:], flags|nlmFDumpIntr)

	if _, err := parseDump(b); !errors.Is(err, errDumpInterrupted) {
		t.Fatalf("err = %v, want errDumpInterrupted", err)
	}
}

func TestParseDumpRejectsMalformed(t *testing.T) {
	b := readFixture(t)
	cases := map[string][]byte{
		"no NLMSG_DONE":      b[:0x100],
		"truncated message":  b[:0x30],
		"truncated header":   b[:8],
		"length past buffer": append([]byte{0xff, 0xff, 0, 0}, b[4:]...),
	}
	for name, input := range cases {
		if socks, err := parseDump(input); err == nil {
			t.Errorf("%s: parsed %+v, want an error", name, socks)
		}
	}
}

func TestParseDumpReportsNetlinkError(t *testing.T) {
	msg := make([]byte, nlmsgHdrLen+4)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], nlmsgError)
	errno := int32(-2) // -ENOENT
	binary.NativeEndian.PutUint32(msg[nlmsgHdrLen:], uint32(errno))
	_, err := parseDump(msg)
	var got syscall.Errno
	if !errors.As(err, &got) || got != 2 {
		t.Fatalf("err = %v, want errno 2", err)
	}
}
