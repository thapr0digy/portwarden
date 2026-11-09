package admin

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
)

var (
	lo4  = netip.MustParseAddr("127.0.0.1")
	any4 = netip.IPv4Unspecified()
)

func key(ns uint32, a netip.Addr, port uint16) model.ListenerKey {
	return model.NewKey(ns, "tcp", a, port)
}

func TestPlan(t *testing.T) {
	bridge := netip.MustParseAddr("172.17.0.2")
	host := Proxy{NetNS: 1, SameNetNS: true, Listeners: []model.ListenerKey{key(1, lo4, 2019), key(1, any4, 8080)}}
	ctr := Proxy{NetNS: 7, Listeners: []model.ListenerKey{key(7, lo4, 2019), key(7, any4, 8080)},
		LocalAddrs: []netip.Addr{lo4, bridge}, HostContainerNet: func(a netip.Addr) bool { return a == bridge }}
	cases := []struct {
		name string
		ep   Endpoint
		p    Proxy
		want string // "addr host" or the error text
	}{
		{"caddy default", Endpoint{Network: "tcp", Addr: "localhost:2019"}, host, "127.0.0.1:2019 localhost:2019"},
		{"literal", Endpoint{Network: "tcp", Addr: "127.0.0.1:2019"}, host, "127.0.0.1:2019 127.0.0.1:2019"},
		{"wildcard listener on loopback", Endpoint{Network: "tcp", Addr: ":8080"}, host, "127.0.0.1:8080 localhost:8080"},
		{"not held", Endpoint{Network: "tcp", Addr: "localhost:9999"}, host, "not a listener the proxy holds"},
		{"other netns's listener", Endpoint{Network: "tcp", Addr: "localhost:2019"}, Proxy{NetNS: 1, SameNetNS: true, Listeners: []model.ListenerKey{key(2, lo4, 2019)}}, "not a listener the proxy holds"},
		{"name", Endpoint{Network: "tcp", Addr: "admin.internal:2019"}, host, "not an address (no DNS lookups)"},
		{"container loopback", Endpoint{Network: "tcp", Addr: "localhost:2019"}, ctr, "container's loopback"},
		{"container wildcard", Endpoint{Network: "tcp", Addr: "0.0.0.0:8080"}, ctr, "172.17.0.2:8080 localhost:8080"},
		{"container off the bridge", Endpoint{Network: "tcp", Addr: ":8080"}, Proxy{NetNS: 7, Listeners: ctr.Listeners, LocalAddrs: ctr.LocalAddrs}, "no address of the proxy's network namespace is on a host container network"},
		{"unix", Endpoint{Network: "unix", Addr: "/run/haproxy/admin.sock"}, host, "unix /run/haproxy/admin.sock"},
		{"relative unix", Endpoint{Network: "unix", Addr: "admin.sock"}, host, "not an absolute path"},
		{"no port", Endpoint{Network: "tcp", Addr: "localhost"}, host, "no port"},
		{"bare v6", Endpoint{Network: "tcp", Addr: "::1:2019"}, host, "brackets"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg, err := Plan(c.ep, c.p)
			got := ""
			switch {
			case err != nil:
				got = err.Error()
			case tg.Network == "unix":
				got = "unix " + tg.Path
			default:
				got = tg.Addr.String() + " " + tg.Host
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// fakeHost dials for real (loopback TCP, net.Pipe for "Unix") and answers the kernel
// questions from its fields.
type fakeHost struct {
	peerPID  uint32
	inode    uint64
	holders  map[uint32]bool
	parents  map[uint32]uint32
	exes     map[uint32]string
	unix     func() (net.Conn, error)
	dialed   []netip.AddrPort
	inodeErr error
}

func (f *fakeHost) DialUnix(ctx context.Context, root, p string) (net.Conn, error) { return f.unix() }
func (f *fakeHost) DialTCP(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
	f.dialed = append(f.dialed, a)
	var d net.Dialer
	return d.DialContext(ctx, "tcp", a.String())
}
func (f *fakeHost) PeerPID(net.Conn) (uint32, error) { return f.peerPID, nil }
func (f *fakeHost) SocketInode(uint32, netip.AddrPort, netip.AddrPort) (uint64, error) {
	return f.inode, f.inodeErr
}
func (f *fakeHost) HoldsSocket(pid uint32, _ uint64) (bool, error) { return f.holders[pid], nil }
func (f *fakeHost) PPID(pid uint32) (uint32, bool) {
	p, ok := f.parents[pid]
	return p, ok
}
func (f *fakeHost) Exe(pid uint32) string { return f.exes[pid] }

// serve answers every connection on a loopback port with handle, and returns the
// endpoint and the proxy that holds it.
func serve(t *testing.T, handle func(net.Conn)) (Endpoint, Proxy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	p := Proxy{PIDs: []uint32{100, 101}, NetNS: 1, SameNetNS: true, Listeners: []model.ListenerKey{key(1, lo4, ap.Port())}}
	return Endpoint{Network: "tcp", Addr: ap.String()}, p
}

func httpServer(status int, header, body string) func(net.Conn) {
	return func(c net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(status)+" "+http.StatusText(status)+"\r\n"+header+
			"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	}
}

func trusted() *fakeHost { return &fakeHost{inode: 42, holders: map[uint32]bool{101: true}} }

func TestReadHTTP(t *testing.T) {
	var gotReq *http.Request
	ep, p := serve(t, func(c net.Conn) {
		r, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		gotReq = r
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
	})
	h := trusted()
	ans, err := Read(context.Background(), h, p, ep, Query{HTTPPath: "/config/"})
	if err != nil || string(ans.Body) != "{}" || ans.Via != ep.Addr {
		t.Fatalf("answer %+v, %v", ans, err)
	}
	if gotReq.Method != "GET" || gotReq.URL.Path != "/config/" || gotReq.Host != ep.Addr || gotReq.Header.Get("Authorization") != "" {
		t.Errorf("request = %s %s host %s", gotReq.Method, gotReq.URL, gotReq.Host)
	}
}

// A proxy configured in the environment is never used: the request goes to the
// verified connection only.
func TestAdminNoProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	ep, p := serve(t, httpServer(200, "", "{}"))
	h := trusted()
	if _, err := Read(context.Background(), h, p, ep, Query{HTTPPath: "/config/"}); err != nil {
		t.Fatal(err)
	}
	if len(h.dialed) != 1 || h.dialed[0].String() != ep.Addr {
		t.Errorf("dialled %v", h.dialed)
	}
}

func TestAdminRefusesRedirect(t *testing.T) {
	ep, p := serve(t, httpServer(302, "Location: http://10.0.0.1/config/\r\n", ""))
	h := trusted()
	_, err := Read(context.Background(), h, p, ep, Query{HTTPPath: "/config/"})
	if err == nil || !strings.Contains(Note(err), "admin:undetermined "+ep.Addr+": redirect (302) not followed") || len(h.dialed) != 1 {
		t.Fatalf("err = %v, dialled %v", err, h.dialed)
	}
}

func TestAdminRefusesAuth(t *testing.T) {
	ep, p := serve(t, httpServer(401, "WWW-Authenticate: Basic\r\n", ""))
	_, err := Read(context.Background(), trusted(), p, ep, Query{HTTPPath: "/api/http/routers"})
	if err == nil || Note(err) != "admin:"+ep.Addr+": admin API needs credentials (401); not read" {
		t.Fatalf("note = %q", Note(err))
	}
}

func TestAdminSizeCap(t *testing.T) {
	big := strings.Repeat("x", MaxBytes+10)
	ep, p := serve(t, httpServer(200, "", big))
	_, err := Read(context.Background(), trusted(), p, ep, Query{HTTPPath: "/config/"})
	if err == nil || !strings.Contains(Note(err), "answer over") {
		t.Fatalf("err = %v", err)
	}
	// The cap holds without a Content-Length too (a CLI answer read to its end).
	ep, p = serve(t, func(c net.Conn) {
		bufio.NewReader(c).ReadString('\n')
		io.WriteString(c, big)
	})
	_, err = Read(context.Background(), trusted(), p, ep, Query{Command: "show servers state"})
	if err == nil || !strings.Contains(Note(err), "answer over") {
		t.Fatalf("command err = %v", err)
	}
}

func TestAdminTimeout(t *testing.T) {
	ep, p := serve(t, func(c net.Conn) { time.Sleep(Timeout + time.Second) })
	start := time.Now()
	_, err := Read(context.Background(), trusted(), p, ep, Query{HTTPPath: "/config/"})
	if err == nil || !strings.Contains(Note(err), "no answer within") {
		t.Fatalf("err = %v", err)
	}
	if took := time.Since(start); took > Timeout+500*time.Millisecond {
		t.Errorf("took %v", took)
	}
}

// The TCP check runs before anything is sent: a connection accepted by a process
// outside the proxy, or not accepted at all, is refused and the request never written.
func TestTCPPeerOwnerMismatch(t *testing.T) {
	got := make(chan string, 4)
	ep, p := serve(t, func(c net.Conn) {
		c.SetReadDeadline(time.Now().Add(time.Second))
		b, _ := io.ReadAll(c)
		got <- string(b)
	})
	impostor := &fakeHost{inode: 42, holders: map[uint32]bool{999: true}}
	_, err := Read(context.Background(), impostor, p, ep, Query{HTTPPath: "/config/"})
	if err == nil || Note(err) != "admin:peer mismatch ("+ep.Addr+" was accepted by a process outside the proxy)" {
		t.Fatalf("note = %q", Note(err))
	}
	if b := <-got; b != "" {
		t.Errorf("the request was sent to an unverified peer: %q", b)
	}
	unaccepted := &fakeHost{inode: 0}
	_, err = Read(context.Background(), unaccepted, p, ep, Query{HTTPPath: "/config/"})
	if err == nil || !strings.Contains(Note(err), "did not accept the connection") {
		t.Fatalf("note = %q", Note(err))
	}
}

func TestPeerCredMismatch(t *testing.T) {
	p := Proxy{PIDs: []uint32{100}, Exe: "/usr/sbin/haproxy", Root: "/"}
	ep := Endpoint{Network: "unix", Addr: "/run/haproxy/admin.sock"}
	answer := func(reply string) func() (net.Conn, error) {
		return func() (net.Conn, error) {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				line, _ := bufio.NewReader(b).ReadString('\n')
				if line == "show servers state\n" {
					io.WriteString(b, reply)
				}
			}()
			return a, nil
		}
	}
	h := &fakeHost{peerPID: 555, unix: answer("1\n")}
	_, err := Read(context.Background(), h, p, ep, Query{Command: "show servers state"})
	if err == nil || Note(err) != "admin:peer mismatch (unix:/run/haproxy/admin.sock is served by pid 555, not the proxy)" {
		t.Fatalf("note = %q", Note(err))
	}
	// A worker of the master (same executable, parent chain reaches it) is the proxy.
	h = &fakeHost{peerPID: 555, unix: answer("1\n# be_name\n"), parents: map[uint32]uint32{555: 100}, exes: map[uint32]string{555: p.Exe, 100: p.Exe}}
	ans, err := Read(context.Background(), h, p, ep, Query{Command: "show servers state"})
	if err != nil || string(ans.Body) != "1\n# be_name\n" || ans.Via != "unix:/run/haproxy/admin.sock" {
		t.Fatalf("answer %+v, %v", ans, err)
	}
	// Another executable's child is not.
	h = &fakeHost{peerPID: 555, unix: answer("1\n"), parents: map[uint32]uint32{555: 100}, exes: map[uint32]string{555: "/tmp/fake", 100: p.Exe}}
	if _, err := Read(context.Background(), h, p, ep, Query{Command: "show servers state"}); err == nil {
		t.Fatal("a child running another executable was trusted")
	}
	// A socket the agent may not open is a skip, not a failure.
	h = &fakeHost{unix: func() (net.Conn, error) { return nil, &os.PathError{Op: "dial", Path: "x", Err: syscall.EACCES} }}
	_, err = Read(context.Background(), h, p, ep, Query{Command: "show servers state"})
	var e *Error
	if !errors.As(err, &e) || !e.Skipped || !strings.Contains(e.Note(), "not writable by the agent") {
		t.Fatalf("err = %v", err)
	}
}

func TestFindSocket(t *testing.T) {
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:07E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:07E3 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 2222 1 0000000000000000 20 4 30 10 -1
`
	got, err := findSocket(strings.NewReader(table), netip.MustParseAddrPort("127.0.0.1:2019"), netip.MustParseAddrPort("127.0.0.1:54321"))
	if err != nil || got != 2222 {
		t.Fatalf("inode = %d, %v", got, err)
	}
	// tcp6: a dual-stack listener's IPv4 peer, mapped; and ::1.
	table6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 3333 1\n" +
		"   1: 00000000000000000000000001000000:1F90 00000000000000000000000001000000:D432 01 00000000:00000000 00:00000000 00000000     0        0 4444 1\n"
	if got, _ := findSocket(strings.NewReader(table6), netip.MustParseAddrPort("127.0.0.1:8080"), netip.MustParseAddrPort("127.0.0.1:54321")); got != 3333 {
		t.Errorf("mapped inode = %d", got)
	}
	if got, _ := findSocket(strings.NewReader(table6), netip.MustParseAddrPort("[::1]:8080"), netip.MustParseAddrPort("[::1]:54322")); got != 4444 {
		t.Errorf("v6 inode = %d", got)
	}
}
