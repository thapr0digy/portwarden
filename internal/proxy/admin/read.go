package admin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Host is the kernel access the reader needs (hostLinux in production; fakes in tests).
type Host interface {
	// DialUnix connects to path inside root (openat2 RESOLVE_IN_ROOT, so a container's
	// symlinks stay inside it).
	DialUnix(ctx context.Context, root, path string) (net.Conn, error)
	// DialTCP connects to a literal address.
	DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// PeerPID is the pid SO_PEERCRED names for a connected Unix socket.
	PeerPID(c net.Conn) (uint32, error)
	// SocketInode finds, in the network namespace of netnsPID, the TCP socket whose
	// local address is local and remote address is remote (the other end of the
	// agent's connection); 0 while the proxy has not accepted it yet.
	SocketInode(netnsPID uint32, local, remote netip.AddrPort) (uint64, error)
	// HoldsSocket reports whether pid has the socket inode open.
	HoldsSocket(pid uint32, inode uint64) (bool, error)
	PPID(pid uint32) (uint32, bool)
	Exe(pid uint32) string
}

// Query is one fixed read-only request.
type Query struct {
	// HTTPPath is the path of a GET; Command an HAProxy CLI command (one of the two).
	HTTPPath string
	Command  string
}

// Answer is a verified response.
type Answer struct {
	Body []byte
	// Via is what was dialled ("127.0.0.1:2019", "unix:/run/haproxy/admin.sock").
	Via string
}

// Read connects to the endpoint, proves the proxy is at the other end, asks q and
// returns the answer, all within Timeout and MaxBytes (ctx may shorten it).
func Read(ctx context.Context, h Host, p Proxy, ep Endpoint, q Query) (Answer, error) {
	t, err := Plan(ep, p)
	if err != nil {
		return Answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	conn, via, err := dial(ctx, h, p, t)
	if err != nil {
		return Answer{}, err
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(d); err != nil {
			return Answer{}, undetermined("%s: %v", via, err)
		}
	}
	if err := verify(ctx, h, p, t, conn); err != nil {
		return Answer{}, err
	}
	var body []byte
	switch {
	case q.HTTPPath != "":
		body, err = get(conn, t.Host, q.HTTPPath)
	case q.Command != "":
		body, err = command(conn, q.Command)
	default:
		err = errors.New("empty query")
	}
	if err != nil {
		return Answer{}, wrap(via, err)
	}
	return Answer{Body: body, Via: via}, nil
}

func dial(ctx context.Context, h Host, p Proxy, t Target) (net.Conn, string, error) {
	dctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	if t.Network == "unix" {
		via := "unix:" + t.Path
		c, err := h.DialUnix(dctx, p.Root, t.Path)
		switch {
		case errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES):
			return nil, via, Skip("socket %s not writable by the agent; not read", t.Path)
		case err != nil:
			return nil, via, undetermined("%s: %v", via, cleanErr(err))
		}
		return c, via, nil
	}
	via := t.Addr.String()
	c, err := h.DialTCP(dctx, t.Addr)
	if err != nil {
		return nil, via, undetermined("%s: %v", via, cleanErr(err))
	}
	return c, via, nil
}

// verify proves the proxy holds the other end of conn, before anything is sent.
func verify(ctx context.Context, h Host, p Proxy, t Target, conn net.Conn) error {
	if t.Network == "unix" {
		pid, err := h.PeerPID(conn)
		if err != nil {
			return undetermined("unix:%s: peer credentials: %v", t.Path, err)
		}
		if !ofProxy(h, p, pid) {
			return mismatch("unix:%s is served by pid %d, not the proxy", t.Path, pid)
		}
		return nil
	}
	local, err1 := addrPort(conn.LocalAddr())
	remote, err2 := addrPort(conn.RemoteAddr())
	if err1 != nil || err2 != nil {
		return undetermined("%s: connection addresses unreadable", t.Addr)
	}
	wait, cancel := context.WithTimeout(ctx, acceptWait)
	defer cancel()
	for {
		inode, err := h.SocketInode(p.Master(), remote, local)
		if err != nil {
			return undetermined("%s: socket table: %v", t.Addr, err)
		}
		if inode != 0 {
			for _, pid := range p.PIDs {
				held, err := h.HoldsSocket(pid, inode)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return undetermined("%s: fds of pid %d: %v", t.Addr, pid, err)
				}
				if held {
					return nil
				}
			}
			return mismatch("%s was accepted by a process outside the proxy", t.Addr)
		}
		select {
		case <-wait.Done():
			return mismatch("%s: the proxy did not accept the connection within %v", t.Addr, acceptWait)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// ofProxy: pid is one of the proxy's processes, or its same-executable parent chain
// reaches one (a worker that holds no listener).
func ofProxy(h Host, p Proxy, pid uint32) bool {
	cur := pid
	for range 64 {
		if slices.Contains(p.PIDs, cur) {
			return true
		}
		if p.Exe == "" || h.Exe(cur) != p.Exe {
			return false
		}
		parent, ok := h.PPID(cur)
		if !ok || parent <= 1 {
			return false
		}
		cur = parent
	}
	return false
}

func addrPort(a net.Addr) (netip.AddrPort, error) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("not a TCP address: %v", a)
	}
	ap := ta.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// limited fails a read past MaxBytes, so neither headers nor body can grow past it.
type limited struct {
	r io.Reader
	n int
}

func (l *limited) Read(b []byte) (int, error) {
	if l.n <= 0 {
		return 0, ErrTooLarge
	}
	if len(b) > l.n {
		b = b[:l.n]
	}
	n, err := l.r.Read(b)
	l.n -= n
	return n, err
}

// get sends one GET and reads a 200 answer. The request is written by hand on the
// verified connection: no client that could follow a redirect, use a proxy from the
// environment or open a second connection.
func get(conn net.Conn, host, path string) ([]byte, error) {
	// Plan only produces an IP literal, localhost or a wildcard with a numeric port, and
	// the paths are constants; this keeps a header from ever being injected regardless.
	if strings.ContainsAny(host+path, "\r\n \t") {
		return nil, errors.New("refusing a request line or Host with whitespace")
	}
	req :="GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: portwarden-agent\r\nAccept: application/json\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(&limited{r: conn, n: MaxBytes + 1})
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, &Error{Reason: fmt.Sprintf("redirect (%d) not followed", resp.StatusCode)}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, Skip("admin API needs credentials (%d); not read", resp.StatusCode)
	default:
		return nil, &Error{Reason: fmt.Sprintf("status %d", resp.StatusCode)}
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}

// command sends one HAProxy CLI command (non-interactive: HAProxy answers and closes)
// and reads the answer to its end.
func command(conn net.Conn, cmd string) ([]byte, error) {
	if strings.ContainsAny(cmd, "\n;") {
		return nil, errors.New("one command only")
	}
	if _, err := io.WriteString(conn, cmd+"\n"); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(&limited{r: conn, n: MaxBytes + 1})
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}

func wrap(via string, err error) error {
	var e *Error
	switch {
	case errors.As(err, &e):
		e.Reason = via + ": " + e.Reason
		return e
	case errors.Is(err, ErrTooLarge):
		return undetermined("%s: answer over %d bytes", via, MaxBytes)
	case errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return undetermined("%s: no answer within %v", via, Timeout)
	}
	return undetermined("%s: %v", via, cleanErr(err))
}

// cleanErr drops the Go net package's operation prefix ("dial tcp 127.0.0.1:2019: ").
func cleanErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}
