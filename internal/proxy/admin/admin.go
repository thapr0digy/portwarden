// Package admin reads a running proxy's own account of its routes from its local admin
// interface: Caddy's admin API and HAProxy's runtime API (the stats socket). It is the
// agent's only client of a socket another program controls, so every read is:
//
//   - for a proxy discovery already trusts (root-run, root-owned binary);
//   - to an endpoint the proxy itself holds: one of its own listening sockets in the
//     agent's listener table, or a Unix socket opened inside the proxy's root;
//   - local only: loopback in the agent's network namespace, or a container proxy's own
//     address on a host container network; never DNS, a redirect, TLS or a proxy;
//   - verified before a byte is sent: the kernel names the process at the other end
//     (SO_PEERCRED for a Unix socket; for TCP, the accepted socket of this very
//     connection must be open in one of the proxy's processes);
//   - bounded: DialTimeout to connect, Timeout and MaxBytes for the whole read;
//   - a fixed read-only request (GET, "show servers state"), no credentials.
//
// Any failure is an *Error, which the mapper turns into one "admin:" note: the proxy is
// then undetermined, never judged from a partial or spoofed answer.
package admin

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// Limits on one proxy's admin read (all its requests together).
const (
	DialTimeout = 500 * time.Millisecond
	Timeout     = 2 * time.Second
	// MaxBytes matches the config readers' budget: the parsers' heap grows with what
	// they read, and whoever runs the proxy controls the answer.
	MaxBytes = conf.MaxTotalBytes
	// acceptWait bounds how long the TCP check waits for the proxy to accept the
	// connection (its socket appears in the proxy's fds only then).
	acceptWait = 300 * time.Millisecond
)

// Endpoint is an admin interface a proxy declares (or the default it would use).
type Endpoint struct {
	// Network is "unix" (Addr is a path as the proxy sees it) or "tcp" (Addr is
	// host:port; the host may be empty or "*" for every address, or "localhost").
	Network, Addr string
	// Origin says where the endpoint came from ("CADDY_ADMIN", "default",
	// "/etc/haproxy/haproxy.cfg:3"), for notes.
	Origin string
}

func (e Endpoint) String() string {
	if e.Network == "unix" {
		return "unix:" + e.Addr
	}
	return e.Addr
}

// Proxy is what the reader needs to know about the proxy it talks to.
type Proxy struct {
	// PIDs are the master first, then the other processes holding its listeners.
	PIDs []uint32
	// Exe is the master's executable: a process whose same-executable parent chain
	// reaches a PID is the proxy's too (a worker that holds no listener).
	Exe string
	// Root is "/" or /proc/<pid>/root: where a Unix socket path resolves.
	Root string
	// NetNS is the proxy's network namespace; SameNetNS says it is the agent's.
	NetNS     uint32
	SameNetNS bool
	// Listeners are the proxy's own listening sockets (from the listener table).
	Listeners []model.ListenerKey
	// LocalAddrs are the addresses of the proxy's network namespace.
	LocalAddrs []netip.Addr
	// HostContainerNet reports whether the agent reaches addr through one of the host's
	// container networks (a bridge or veth), so a dial to a container's own address
	// cannot leave the host. nil: never.
	HostContainerNet func(addr netip.Addr) bool
}

// Master is the proxy's master process (0 when unknown).
func (p Proxy) Master() uint32 {
	if len(p.PIDs) == 0 {
		return 0
	}
	return p.PIDs[0]
}

// Error is why an admin read gave no answer the agent may use.
type Error struct {
	// Reason is the note's text after its prefix.
	Reason string
	// Mismatch: something other than the proxy answered (or could have).
	Mismatch bool
	// Skipped: the read was not attempted by design (no endpoint, needs credentials),
	// not a failure.
	Skipped bool
}

func (e *Error) Error() string { return e.Note() }

// Note is the proxy note for the failure.
func (e *Error) Note() string {
	switch {
	case e.Mismatch:
		return "admin:peer mismatch (" + e.Reason + ")"
	case e.Skipped:
		return "admin:" + e.Reason
	}
	return "admin:undetermined " + e.Reason
}

func undetermined(format string, args ...any) *Error {
	return &Error{Reason: sprintf(format, args...)}
}

func mismatch(format string, args ...any) *Error {
	return &Error{Reason: sprintf(format, args...), Mismatch: true}
}

// Skip is an *Error for a read not attempted by design.
func Skip(format string, args ...any) *Error {
	return &Error{Reason: sprintf(format, args...), Skipped: true}
}

// Note renders any error from this package as a proxy note.
func Note(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Note()
	}
	return "admin:undetermined " + err.Error()
}

var sprintf = fmt.Sprintf

// ErrTooLarge is returned when an answer exceeds MaxBytes.
var ErrTooLarge = errors.New("answer over the size limit")
