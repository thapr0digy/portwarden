// Package model holds the types shared by the agent's collectors and publisher.
package model

import (
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// ListenerKey identifies a listening socket: netns / proto / bind address : port.
// The owning process is an attribute of the listener, not part of its identity.
type ListenerKey struct {
	NetNS uint32
	Proto string
	Addr  netip.Addr
	Port  uint16
}

// NewKey builds a key, unmapping IPv4-mapped IPv6 addresses ("::ffff:a.b.c.d" -> "a.b.c.d").
func NewKey(netns uint32, proto string, addr netip.Addr, port uint16) ListenerKey {
	return ListenerKey{NetNS: netns, Proto: proto, Addr: addr.Unmap(), Port: port}
}

// String renders "<netns>/<proto>/<addr>:<port>", with IPv6 addresses in brackets.
func (k ListenerKey) String() string {
	hostPort := netip.AddrPortFrom(k.Addr, k.Port).String()
	return strconv.FormatUint(uint64(k.NetNS), 10) + "/" + k.Proto + "/" + hostPort
}

// Listener protocols.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// Container identifies the container a process runs in; zero when it is not containerised.
type Container struct {
	Runtime, ID string
}

// Process describes a process holding a listening socket.
type Process struct {
	PID, UID   uint32
	Comm       string
	Exe        string
	Cmdline    []string
	SHA256     string
	Unit       string
	SocketUnit string
	Container  Container
	CgroupID   uint64
}

// IsZero reports whether p carries no information (an ownerless listener).
func (p Process) IsZero() bool {
	return p.Equal(Process{})
}

// Equal compares every field; a nil and an empty Cmdline are equal.
func (p Process) Equal(q Process) bool {
	return p.PID == q.PID && p.UID == q.UID &&
		p.Comm == q.Comm && p.Exe == q.Exe &&
		slices.Equal(p.Cmdline, q.Cmdline) &&
		p.SHA256 == q.SHA256 && p.Unit == q.Unit && p.SocketUnit == q.SocketUnit &&
		p.Container == q.Container && p.CgroupID == q.CgroupID
}

// SameIdentity compares the fields that say who holds a socket: PID, Exe,
// SHA256, Unit, SocketUnit, Container and CgroupID. UID, Comm and Cmdline are
// left out because a process can change them itself (a privilege drop, a
// retitle) without becoming a different owner.
func (p Process) SameIdentity(q Process) bool {
	return p.PID == q.PID && p.Exe == q.Exe && p.SHA256 == q.SHA256 &&
		p.Unit == q.Unit && p.SocketUnit == q.SocketUnit &&
		p.Container == q.Container && p.CgroupID == q.CgroupID
}

// Kind is the type of a listener observation.
type Kind int

const (
	Opened Kind = iota + 1
	Closed
	OwnerChanged
)

// Source says where an observation came from.
type Source int

const (
	SourceEBPF Source = iota + 1
	SourceBaseline
	SourceReconcile
)

// V6Only is an IPv6 socket's IPV6_V6ONLY flag as the kernel reports it. It is fixed
// once the socket is bound, so a listener's value never changes.
type V6Only uint8

const (
	// V6OnlyUnknown: not read (an IPv4 socket, or a source that did not say).
	V6OnlyUnknown V6Only = iota
	// V6OnlyOff: a dual-stack socket; bound to [::] it takes IPv4 too.
	V6OnlyOff
	// V6OnlyOn: IPv6 only.
	V6OnlyOn
)

// Observation is a single listener open or close, as seen by a collector.
type Observation struct {
	Kind   Kind
	Cookie uint64
	Key    ListenerKey
	Proc   Process
	At     time.Time
	Source Source
	// V6Only is the socket's IPV6_V6ONLY flag (Opened only).
	V6Only V6Only
}
