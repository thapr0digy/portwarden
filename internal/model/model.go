// Package model holds the types shared by the agent's collectors and publisher.
package model

import (
	"net/netip"
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

// Process describes a process holding a listening socket.
type Process struct {
	PID, UID uint32
	Comm     string
	Exe      string
}

// Kind is the type of a listener observation.
type Kind int

const (
	Opened Kind = iota + 1
	Closed
)

// Source says where an observation came from.
type Source int

const (
	SourceEBPF Source = iota + 1
	SourceBaseline
)

// Observation is a single listener open or close, as seen by a collector.
type Observation struct {
	Kind   Kind
	Cookie uint64
	Key    ListenerKey
	Proc   Process
	At     time.Time
	Source Source
}
