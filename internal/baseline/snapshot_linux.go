//go:build linux

package baseline

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/model"
)

// Snapshot returns one baseline Opened observation per TCP listener in the host
// network namespace and per process holding it (see join). Owners are read before the
// listeners: a socket that appears in between is listed without an owner, and the live
// probe has already queued its Opened, with the owner.
//
// A first, discarded dump makes the kernel assign a cookie to every listener (inet_diag
// does, and the owners iterator can only read the cookie of an MPTCP listener's subflow,
// not assign it; see bpf/owners.bpf.c).
func Snapshot() ([]model.Observation, error) {
	netns, err := HostNetNS()
	if err != nil {
		return nil, err
	}
	if _, err := Listeners(); err != nil {
		return nil, fmt.Errorf("assign listener cookies: %w", err)
	}
	owners, err := Owners()
	if err != nil {
		return nil, err
	}
	listeners, err := Listeners()
	if err != nil {
		return nil, err
	}
	return join(netns, listeners, owners, time.Now()), nil
}

// HostNetNS returns the inode of the agent's network namespace, which is the host's.
func HostNetNS() (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		return 0, fmt.Errorf("stat /proc/self/ns/net: %w", err)
	}
	return uint32(st.Ino), nil
}
