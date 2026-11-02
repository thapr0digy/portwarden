//go:build linux

package baseline

import (
	"fmt"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/model"
)

// Snapshot returns one baseline Opened observation per TCP listener and per UDP socket
// bound to an explicit port, in every network namespace, and per process holding it
// (see join). Owners are read before the host dumps: a socket that appears in between is
// listed without an owner, and the live probe has already queued its Opened, with the
// owner.
//
// A first, discarded dump makes the kernel assign a cookie to every TCP listener
// (inet_diag does, and the owners iterator can only read the cookie of an MPTCP
// listener's subflow, not assign it; see bpf/owners.bpf.c).
//
// The dumps and iter/udp list the calling thread's netns, so Snapshot stays on one
// thread and keys them with that thread's netns: the host's, in the agent.
func Snapshot() ([]model.Observation, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	netns, err := netNSOf("/proc/thread-self/ns/net")
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
	udp, err := UDPSockets()
	if err != nil {
		return nil, err
	}
	return join(netns, listeners, udp, owners, time.Now()), nil
}

// HostNetNS returns the inode of the agent's network namespace, which is the host's.
func HostNetNS() (uint32, error) {
	return netNSOf("/proc/self/ns/net")
}

func netNSOf(path string) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return uint32(st.Ino), nil
}
