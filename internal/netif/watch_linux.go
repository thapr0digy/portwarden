//go:build linux

package netif

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// WatchAddresses signals on every interface or address change (rtnetlink link and
// address groups). No capability is needed.
func WatchAddresses(ctx context.Context) (<-chan struct{}, error) {
	return subscribe(ctx, unix.NETLINK_ROUTE, unix.RTNLGRP_LINK, unix.RTNLGRP_IPV4_IFADDR, unix.RTNLGRP_IPV6_IFADDR)
}

// WatchNftables signals on every nf_tables change (the NFNLGRP_NFTABLES group, which
// also carries iptables-nft's changes). Joining it needs CAP_NET_ADMIN.
func WatchNftables(ctx context.Context) (<-chan struct{}, error) {
	return subscribe(ctx, unix.NETLINK_NETFILTER, unix.NFNLGRP_NFTABLES)
}

// subscribe joins netlink multicast groups and sends a token (coalesced) whenever a
// message, or a buffer overrun, arrives. The channel closes when ctx ends or the socket
// fails.
func subscribe(ctx context.Context, proto int, groups ...int) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	for _, g := range groups {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, g); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("netlink join group %d: %w", g, err)
		}
	}
	// A non-blocking fd goes through Go's poller, so Close unblocks the reader.
	f := os.NewFile(uintptr(fd), "netlink")
	out := make(chan struct{}, 1)
	go func() {
		<-ctx.Done()
		_ = f.Close()
	}()
	go func() {
		defer close(out)
		buf := make([]byte, 64<<10)
		for {
			_, err := f.Read(buf)
			if err != nil && !errors.Is(err, unix.ENOBUFS) {
				return
			}
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()
	return out, nil
}
