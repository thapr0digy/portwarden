//go:build !linux

package netif

import (
	"context"
	"errors"
)

var errLinuxOnly = errors.New("netlink notifications are linux only")

// WatchAddresses is linux only.
func WatchAddresses(context.Context) (<-chan struct{}, error) { return nil, errLinuxOnly }

// WatchNftables is linux only.
func WatchNftables(context.Context) (<-chan struct{}, error) { return nil, errLinuxOnly }
