package sdsocket

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// A bus socket that accepts but never answers must not hang the lister past its context.
func TestDBusListerBoundedByContext(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "bus")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // held open, never answered
		}
	}()
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+sock)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := NewDBusLister().SocketUnits(ctx); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from an unresponsive bus")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SocketUnits hung past its context")
	}
}
