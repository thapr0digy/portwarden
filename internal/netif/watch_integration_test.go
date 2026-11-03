//go:build integration && linux

package netif

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// Runs as root in the VM (make itest): adds a dummy interface and an nft table and
// expects each watcher to signal.
func TestWatchersSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, err := WatchAddresses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := WatchNftables(ctx)
	if err != nil {
		t.Fatal(err)
	}
	drain := func(c <-chan struct{}) {
		for {
			select {
			case <-c:
			case <-time.After(200 * time.Millisecond):
				return
			}
		}
	}
	drain(addrs)
	drain(tables)

	run(t, "ip", "link", "add", "pwtest0", "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "pwtest0").Run() })
	run(t, "ip", "addr", "add", "198.18.0.1/24", "dev", "pwtest0")
	waitSignal(t, addrs, "address change")

	run(t, "nft", "add", "table", "inet", "pwtest")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "pwtest").Run() })
	waitSignal(t, tables, "nft change")

	cancel()
	select {
	case _, ok := <-tables:
		if ok {
			// One token may still be buffered; the next receive sees the close.
			<-tables
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not close on cancel")
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

func waitSignal(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatalf("no signal for %s", what)
	}
}
