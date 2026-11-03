// fakehost publishes a heartbeat every second as another host (dev/e2e.sh), so the
// backend's feed stays alive while the real agent is stopped and the silence check sees
// one host go silent rather than the whole feed stall.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/thapr0digy/portwarden/internal/publish"
)

func main() {
	url := flag.String("nats-url", "nats://127.0.0.1:4222", "NATS URL")
	nkey := flag.String("nats-nkey", "", "the host user's nkey seed")
	host := flag.String("host", "", "host id")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	p, err := publish.New(ctx, publish.Config{URL: *url, HostID: *host, NkeyFile: *nkey})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakehost:", err)
		os.Exit(1)
	}
	defer p.Close()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		p.Heartbeat(0)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
