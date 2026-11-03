// portwarden-watch prints the ASM_EVENTS stream, one line per message, for humans and for
// dev/e2e.sh. It is read-only: an ordered consumer leaves no state on the server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/version"
)

const streamName = "ASM_EVENTS"

type options struct {
	natsURL   string
	natsCreds string
	natsNkey  string
	host      string
	since     time.Duration
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("portwarden-watch", flag.ContinueOnError)
	fs.StringVar(&o.natsURL, "nats-url", "nats://127.0.0.1:4222", "NATS server URL")
	fs.StringVar(&o.natsCreds, "nats-creds", "", "NATS credentials file")
	fs.StringVar(&o.natsNkey, "nats-nkey", "", "NATS nkey user seed file (the user needs stream read and consumer rights, e.g. the admin)")
	fs.StringVar(&o.host, "host", "*", "host id (contents of /etc/machine-id) to watch, or * for all hosts")
	fs.DurationVar(&o.since, "since", 10*time.Minute, "replay messages from this long ago (0s = only new messages)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.since < 0 {
		return o, fmt.Errorf("--since must not be negative, got %s", o.since)
	}
	if o.natsCreds != "" && o.natsNkey != "" {
		return o, errors.New("--nats-creds and --nats-nkey are exclusive")
	}
	if o.host == "" {
		return o, errors.New("--host must not be empty")
	}
	return o, nil
}

func main() {
	version.HandleFlag()
	opts, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "portwarden-watch:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "portwarden-watch:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opts options) error {
	copts := []nats.Option{nats.Name("portwarden-watch")}
	if opts.natsCreds != "" {
		copts = append(copts, nats.UserCredentials(opts.natsCreds))
	}
	if opts.natsNkey != "" {
		nk, err := nats.NkeyOptionFromSeed(opts.natsNkey)
		if err != nil {
			return fmt.Errorf("nkey: %w", err)
		}
		copts = append(copts, nk)
	}
	nc, err := nats.Connect(opts.natsURL, copts...)
	if err != nil {
		return fmt.Errorf("connect %s: %w", opts.natsURL, err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}
	start := time.Now().Add(-opts.since)
	stream, err := js.Stream(ctx, streamName)
	if err != nil {
		return fmt.Errorf("stream %s: %w", streamName, err)
	}
	cons, err := stream.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{
		FilterSubjects: []string{"asm." + opts.host + ".>", "pwb.cloud." + opts.host + ".exposure", "pwb.verifier." + opts.host + ".exposure"},
		DeliverPolicy:  jetstream.DeliverByStartTimePolicy,
		OptStartTime:   &start,
	})
	if err != nil {
		return fmt.Errorf("ordered consumer: %w", err)
	}

	var gaps gapTracker
	cc, err := cons.Consume(func(m jetstream.Msg) {
		p, err := parseMessage(m.Subject(), m.Data())
		if err != nil {
			fmt.Fprintln(os.Stderr, "portwarden-watch:", err)
			return
		}
		if gap := gaps.check(p.run, p.seq); gap != "" {
			fmt.Println(gap)
		}
		fmt.Println(p.line)
	})
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}
	defer cc.Stop()
	<-ctx.Done()
	return nil
}
