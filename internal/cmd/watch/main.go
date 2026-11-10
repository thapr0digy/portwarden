// Package watch is `portwarden watch` (also installed as portwarden-watch): it prints the
// ASM_EVENTS stream, one line per message, for humans and for dev/e2e.sh. It is
// read-only: an ordered consumer leaves no state on the server.
package watch

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/cmd/cli"
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

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet(Name, flag.ContinueOnError)
	fs.SetOutput(stderr)
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

// Name is the command's name in its usage, version line and errors.
const Name = "portwarden-watch"

// Run is `portwarden watch` (and the portwarden-watch name): it prints a line per message
// on stdout until SIGTERM or SIGINT and returns cli.Exit with the status the process ends
// with (2 for bad flags, 1 when it cannot watch).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if version.Requested(args) {
		version.Fprint(stdout, Name)
		return nil
	}
	opts, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		fmt.Fprintln(stderr, Name+":", err)
		return cli.Exit(2)
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, opts, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, Name+":", err)
		return cli.Exit(1)
	}
	return nil
}

func run(ctx context.Context, opts options, stdout, stderr io.Writer) error {
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
			fmt.Fprintln(stderr, Name+":", err)
			return
		}
		if gap := gaps.check(p.run, p.seq); gap != "" {
			fmt.Fprintln(stdout, gap)
		}
		fmt.Fprintln(stdout, p.line)
	})
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}
	defer cc.Stop()
	<-ctx.Done()
	return nil
}
