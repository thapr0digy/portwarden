//go:build linux

// Command lw-agent reports the host's TCP listening sockets to NATS JetStream.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/listener-watch/internal/agent"
	"github.com/thapr0digy/listener-watch/internal/baseline"
	"github.com/thapr0digy/listener-watch/internal/hostid"
	"github.com/thapr0digy/listener-watch/internal/preflight"
	"github.com/thapr0digy/listener-watch/internal/probes"
	"github.com/thapr0digy/listener-watch/internal/publish"
	"github.com/thapr0digy/listener-watch/internal/state"
)

type options struct {
	natsURL, natsCreds, tlsCA, tlsCert, tlsKey, machineIDPath string
	heartbeat                                                 time.Duration
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("lw-agent", flag.ContinueOnError)
	fs.StringVar(&o.natsURL, "nats-url", "nats://127.0.0.1:4222", "NATS server URL")
	fs.StringVar(&o.natsCreds, "nats-creds", "", "NATS credentials file")
	fs.StringVar(&o.tlsCA, "tls-ca", "", "CA certificate for the NATS server")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "client certificate")
	fs.StringVar(&o.tlsKey, "tls-key", "", "client key")
	fs.StringVar(&o.machineIDPath, "machine-id-path", hostid.DefaultPath, "file holding the host id")
	fs.DurationVar(&o.heartbeat, "heartbeat", 30*time.Second, "interval between heartbeat messages")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.heartbeat <= 0 {
		return o, fmt.Errorf("--heartbeat must be positive, got %s", o.heartbeat)
	}
	return o, nil
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	opts, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "lw-agent:", err)
		os.Exit(2)
	}
	if err := run(opts, log); err != nil {
		log.Error("lw-agent failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(opts options, log *slog.Logger) error {
	if err := preflight.Check(kernelRelease()); err != nil {
		return err
	}
	host, err := hostid.Read(opts.machineIDPath)
	if err != nil {
		return err
	}
	hostNetNS, err := baseline.HostNetNS()
	if err != nil {
		return fmt.Errorf("host network namespace: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Probes first, so no listener is missed while the baseline is taken.
	pr, err := probes.Start(hostNetNS)
	if err != nil {
		return fmt.Errorf("start probes: %w", err)
	}
	pub, err := publish.New(ctx, publish.Config{
		URL: opts.natsURL, CredsFile: opts.natsCreds,
		CAFile: opts.tlsCA, CertFile: opts.tlsCert, KeyFile: opts.tlsKey,
		HostID: host,
	})
	if err != nil {
		_ = pr.Close()
		return fmt.Errorf("publisher: %w", err)
	}
	log.Info("started", "host_id", host, "netns", hostNetNS, "nats_url", opts.natsURL)

	var beats sync.WaitGroup
	beats.Add(1)
	go func() {
		defer beats.Done()
		heartbeatLoop(ctx, opts.heartbeat, pr, pub)
	}()

	runErr := agent.Run(ctx, pr, baseline.Snapshot, loggingSink{pub, log})
	stop() // end the heartbeat loop even if Run returned on its own
	beats.Wait()

	// A source that closes while we were not asked to stop means the reader died.
	if runErr == nil && ctx.Err() == nil {
		runErr = fmt.Errorf("probe reader stopped: %w", errOrUnknown(pr.Err()))
	}
	if err := pr.Close(); err != nil {
		log.Warn("closing probes", "error", err.Error())
	}
	if err := pub.Close(); err != nil {
		log.Warn("closing publisher", "error", err.Error())
	}
	if runErr == nil {
		log.Info("stopped")
	}
	return runErr
}

func errOrUnknown(err error) error {
	if err == nil {
		return errors.New("event channel closed")
	}
	return err
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

func heartbeatLoop(ctx context.Context, every time.Duration, pr *probes.Probes, pub *publish.Publisher) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pub.Heartbeat(pr.Counters())
		}
	}
}

// loggingSink logs each snapshot's size as it is queued; delivery to NATS is separate.
type loggingSink struct {
	*publish.Publisher
	log *slog.Logger
}

func (s loggingSink) Snapshot(listeners []state.Listener) {
	s.log.Info("snapshot queued", "listeners", len(listeners))
	s.Publisher.Snapshot(listeners)
}
