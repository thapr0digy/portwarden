//go:build linux

// Command portwarden-agent reports the host's TCP and UDP listening sockets to NATS JetStream.
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
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/agent"
	"github.com/thapr0digy/portwarden/internal/baseline"
	"github.com/thapr0digy/portwarden/internal/exposure"
	"github.com/thapr0digy/portwarden/internal/hostid"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/preflight"
	"github.com/thapr0digy/portwarden/internal/probes"
	"github.com/thapr0digy/portwarden/internal/procinfo"
	"github.com/thapr0digy/portwarden/internal/publicip"
	"github.com/thapr0digy/portwarden/internal/publish"
	"github.com/thapr0digy/portwarden/internal/sdsocket"
	"github.com/thapr0digy/portwarden/internal/state"
)

const (
	hashMaxBytes     = 64 << 20 // executables larger than this are not hashed (bounds inline hashing)
	socketUnitTTL    = 30 * time.Second
	socketUnitPrime  = 2 * time.Second // bounds the startup socket unit list
	recheckSettle    = 250 * time.Millisecond
	defaultSpoolMax  = "64MiB"
	defaultSpoolDir  = "/var/lib/portwarden/spool"
	defaultCloseWait = 2 * time.Second
	defaultRecheck   = 5 * time.Minute
	defaultFWPoll    = 30 * time.Second
	viewDebounce     = time.Second // a burst of firewall or address changes is read once
	imdsTimeout      = 2 * time.Second
	imdsRetry        = 30 * time.Second
	dmiDir           = "/sys/class/dmi/id"
)

type options struct {
	natsURL, natsCreds, tlsCA, tlsCert, tlsKey, machineIDPath string
	heartbeat                                                 time.Duration
	spoolDir                                                  string
	spoolMax                                                  int64
	closeGrace, recheck                                       time.Duration
	firewallPoll                                              time.Duration
	imds                                                      string
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("portwarden-agent", flag.ContinueOnError)
	fs.StringVar(&o.natsURL, "nats-url", "nats://127.0.0.1:4222", "NATS server URL")
	fs.StringVar(&o.natsCreds, "nats-creds", "", "NATS credentials file")
	fs.StringVar(&o.tlsCA, "tls-ca", "", "CA certificate for the NATS server")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "client certificate")
	fs.StringVar(&o.tlsKey, "tls-key", "", "client key")
	fs.StringVar(&o.machineIDPath, "machine-id-path", hostid.DefaultPath, "file holding the host id")
	fs.DurationVar(&o.heartbeat, "heartbeat", 30*time.Second, "interval between heartbeat messages")
	fs.StringVar(&o.spoolDir, "spool-dir", defaultSpoolDir, "directory for unsent messages (\"\" keeps them in memory)")
	spoolMax := fs.String("spool-max", defaultSpoolMax, "spool size limit in bytes (KiB, MiB and GiB suffixes)")
	fs.DurationVar(&o.closeGrace, "close-grace", defaultCloseWait, "delay before a closed listener is reported (0 reports at once)")
	fs.DurationVar(&o.recheck, "recheck", defaultRecheck, "interval between full listener rechecks (0 disables)")
	fs.DurationVar(&o.firewallPoll, "firewall-poll", defaultFWPoll, "firewall re-read interval when change notifications are unavailable or iptables-legacy is in use")
	fs.StringVar(&o.imds, "imds", "auto", "cloud metadata for public IPs: auto (only when DMI says AWS, GCP or Azure) or off")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.firewallPoll <= 0 {
		return o, fmt.Errorf("--firewall-poll must be positive, got %s", o.firewallPoll)
	}
	if o.imds != "auto" && o.imds != "off" {
		return o, fmt.Errorf("--imds must be auto or off, got %q", o.imds)
	}
	if o.heartbeat <= 0 {
		return o, fmt.Errorf("--heartbeat must be positive, got %s", o.heartbeat)
	}
	if o.closeGrace < 0 {
		return o, fmt.Errorf("--close-grace must not be negative, got %s", o.closeGrace)
	}
	if o.recheck < 0 {
		return o, fmt.Errorf("--recheck must not be negative, got %s", o.recheck)
	}
	n, err := parseSize(*spoolMax)
	if err != nil {
		return o, fmt.Errorf("--spool-max: %w", err)
	}
	o.spoolMax = n
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
		fmt.Fprintln(os.Stderr, "portwarden-agent:", err)
		os.Exit(2)
	}
	if err := run(opts, log); err != nil {
		log.Error("portwarden-agent failed", "error", err.Error())
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

	// Socket units are listed before the baseline, so socket-activated listeners in the
	// startup snapshot carry their units; Match never blocks after this.
	matcher := sdsocket.NewMatcher(sdsocket.NewDBusLister(), socketUnitTTL, uint64(hostNetNS))
	primeCtx, cancelPrime := context.WithTimeout(ctx, socketUnitPrime)
	matcher.Prime(primeCtx)
	cancelPrime()
	enrich := newEnricher(procinfo.NewResolver("/proc", "/sys/fs/cgroup", hashMaxBytes), matcher, hostNetNS)

	// The first exposure view (firewall and interfaces; each tool read is bounded) is read
	// before the probes start, so the probe buffer is not held open for it.
	watcher := exposure.NewWatcher(exposure.WatchConfig{
		Config: exposure.Config{
			HostNetNS:  hostNetNS,
			Run:        exposure.ExecRunner,
			Interfaces: netif.Snapshot,
			NetnsAddrs: exposure.ProcNetnsAddrs("/proc"),
		},
		Debounce:         viewDebounce,
		Poll:             opts.firewallPoll,
		Recheck:          opts.recheck,
		FirewallChanges:  netif.WatchNftables,
		InterfaceChanges: netif.WatchAddresses,
	})
	initialView := watcher.Initial(ctx)
	var pubRef atomic.Pointer[publish.Publisher]
	hostInfo := publicip.NewCollector(func(h model.HostInfo) {
		if p := pubRef.Load(); p != nil {
			p.SetHost(h)
		}
	})
	if ifs, err := initialView.Interfaces(); err == nil {
		hostInfo.SetInterfaces(ifs)
	}
	hostInfo.SetConditions(initialView.Conditions())

	// Probes first, so no listener is missed while the baseline is taken.
	pr, err := probes.Start()
	if err != nil {
		return fmt.Errorf("start probes: %w", err)
	}
	pub, err := publish.New(ctx, publish.Config{
		URL: opts.natsURL, CredsFile: opts.natsCreds,
		CAFile: opts.tlsCA, CertFile: opts.tlsCert, KeyFile: opts.tlsKey,
		HostID:   host,
		SpoolDir: opts.spoolDir, SpoolMax: opts.spoolMax,
		LocalAddr: hostInfo.SetIngestLocal,
	})
	if err != nil {
		_ = pr.Close()
		return fmt.Errorf("publisher: %w", err)
	}
	pubRef.Store(pub)
	pub.SetHost(hostInfo.Host())

	judges := make(chan agent.Judge, 1)
	go watcher.Run(ctx, initialView, func(v *exposure.View) {
		if ifs, err := v.Interfaces(); err == nil {
			hostInfo.SetInterfaces(ifs)
		}
		hostInfo.SetConditions(v.Conditions())
		offerLatest(judges, v)
	})
	if opts.imds == "auto" {
		if cloud := publicip.Detect(dmiDir); cloud != "" {
			log.Info("cloud detected; reading instance metadata", "cloud", cloud)
			refresh := opts.recheck
			if refresh <= 0 {
				refresh = defaultRecheck
			}
			go publicip.RunIMDS(ctx, publicip.NewClient("", imdsTimeout), cloud, refresh, imdsRetry, hostInfo.SetCloud)
		}
	}
	log.Info("started", "host_id", host, "netns", hostNetNS, "nats_url", opts.natsURL,
		"spool_dir", opts.spoolDir, "spool_max", opts.spoolMax)

	var beats sync.WaitGroup
	beats.Add(1)
	go func() {
		defer beats.Done()
		heartbeatLoop(ctx, opts.heartbeat, pr, pub)
	}()

	runErr := agent.Run(ctx, pr, baseline.Snapshot, loggingSink{pub, log}, agent.Options{
		Enrich:     enrich,
		CloseGrace: opts.closeGrace,
		Recheck:    opts.recheck,
		Drops:      pr.Counters,
		Settle:     recheckSettle,
		Judge:      initialView,
		Judges:     judges,
	})
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

// offerLatest hands j to the agent loop, replacing a judge it has not taken yet: only
// the newest view matters.
func offerLatest(ch chan agent.Judge, j agent.Judge) {
	for {
		select {
		case ch <- j:
			return
		default:
		}
		select {
		case <-ch:
		default:
		}
	}
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
