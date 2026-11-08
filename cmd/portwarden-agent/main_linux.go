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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/agent"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/baseline"
	"github.com/thapr0digy/portwarden/internal/cgroupns"
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
	"github.com/thapr0digy/portwarden/internal/tamper"
	"github.com/thapr0digy/portwarden/internal/version"
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
	viewDebounce     = time.Second     // a burst of firewall or address changes is read once
	viewMaxWait      = 5 * time.Second // …but no later than this after its first change
	imdsTimeout      = 2 * time.Second
	imdsRetry        = 30 * time.Second
	dmiDir           = "/sys/class/dmi/id"
	defaultProxyPoll = 2 * time.Second
	proxySettle      = 2 * time.Second  // a changed proxy config is read once it held still this long
	proxyMinGap      = 10 * time.Second // at most one proxy.routes per proxy per this interval
	defaultTamper    = 30 * time.Second
	defaultDropRate  = 1000
)

type options struct {
	natsURL, natsCreds, natsNkey, tlsCA, tlsCert, tlsKey, machineIDPath string
	heartbeat                                                           time.Duration
	spoolDir                                                            string
	spoolMax                                                            int64
	closeGrace, recheck                                                 time.Duration
	firewallPoll                                                        time.Duration
	imds                                                                string
	proxyMap                                                            string
	proxyPoll                                                           time.Duration
	tamperInterval                                                      time.Duration
	tamperFiles                                                         []string
	tamperDropRate                                                      float64
	natsNkeyDir                                                         string
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("portwarden-agent", flag.ContinueOnError)
	fs.StringVar(&o.natsURL, "nats-url", "nats://127.0.0.1:4222", "NATS server URL")
	fs.StringVar(&o.natsCreds, "nats-creds", "", "NATS credentials file")
	fs.StringVar(&o.natsNkey, "nats-nkey", "", "NATS nkey user seed file (portwarden-natsauth mint --role host)")
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
	fs.StringVar(&o.proxyMap, "proxy-map", "auto", "map reverse proxies (nginx, Apache, HAProxy configs; observed proxy connections): auto or off")
	fs.DurationVar(&o.proxyPoll, "proxy-poll", defaultProxyPoll, "how often proxy config files and connection counts are checked")
	fs.DurationVar(&o.tamperInterval, "tamper-interval", defaultTamper, "interval between tamper self-checks (0 disables them)")
	fs.Float64Var(&o.tamperDropRate, "tamper-drop-rate", defaultDropRate, "ring-buffer drops per minute at which events_dropped pages (below it the flag is informational; 0 never pages)")
	fs.StringVar(&o.natsNkeyDir, "nats-nkey-dir", "", "directory of per-host nkey seeds (host-<host id>.nk, as portwarden-natsauth mint writes them): the agent uses its own host's (one Secret for a whole Kubernetes cluster)")
	tamperFiles := fs.String("tamper-files", "", "comma-separated absolute paths of extra files whose change is a tamper signal (e.g. the NATS credentials)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.tamperDropRate < 0 {
		return o, fmt.Errorf("--tamper-drop-rate must not be negative, got %v", o.tamperDropRate)
	}
	if o.natsNkeyDir != "" && (o.natsNkey != "" || o.natsCreds != "") {
		return o, errors.New("--nats-nkey-dir excludes --nats-nkey and --nats-creds")
	}
	if o.tamperInterval < 0 {
		return o, fmt.Errorf("--tamper-interval must not be negative, got %s", o.tamperInterval)
	}
	for _, f := range strings.Split(*tamperFiles, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if !filepath.IsAbs(f) {
			return o, fmt.Errorf("--tamper-files: %q is not an absolute path", f)
		}
		o.tamperFiles = append(o.tamperFiles, f)
	}
	if o.firewallPoll <= 0 {
		return o, fmt.Errorf("--firewall-poll must be positive, got %s", o.firewallPoll)
	}
	if o.imds != "auto" && o.imds != "off" {
		return o, fmt.Errorf("--imds must be auto or off, got %q", o.imds)
	}
	if o.proxyMap != "auto" && o.proxyMap != "off" {
		return o, fmt.Errorf("--proxy-map must be auto or off, got %q", o.proxyMap)
	}
	if o.proxyPoll <= 0 {
		return o, fmt.Errorf("--proxy-poll must be positive, got %s", o.proxyPoll)
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
	version.HandleFlag()
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
	if opts.natsNkeyDir != "" {
		// One Secret for a cluster holds every node's seed; each agent takes its own, so
		// hosts stay unable to publish for each other (ruling R-f).
		opts.natsNkey = filepath.Join(opts.natsNkeyDir, "host-"+host+".nk")
		if _, err := os.Stat(opts.natsNkey); err != nil {
			return fmt.Errorf("--nats-nkey-dir: no seed for this host (%s): %w", host, err)
		}
	}
	hostNetNS, err := baseline.HostNetNS()
	if err != nil {
		return fmt.Errorf("host network namespace: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// Set when NATS refuses the agent's own subjects: the agent exits with it, so wrong
	// credentials show as a failed unit and host silence, never as lost messages.
	var deniedErr atomic.Pointer[error]

	// Socket units are listed before the baseline, so socket-activated listeners in the
	// startup snapshot carry their units; Match never blocks after this.
	matcher := sdsocket.NewMatcher(sdsocket.NewDBusLister(), socketUnitTTL, uint64(hostNetNS))
	primeCtx, cancelPrime := context.WithTimeout(ctx, socketUnitPrime)
	matcher.Prime(primeCtx)
	cancelPrime()
	resolver := procinfo.NewResolver("/proc", "/sys/fs/cgroup", hashMaxBytes)
	// In a container (a DaemonSet) /proc cgroup paths are relative to a private cgroup
	// namespace; units, containers and the proxy cgroups need the host's paths.
	cgns, err := cgroupns.Detect("/proc", "/sys/fs/cgroup")
	if err != nil {
		log.Warn("cgroup namespace root unknown; cgroup paths are used as /proc shows them", "err", err.Error())
	} else if cgns.Root != "" {
		log.Info("private cgroup namespace; translating cgroup paths", "root", cgns.Root)
	}
	resolver.SetCgroupTranslator(cgns.Host)
	enrich := newEnricher(resolver, matcher, hostNetNS)

	// The first exposure view (firewall and interfaces; each tool read is bounded) is read
	// before the probes start, so the probe buffer is not held open for it. The watcher
	// joins the change notifications first, so a change during startup is not missed.
	watcher := exposure.NewWatcher(exposure.WatchConfig{
		Config: exposure.Config{
			HostNetNS:  hostNetNS,
			Run:        exposure.ExecRunner,
			Interfaces: netif.Snapshot,
			NetnsAddrs: exposure.ProcNetnsAddrs("/proc"),
		},
		Debounce:         viewDebounce,
		MaxWait:          viewMaxWait,
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

	// Extra watched files are hashed before anything starts: a missing one is a bad flag.
	var extraFiles *tamper.FileSet
	if opts.tamperInterval > 0 && len(opts.tamperFiles) > 0 {
		if extraFiles, err = tamper.NewFileSet("files", tamper.KindFileChanged, tamper.StaticFiles(opts.tamperFiles...)); err != nil {
			return fmt.Errorf("--tamper-files: %w", err)
		}
	}

	// Probes first, so no listener is missed while the baseline is taken.
	pr, err := probes.Start()
	if err != nil {
		return fmt.Errorf("start probes: %w", err)
	}
	runNumber, err := publish.NextRunNumber(opts.spoolDir)
	if err != nil {
		// Ordering then falls back to run ids; never block the agent on it.
		slog.Warn("run counter unavailable; consumers order runs by run id", "err", err)
		runNumber = 0
	}
	self := selfIdentity(log)
	pub, err := publish.New(ctx, publish.Config{
		URL: opts.natsURL, CredsFile: opts.natsCreds, NkeyFile: opts.natsNkey,
		CAFile: opts.tlsCA, CertFile: opts.tlsCert, KeyFile: opts.tlsKey,
		HostID:   host,
		SpoolDir: opts.spoolDir, SpoolMax: opts.spoolMax,
		BootID: publish.ReadBootID(publish.BootIDPath), RunNumber: runNumber,
		AgentVersion: version.Version, ExeSHA256: self.hash,
		LocalAddr: hostInfo.SetIngestLocal,
		OnDenied: func(subject string) {
			if strings.HasSuffix(subject, "."+bus.KindTamper) {
				log.Error("NATS refuses tamper events: re-render the auth block (portwarden-natsauth render) for this release", "subject", subject)
				return
			}
			err := fmt.Errorf("NATS refuses this agent's publishes (%s): its credentials are not host %s's user", subject, host)
			if deniedErr.CompareAndSwap(nil, &err) {
				stop()
			}
		},
	})
	if err != nil {
		_ = pr.Close()
		return fmt.Errorf("publisher: %w", err)
	}
	pubRef.Store(pub)
	// The fingerprint first: the host block set next is the first one stamped with it.
	pub.SetFirewall(initialView.FirewallDigest())
	pub.SetHost(hostInfo.Host())

	judges := make(chan agent.Judge, 1)
	// The host block and the fingerprint follow the view the agent loop actually judges
	// with (agentOpts.OnJudge), not the watcher's latest read, so no event of the old
	// ruleset carries the new fingerprint.
	go watcher.Run(ctx, initialView, func(v *exposure.View) { offerLatest(judges, v) })
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
	log.Info("started", "version", version.Version, "host_id", host, "netns", hostNetNS, "nats_url", opts.natsURL,
		"spool_dir", opts.spoolDir, "spool_max", opts.spoolMax)

	var beats sync.WaitGroup
	beats.Add(1)
	go func() {
		defer beats.Done()
		heartbeatLoop(ctx, opts.heartbeat, pr, pub)
	}()

	agentOpts := agent.Options{
		Enrich:     enrich,
		CloseGrace: opts.closeGrace,
		Recheck:    opts.recheck,
		Drops:      pr.Counters,
		Settle:     recheckSettle,
		Judge:      initialView,
		Judges:     judges,
		OnJudge:    onJudge(pub, hostInfo),
		// Removals and first route sets go out at once; later changes at most once per gap.
		ProxyMinInterval: proxyMinGap,
	}
	var proxyConns *probes.ProxyConns
	if opts.proxyMap == "auto" {
		proxyConns = startProxyMapping(ctx, opts, hostNetNS, resolver, cgns.Host, &agentOpts, log)
	}

	if opts.tamperInterval > 0 {
		mon := newTamperMonitor(self, extraFiles, opts.tamperDropRate, pr, proxyConns, log)
		beats.Add(1)
		go func() {
			defer beats.Done()
			tamperLoop(ctx, opts.tamperInterval, mon, pub, log)
		}()
	}

	runErr := agent.Run(ctx, pr, baseline.Snapshot, loggingSink{pub, log}, agentOpts)
	if e := deniedErr.Load(); e != nil {
		runErr = *e
	}
	stop() // end the heartbeat loop even if Run returned on its own
	beats.Wait()

	// A source that closes while we were not asked to stop means the reader died.
	if runErr == nil && ctx.Err() == nil {
		runErr = fmt.Errorf("probe reader stopped: %w", errOrUnknown(pr.Err()))
	}
	if err := pr.Close(); err != nil {
		log.Warn("closing probes", "error", err.Error())
	}
	if proxyConns != nil {
		if err := proxyConns.Close(); err != nil {
			log.Warn("closing proxy connection probes", "error", err.Error())
		}
	}
	if runErr == nil {
		// Asked to stop: the clean-shutdown marker goes first in the drain below, so the
		// alerter does not read this restart as unclean. Error exits never send it.
		pub.Stopping()
	}
	if err := pub.Close(); err != nil {
		log.Warn("closing publisher", "error", err.Error())
	}
	if runErr == nil {
		log.Info("stopped")
	}
	return runErr
}

// exeIdentity is the agent's executable as hashed once at start.
type exeIdentity struct{ path, hash string }

// selfIdentity hashes the running executable once, off the event loop (before the agent
// loop starts). A failure leaves the hash empty for the run (heartbeats then carry "")
// and is logged; the self_exe tamper check then takes its own baseline.
func selfIdentity(log *slog.Logger) exeIdentity {
	path, hash, err := tamper.SelfExeHash()
	if err != nil {
		log.Warn("agent executable not hashed; heartbeats carry no exe_sha256 this run", "err", err.Error())
		return exeIdentity{}
	}
	return exeIdentity{path: path, hash: hash}
}

// offerLatest hands j to the agent loop, replacing a judge it has not taken yet: only
// the newest view matters.
// onJudge publishes nothing for a judge that is not a viewInfo; the views must be.
var _ viewInfo = (*exposure.View)(nil)

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

// ProxyRoutes logs each route set as it is queued.
func (s loggingSink) ProxyRoutes(sets []model.ProxyRoutes) {
	for _, r := range sets {
		s.log.Info("proxy routes queued", "proxy", r.Proxy.ID, "trigger", r.Trigger,
			"routes", len(r.Routes), "removed", r.Removed)
	}
	s.Publisher.ProxyRoutes(sets)
}

func (s loggingSink) Snapshot(listeners []state.Listener, proxies []model.ProxyRoutes) {
	s.log.Info("snapshot queued", "listeners", len(listeners), "proxies", len(proxies))
	s.Publisher.Snapshot(listeners, proxies)
}
