// portwarden-inventory keeps the current state of every host, listener, exposure and
// proxy route in PostgreSQL from the ASM_EVENTS stream, raises "host silent" when a
// host's heartbeats stop, runs the cloud look-up (level 3) and serves a read-only JSON
// API. See README "Backend".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"

	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/cloud"
	cloudaws "github.com/thapr0digy/portwarden/internal/cloud/aws"
	"github.com/thapr0digy/portwarden/internal/inventory"
	"github.com/thapr0digy/portwarden/internal/inventory/api"
	"github.com/thapr0digy/portwarden/internal/inventory/pg"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/version"
)

// Config is the JSON config file (--config).
type Config struct {
	NATS svc.NATS `json:"nats"`
	// PostgresDSNFile holds the DSN (with its password); PORTWARDEN_INVENTORY_DSN wins.
	PostgresDSNFile string `json:"postgres_dsn_file"`
	// Listen is the API address; loopback by default. The API has no TLS of its own, so a
	// non-loopback address (bearer token in cleartext) is refused unless
	// AllowInsecureListen is set (e.g. behind a TLS-terminating proxy on the same host).
	Listen              string `json:"listen"`
	AllowInsecureListen bool   `json:"allow_insecure_listen"`
	// TokenFile holds the API bearer token; PORTWARDEN_INVENTORY_TOKEN wins.
	TokenFile string `json:"token_file"`
	// SilentAfter: a host without a heartbeat this long is silent (default 90s).
	SilentAfter svc.Duration `json:"silent_after"`
	Cloud       CloudConfig  `json:"cloud"`
	// Reprobe: listeners at level bound or above whose last outside probe is older than
	// this are requested again (default 24h).
	Reprobe   svc.Duration    `json:"reprobe"`
	Retention RetentionConfig `json:"retention"`
}

// RetentionConfig prunes old rows (M8). History and Quarantine are ages; unset means the
// default (90 days, 30 days), "0s" keeps the table forever.
type RetentionConfig struct {
	History    *svc.Duration `json:"history"`
	Quarantine *svc.Duration `json:"quarantine"`
	// Interval between passes (default 1h); Batch rows per DELETE (default 1000).
	Interval svc.Duration `json:"interval"`
	Batch    int          `json:"batch"`
}

func (c Config) retention() inventory.Retention {
	age := func(d *svc.Duration, def time.Duration) time.Duration {
		if d == nil {
			return def
		}
		return time.Duration(*d)
	}
	r := c.Retention
	return inventory.Retention{History: age(r.History, inventory.DefaultHistoryRetention),
		Quarantine: age(r.Quarantine, inventory.DefaultQuarantineRetention), Interval: time.Duration(r.Interval), Batch: r.Batch}.WithDefaults()
}

const defaultListen = "127.0.0.1:8740"

// CloudConfig turns on the level 3 look-up.
type CloudConfig struct {
	// AWS enables the AWS look-up with the SDK's default credentials (instance role,
	// environment, shared config). Hosts on GCP or Azure always get "unsupported".
	AWS      bool         `json:"aws"`
	Refresh  svc.Duration `json:"refresh"`
	Endpoint string       `json:"endpoint"`
	// Regions, when set, are the only regions looked up.
	Regions []string `json:"regions"`
}

func main() {
	version.HandleFlag()
	if len(os.Args) > 1 && os.Args[1] == "forget-host" {
		if err := forgetHost(os.Args[2:], os.Stdout, os.Getenv); err != nil {
			fmt.Fprintln(os.Stderr, "portwarden-inventory forget-host:", err)
			os.Exit(1)
		}
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	path := flag.String("config", "/etc/portwarden/inventory.json", "config file (JSON)")
	flag.Parse()
	if err := run(*path); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("portwarden-inventory", "err", err)
		os.Exit(1)
	}
}

func run(path string) error {
	var cfg Config
	if err := svc.Load(path, &cfg); err != nil {
		return err
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.Retention.Batch < 0 {
		return errors.New("retention.batch must not be negative")
	}
	if err := checkListen(cfg.Listen, cfg.AllowInsecureListen); err != nil {
		return err
	}
	dsn, err := svc.Secret("PORTWARDEN_INVENTORY_DSN", cfg.PostgresDSNFile)
	if err != nil {
		return fmt.Errorf("postgres dsn: %w", err)
	}
	token, err := svc.Secret("PORTWARDEN_INVENTORY_TOKEN", cfg.TokenFile)
	if err != nil {
		return fmt.Errorf("api token: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	store, err := pg.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer store.Close()

	silentAfter := cfg.SilentAfter.D(90 * time.Second)
	cons := &inventory.Consumer{Store: store, Liveness: liveness.New(silentAfter), Feed: liveness.NewFeed(silentAfter, time.Now())}
	// Connect retries in the background, so the API comes up even with NATS down.
	nc, js, err := bus.Connect(cfg.NATS.Bus(natsauth.RoleInventory, "portwarden-inventory", cons.SetConnected))
	if err != nil {
		return err
	}
	defer nc.Close()
	pub := bus.NewPublisher(js, "inventory")
	cons.Announce = func(ctx context.Context, host string) (uint64, error) {
		id := bus.NewEventID()
		return pub.PublishSeq(ctx, bus.ForgottenSubject(host), id, &asmv1.HostForgotten{EventId: id, HostId: host, At: timestamppb.Now()})
	}

	apiSrv, err := api.New(store, token)
	if err != nil {
		return err
	}
	apiSrv.SetForget(cons.Forget)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: apiSrv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		slog.Info("api listening", "addr", ln.Addr().String())
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("api server", "err", err)
			stop()
		}
	}()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()
	stream, err := svc.WaitStream(ctx, js)
	if err != nil {
		return err
	}
	cons.Snapshots = inventory.StreamSnapshots{Stream: stream}
	if err := cons.SeedLiveness(ctx); err != nil {
		return err
	}
	// Background workers stop before the store closes (deferred above).
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	probes := inventory.NewProbeRequester(store, pub.Publish)
	probes.Reprobe = cfg.Reprobe.D(24 * time.Hour)
	cons.Exposed = probes.Notify
	wg.Go(func() { probes.Run(ctx) })
	ret := cfg.retention()
	slog.Info("retention", "history", ret.History.String(), "quarantine", ret.Quarantine.String(), "interval", ret.Interval.String(), "batch", ret.Batch)
	wg.Go(func() { ret.Run(ctx, store) })
	if cfg.Cloud.AWS {
		prov, err := cloudaws.New(ctx, cloudaws.Options{Endpoint: cfg.Cloud.Endpoint, Regions: cfg.Cloud.Regions})
		if err != nil {
			return err
		}
		cpub := bus.NewPublisher(js, "cloud")
		lookup := inventory.NewCloudLookup(store, map[string]cloud.Provider{"aws": prov}, cpub.Publish, cpub.RunID)
		lookup.Refresh = cfg.Cloud.Refresh.D(10 * time.Minute)
		cons.Changed = lookup.Notify
		wg.Go(func() { lookup.Run(ctx) })
		slog.Info("cloud look-up on", "providers", "aws (gcp, azure: unsupported)", "refresh", lookup.Refresh.String())
	}
	wg.Go(func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := cons.CheckSilence(ctx); err != nil {
					slog.Warn("silence check", "err", err)
				}
			}
		}
	})

	c, err := bus.Durable(ctx, js, natsauth.ConsumerInventory, bus.DurableOptions{
		Filters: []string{"asm.>", "pwb.cloud.*.exposure", "pwb.verifier.*.exposure"}})
	if err != nil {
		return err
	}
	slog.Info("consuming", "stream", natsauth.StreamName, "consumer", natsauth.ConsumerInventory)
	return svc.Consume(ctx, c, func(ctx context.Context, m jetstream.Msg) error {
		meta := inventory.Meta{}
		if md, err := m.Metadata(); err == nil {
			meta.StreamSeq, meta.StreamTime = md.Sequence.Stream, md.Timestamp
		}
		return cons.Handle(ctx, m.Subject(), m.Data(), meta)
	}, svc.ConsumeOptions{Quarantine: func(ctx context.Context, m jetstream.Msg, why error) error {
		var seq uint64
		if md, err := m.Metadata(); err == nil {
			seq = md.Sequence.Stream
		}
		return store.Quarantine(ctx, seq, m.Subject(), why.Error(), m.Data())
	}})
}

// checkListen refuses a non-loopback API address without TLS unless allowed.
func checkListen(addr string, allowInsecure bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if ip, err := netip.ParseAddr(host); (err == nil && ip.IsLoopback()) || host == "localhost" || allowInsecure {
		return nil
	}
	return fmt.Errorf("listen %s is not loopback and the API has no TLS: the bearer token would cross the network in cleartext (set allow_insecure_listen to accept that)", addr)
}
