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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/cloud"
	cloudaws "github.com/thapr0digy/portwarden/internal/cloud/aws"
	"github.com/thapr0digy/portwarden/internal/inventory"
	"github.com/thapr0digy/portwarden/internal/inventory/api"
	"github.com/thapr0digy/portwarden/internal/inventory/pg"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// Config is the JSON config file (--config).
type Config struct {
	NATS svc.NATS `json:"nats"`
	// PostgresDSNFile holds the DSN (with its password); PORTWARDEN_INVENTORY_DSN wins.
	PostgresDSNFile string `json:"postgres_dsn_file"`
	// Listen is the API address; loopback by default.
	Listen string `json:"listen"`
	// TokenFile holds the API bearer token; PORTWARDEN_INVENTORY_TOKEN wins.
	TokenFile string `json:"token_file"`
	// SilentAfter: a host without a heartbeat this long is silent (default 90s).
	SilentAfter svc.Duration `json:"silent_after"`
	Cloud       CloudConfig  `json:"cloud"`
}

// CloudConfig turns on the level 3 look-up.
type CloudConfig struct {
	// AWS enables the AWS look-up with the SDK's default credentials (instance role,
	// environment, shared config). Hosts on GCP or Azure always get "unsupported".
	AWS      bool         `json:"aws"`
	Refresh  svc.Duration `json:"refresh"`
	Endpoint string       `json:"endpoint"`
}

func main() {
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
		cfg.Listen = "127.0.0.1:8740"
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

	apiSrv, err := api.New(store, token)
	if err != nil {
		return err
	}
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

	nc, js, err := bus.Connect(cfg.NATS.Bus(natsauth.RoleInventory, "portwarden-inventory"))
	if err != nil {
		return err
	}
	defer nc.Close()
	stream, err := svc.WaitStream(ctx, js)
	if err != nil {
		return err
	}

	cons := &inventory.Consumer{Store: store, Snapshots: inventory.StreamSnapshots{Stream: stream},
		Liveness: liveness.New(cfg.SilentAfter.D(90 * time.Second))}
	if err := cons.SeedLiveness(ctx); err != nil {
		return err
	}
	if cfg.Cloud.AWS {
		prov, err := cloudaws.New(ctx, cloudaws.Options{Endpoint: cfg.Cloud.Endpoint})
		if err != nil {
			return err
		}
		pub := bus.NewPublisher(js, "cloud")
		lookup := inventory.NewCloudLookup(store, map[string]cloud.Provider{"aws": prov}, pub.Publish, pub.RunID)
		lookup.Refresh = cfg.Cloud.Refresh.D(10 * time.Minute)
		cons.Changed = lookup.Notify
		go lookup.Run(ctx)
		slog.Info("cloud look-up on", "providers", "aws (gcp, azure: unsupported)", "refresh", lookup.Refresh.String())
	}
	go func() {
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
	}()

	c, err := bus.Durable(ctx, js, natsauth.ConsumerInventory, bus.DurableOptions{Filters: []string{"asm.>"}})
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
	})
}
