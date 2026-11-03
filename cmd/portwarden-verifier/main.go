// portwarden-verifier is the outside checker: run it on a machine outside the servers'
// networks (fixed source addresses with a clear reverse DNS name, design §9). It probes
// level ≥ bound listeners on inventory addresses inside its allowlist and publishes
// asm.<host>.exposure.confirmed. See README "Backend".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/verifier"
)

// Config is the JSON config file (--config).
type Config struct {
	NATS svc.NATS `json:"nats"`
	// Checker names this checker in its results, e.g. "portwarden-verifier@probe-1".
	Checker string `json:"checker"`
	// AllowCIDRs is the allowlist; required (an empty one probes nothing, so it is refused).
	AllowCIDRs []string `json:"allow_cidrs"`
	// HostAddresses adds inventory addresses per host id (e.g. private addresses the
	// checker can reach, or ones the agent cannot see behind 1:1 NAT).
	HostAddresses map[string][]string `json:"host_addresses"`
	Rate          struct {
		GlobalPerSecond  float64 `json:"global_per_second"`
		PerHostPerMinute float64 `json:"per_host_per_minute"`
		Concurrency      int     `json:"concurrency"`
	} `json:"rate"`
	Timeouts struct {
		Connect svc.Duration `json:"connect"`
		Banner  svc.Duration `json:"banner"`
	} `json:"timeouts"`
	HTTPPorts []uint16     `json:"http_ports"`
	UserAgent string       `json:"user_agent"`
	Reprobe   svc.Duration `json:"reprobe"`
	MinGap    svc.Duration `json:"min_gap"`
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	path := flag.String("config", "/etc/portwarden/verifier.json", "config file (JSON)")
	flag.Parse()
	if err := run(*path); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("portwarden-verifier", "err", err)
		os.Exit(1)
	}
}

func run(path string) error {
	var cfg Config
	if err := svc.Load(path, &cfg); err != nil {
		return err
	}
	scope, err := buildScope(cfg)
	if err != nil {
		return err
	}
	if cfg.Checker == "" {
		host, _ := os.Hostname()
		cfg.Checker = "portwarden-verifier@" + host
	}
	prober := verifier.NewProber()
	prober.Timeout = cfg.Timeouts.Connect.D(3 * time.Second)
	prober.BannerWait = cfg.Timeouts.Banner.D(2 * time.Second)
	if cfg.UserAgent != "" {
		prober.UserAgent = cfg.UserAgent
	}
	prober.HTTPPorts = map[uint16]bool{}
	for _, p := range cfg.HTTPPorts {
		prober.HTTPPorts[p] = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	nc, js, err := bus.Connect(cfg.NATS.Bus(natsauth.RoleVerifier, "portwarden-verifier"))
	if err != nil {
		return err
	}
	defer nc.Close()
	if _, err := svc.WaitStream(ctx, js); err != nil {
		return err
	}
	pub := bus.NewPublisher(js, "verifier")
	v := verifier.New(scope, prober.Probe, pub.Publish, pub.RunID, cfg.Checker, verifier.Limits{
		GlobalPerSecond: cfg.Rate.GlobalPerSecond, PerHostPerMinute: cfg.Rate.PerHostPerMinute, Concurrency: cfg.Rate.Concurrency,
		Reprobe: cfg.Reprobe.D(24 * time.Hour), MinGap: cfg.MinGap.D(30 * time.Second),
	})
	defer v.Wait()

	c, err := bus.Durable(ctx, js, natsauth.ConsumerVerifier, bus.DurableOptions{
		Filters:    []string{"asm.*." + bus.KindExposureChanged, "asm.*." + bus.KindSnapshot, "asm.*." + bus.KindClosed},
		DeliverNew: true,
	})
	if err != nil {
		return err
	}
	slog.Info("verifier running", "checker", cfg.Checker, "allow", cfg.AllowCIDRs, "limits", fmt.Sprintf("%+v", v.Limits))
	return svc.Consume(ctx, c, func(ctx context.Context, m jetstream.Msg) error {
		host, kind, ok := bus.ParseSubject(m.Subject())
		if !ok {
			return nil
		}
		switch kind {
		case bus.KindExposureChanged:
			var ev asmv1.ExposureEvent
			if proto.Unmarshal(m.Data(), &ev) == nil && (ev.GetHostId() == "" || ev.GetHostId() == host) {
				v.Exposure(ctx, host, &ev)
			}
		case bus.KindSnapshot:
			var s asmv1.Snapshot
			if proto.Unmarshal(m.Data(), &s) == nil && (s.GetHostId() == "" || s.GetHostId() == host) {
				v.Snapshot(ctx, host, &s)
			}
		case bus.KindClosed:
			var ev asmv1.ListenerEvent
			if proto.Unmarshal(m.Data(), &ev) == nil {
				v.Forget(host, ev.GetListener().GetKey())
			}
		}
		return nil
	})
}

func buildScope(cfg Config) (verifier.Scope, error) {
	var s verifier.Scope
	if len(cfg.AllowCIDRs) == 0 {
		return s, errors.New("allow_cidrs is empty: list the networks the checker may probe")
	}
	for _, c := range cfg.AllowCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return s, fmt.Errorf("allow_cidrs: %w", err)
		}
		s.Allow = append(s.Allow, p.Masked())
	}
	s.HostAddresses = map[string][]netip.Addr{}
	for host, addrs := range cfg.HostAddresses {
		for _, a := range addrs {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				return s, fmt.Errorf("host_addresses[%s]: %w", host, err)
			}
			s.HostAddresses[host] = append(s.HostAddresses[host], ip.Unmap())
		}
	}
	return s, nil
}
