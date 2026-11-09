// portwarden-verifier is the outside checker: run it on a machine outside the servers'
// networks (fixed source addresses with a clear reverse DNS name, design §9). It probes
// what the inventory requests (pwb.probe.<host>.request, built from stored state), on
// addresses inside its allowlist (non-public ones only when listed for the host), and
// publishes pwb.verifier.<host>.exposure. See README "Backend".
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
	"github.com/thapr0digy/portwarden/internal/version"
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
		Queue            int     `json:"queue"`
	} `json:"rate"`
	Timeouts struct {
		Connect svc.Duration `json:"connect"`
		Banner  svc.Duration `json:"banner"`
	} `json:"timeouts"`
	HTTPPorts []uint16     `json:"http_ports"`
	UserAgent string       `json:"user_agent"`
	MinGap    svc.Duration `json:"min_gap"`
}

func main() {
	version.HandleFlag()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	path := flag.String("config", "/etc/portwarden/verifier.json", "config file (JSON)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	err := run(ctx, *path)
	stop()
	os.Exit(exitCode(err))
}

// exitCode is the process's exit status for run's result: 0 for a clean stop (nil, or the
// signal's context.Canceled), else 1 after logging the error.
func exitCode(err error) int {
	if err == nil || errors.Is(err, context.Canceled) {
		return 0
	}
	slog.Error("portwarden-verifier", "err", err)
	return 1
}

// settings is the config after loading and checking, ready for wiring.
type settings struct {
	cfg    Config
	scope  verifier.Scope
	prober *verifier.Prober
}

// load reads and checks the config: everything before the first connection.
func load(path string) (settings, error) {
	var cfg Config
	if err := svc.Load(path, &cfg); err != nil {
		return settings{}, err
	}
	scope, err := buildScope(cfg)
	if err != nil {
		return settings{}, err
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
	return settings{cfg: cfg, scope: scope, prober: prober}, nil
}

// run loads the config, connects and probes what the inventory requests until ctx ends
// (then it returns ctx's error).
func run(ctx context.Context, path string) error {
	st, err := load(path)
	if err != nil {
		return err
	}
	cfg := st.cfg
	nc, js, err := bus.Connect(cfg.NATS.Bus(natsauth.RoleVerifier, "portwarden-verifier", nil))
	if err != nil {
		return err
	}
	defer nc.Close()
	if _, err := svc.WaitStream(ctx, js); err != nil {
		return err
	}
	pub := bus.NewPublisher(js, "verifier")
	v := verifier.New(st.scope, st.prober.Probe, pub.Publish, pub.RunID, cfg.Checker, verifier.Limits{
		GlobalPerSecond: cfg.Rate.GlobalPerSecond, PerHostPerMinute: cfg.Rate.PerHostPerMinute, Concurrency: cfg.Rate.Concurrency,
		Queue: cfg.Rate.Queue, MinGap: cfg.MinGap.D(30 * time.Second),
	})
	wait := v.Start(ctx)
	defer wait()

	c, err := bus.Durable(ctx, js, natsauth.ConsumerVerifier, bus.DurableOptions{
		Filters:    []string{"pwb.probe.*." + bus.KindProbeRequest},
		DeliverNew: true,
	})
	if err != nil {
		return err
	}
	slog.Info("verifier running", "checker", cfg.Checker, "allow", cfg.AllowCIDRs, "limits", fmt.Sprintf("%+v", v.Limits))
	return svc.Consume(ctx, c, handleRequest(v), svc.ConsumeOptions{})
}

// handleRequest checks a probe request against its subject and hands it to the verifier.
func handleRequest(v *verifier.Verifier) svc.Handler {
	return func(_ context.Context, m jetstream.Msg) error {
		p, ok := bus.Parse(m.Subject())
		if !ok || p.Origin != bus.OriginProbe {
			return nil
		}
		var r asmv1.ProbeRequest
		if err := proto.Unmarshal(m.Data(), &r); err != nil {
			return svc.Permanent(err)
		}
		if r.GetHostId() != "" && r.GetHostId() != p.Host {
			return svc.Permanent(fmt.Errorf("request host_id %q differs from the subject's", r.GetHostId()))
		}
		v.Request(p.Host, &r)
		return nil
	}
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
