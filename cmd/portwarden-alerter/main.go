// portwarden-alerter pages on newly reachable listeners (exposure.changed reaching the
// page level from below, from the agent or the cloud look-up), on the outside checker's
// confirmations, and on host silence. Each alert is written as one JSON line to stdout
// and, when a webhook is configured, POSTed with an HMAC signature. See README "Backend".
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/alerter"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/natsauth"
)

// Config is the JSON config file (--config).
type Config struct {
	NATS  svc.NATS `json:"nats"`
	Rules struct {
		PageLevel       string           `json:"page_level"`
		PageOnConfirmed *bool            `json:"page_on_confirmed"`
		PageOnSilence   *bool            `json:"page_on_silence"`
		DedupeWindow    svc.Duration     `json:"dedupe_window"`
		SilentAfter     svc.Duration     `json:"silent_after"`
		Ignore          []alerter.Ignore `json:"ignore"`
	} `json:"rules"`
	Webhook struct {
		URL         string       `json:"url"`
		SecretFile  string       `json:"secret_file"`
		Timeout     svc.Duration `json:"timeout"`
		MaxAttempts int          `json:"max_attempts"`
	} `json:"webhook"`
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	path := flag.String("config", "/etc/portwarden/alerter.json", "config file (JSON)")
	flag.Parse()
	if err := run(*path); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("portwarden-alerter", "err", err)
		os.Exit(1)
	}
}

func orTrue(b *bool) bool { return b == nil || *b }

func run(path string) error {
	var cfg Config
	if err := svc.Load(path, &cfg); err != nil {
		return err
	}
	rules := alerter.Rules{PageLevel: cfg.Rules.PageLevel, PageOnConfirmed: orTrue(cfg.Rules.PageOnConfirmed),
		PageOnSilence: orTrue(cfg.Rules.PageOnSilence), DedupeWindow: cfg.Rules.DedupeWindow.D(time.Hour), Ignore: cfg.Rules.Ignore}
	if err := rules.Validate(); err != nil {
		return err
	}
	var hook *alerter.Webhook
	if cfg.Webhook.URL != "" {
		secret, err := svc.Secret("PORTWARDEN_ALERTER_WEBHOOK_SECRET", cfg.Webhook.SecretFile)
		if err != nil {
			return fmt.Errorf("webhook secret: %w", err)
		}
		hook = alerter.NewWebhook(cfg.Webhook.URL, []byte(secret), cfg.Webhook.Timeout.D(5*time.Second), cfg.Webhook.MaxAttempts)
	} else {
		slog.Warn("no webhook configured: alerts go to stdout only")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	nc, js, err := bus.Connect(cfg.NATS.Bus(natsauth.RoleAlerter, "portwarden-alerter"))
	if err != nil {
		return err
	}
	defer nc.Close()
	if _, err := svc.WaitStream(ctx, js); err != nil {
		return err
	}

	a := &app{engine: alerter.NewEngine(rules, bus.NewEventID), live: liveness.New(cfg.Rules.SilentAfter.D(90 * time.Second)),
		out: make(chan *alerter.Alert, 1000), hook: hook}
	go a.deliver(ctx)
	go a.watchSilence(ctx)

	hb, err := heartbeatConsumer(ctx, js)
	if err != nil {
		return err
	}
	go func() {
		if err := svc.Consume(ctx, hb, a.heartbeat); err != nil && ctx.Err() == nil {
			slog.Error("heartbeat consumer stopped", "err", err)
			stop()
		}
	}()
	ex, err := bus.Durable(ctx, js, natsauth.ConsumerAlerter, bus.DurableOptions{
		Filters:    []string{"asm.*." + bus.KindExposureChanged, "asm.*." + bus.KindExposureConfirmed},
		DeliverNew: true, // a first start does not page for the stream's history
	})
	if err != nil {
		return err
	}
	slog.Info("alerter running", "page_level", rules.PageLevel, "dedupe_window", rules.DedupeWindow.String(),
		"silent_after", a.live.After.String(), "webhook", hook != nil)
	return svc.Consume(ctx, ex, a.exposure)
}

// heartbeatConsumer re-creates the heartbeat consumer from each host's last heartbeat,
// so a host that went silent while the alerter was down is still noticed.
func heartbeatConsumer(ctx context.Context, js jetstream.JetStream) (jetstream.Consumer, error) {
	if err := js.DeleteConsumer(ctx, natsauth.StreamName, natsauth.ConsumerAlerterHB); err != nil && !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return nil, fmt.Errorf("reset heartbeat consumer: %w", err)
	}
	return js.CreateOrUpdateConsumer(ctx, natsauth.StreamName, jetstream.ConsumerConfig{
		Durable: natsauth.ConsumerAlerterHB, FilterSubject: "asm.*." + bus.KindHeartbeat,
		DeliverPolicy: jetstream.DeliverLastPerSubjectPolicy, AckPolicy: jetstream.AckExplicitPolicy, AckWait: 30 * time.Second,
	})
}

type app struct {
	mu     sync.Mutex // guards engine and live
	engine *alerter.Engine
	live   *liveness.Tracker
	out    chan *alerter.Alert
	hook   *alerter.Webhook
}

func (a *app) heartbeat(_ context.Context, m jetstream.Msg) error {
	host, _, ok := bus.ParseSubject(m.Subject())
	if !ok {
		return nil
	}
	md, err := m.Metadata()
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if t := a.live.Seen(host, md.Timestamp, time.Now()); t != nil {
		a.decide(a.engine.Liveness(*t), "host recovered")
	}
	return nil
}

func (a *app) watchSilence(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.mu.Lock()
			for _, tr := range a.live.Check(now) {
				a.decide(a.engine.Liveness(tr), "host silent")
			}
			a.engine.Expire(now)
			a.mu.Unlock()
		}
	}
}

func (a *app) exposure(_ context.Context, m jetstream.Msg) error {
	host, kind, ok := bus.ParseSubject(m.Subject())
	if !ok {
		return nil
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	switch kind {
	case bus.KindExposureChanged:
		var ev asmv1.ExposureEvent
		if err := proto.Unmarshal(m.Data(), &ev); err != nil || (ev.GetHostId() != "" && ev.GetHostId() != host) {
			slog.Warn("skipping bad exposure event", "subject", m.Subject(), "err", err)
			return nil
		}
		a.decide(a.engine.Exposure(host, &ev, now), "exposure "+ev.GetListener().GetKey())
	case bus.KindExposureConfirmed:
		var ev asmv1.ExposureConfirmation
		if err := proto.Unmarshal(m.Data(), &ev); err != nil || (ev.GetHostId() != "" && ev.GetHostId() != host) {
			slog.Warn("skipping bad confirmation", "subject", m.Subject(), "err", err)
			return nil
		}
		a.decide(a.engine.Confirmation(host, &ev, now), "confirmation "+ev.GetListener().GetKey())
	}
	return nil
}

// decide queues an alert (never blocking the consumer: a full queue drops it, logged).
func (a *app) decide(d alerter.Decision, what string) {
	if d.Suppressed != "" {
		slog.Info("alert suppressed", "what", what, "rule", d.Suppressed)
	}
	if d.Alert == nil {
		return
	}
	select {
	case a.out <- d.Alert:
	default:
		slog.Error("alert queue full; alert dropped", "alert", d.Alert.ID, "summary", d.Alert.Summary)
	}
}

func (a *app) deliver(ctx context.Context) {
	enc := json.NewEncoder(os.Stdout)
	for {
		select {
		case <-ctx.Done():
			return
		case al := <-a.out:
			if err := enc.Encode(al); err != nil {
				slog.Warn("stdout", "err", err)
			}
			slog.Info("alert", "id", al.ID, "kind", al.Kind, "host", al.Host, "summary", al.Summary)
			if a.hook == nil {
				continue
			}
			if err := a.hook.Send(ctx, al); err != nil {
				slog.Error("alert not delivered to the webhook", "id", al.ID, "err", err)
			} else {
				slog.Info("alert delivered", "id", al.ID)
			}
		}
	}
}
