// portwarden-alerter pages on newly reachable listeners (an agent exposure.changed or a
// cloud verdict reaching the page level from below), on the outside checker's
// transitions to confirmed, on host silence, and once when its own feed stalls. Every
// decision and its page are stored in PostgreSQL in one transaction before the NATS
// message is acked; an outbox worker delivers pages (one JSON line on stdout each, and a
// signed webhook POST) with retries across restarts. Run one instance. See README
// "Backend".
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
	"github.com/thapr0digy/portwarden/internal/alerter/pgstate"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
	"github.com/thapr0digy/portwarden/internal/backend/liveness"
	"github.com/thapr0digy/portwarden/internal/backend/svc"
	"github.com/thapr0digy/portwarden/internal/natsauth"
	"github.com/thapr0digy/portwarden/internal/version"
)

// Config is the JSON config file (--config).
type Config struct {
	NATS svc.NATS `json:"nats"`
	// PostgresDSNFile holds the state database's DSN; PORTWARDEN_ALERTER_DSN wins.
	PostgresDSNFile string `json:"postgres_dsn_file"`
	Rules           struct {
		PageLevel       string           `json:"page_level"`
		PageOnConfirmed *bool            `json:"page_on_confirmed"`
		PageOnSilence   *bool            `json:"page_on_silence"`
		PageOnTamper    *bool            `json:"page_on_tamper"`
		TamperIgnore    []string         `json:"tamper_ignore"`
		DedupeWindow    svc.Duration     `json:"dedupe_window"`
		SilentAfter     svc.Duration     `json:"silent_after"`
		Ignore          []alerter.Ignore `json:"ignore"`
	} `json:"rules"`
	Webhook struct {
		URL        string       `json:"url"`
		SecretFile string       `json:"secret_file"`
		Timeout    svc.Duration `json:"timeout"`
		// MaxAttempts per page, across restarts (default 20; backoff 1 s doubling to 5 min).
		MaxAttempts   int  `json:"max_attempts"`
		AllowInsecure bool `json:"allow_insecure"`
	} `json:"webhook"`
}

func main() {
	version.HandleFlag()
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
		PageOnSilence: orTrue(cfg.Rules.PageOnSilence), DedupeWindow: cfg.Rules.DedupeWindow.D(time.Hour), Ignore: cfg.Rules.Ignore,
		PageOnTamper: orTrue(cfg.Rules.PageOnTamper), TamperIgnore: cfg.Rules.TamperIgnore}
	if err := rules.Validate(); err != nil {
		return err
	}
	var hook *alerter.Webhook
	if cfg.Webhook.URL != "" {
		if err := alerter.CheckURL(cfg.Webhook.URL, cfg.Webhook.AllowInsecure); err != nil {
			return err
		}
		secret, err := svc.Secret("PORTWARDEN_ALERTER_WEBHOOK_SECRET", cfg.Webhook.SecretFile)
		if err != nil {
			return fmt.Errorf("webhook secret: %w", err)
		}
		hook = alerter.NewWebhook(cfg.Webhook.URL, []byte(secret), cfg.Webhook.Timeout.D(5*time.Second), 1)
	} else {
		slog.Warn("no webhook configured: alerts go to stdout only")
	}
	dsn, err := svc.Secret("PORTWARDEN_ALERTER_DSN", cfg.PostgresDSNFile)
	if err != nil {
		return fmt.Errorf("postgres dsn: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	store, err := pgstate.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer store.Close()

	silentAfter := cfg.Rules.SilentAfter.D(90 * time.Second)
	a := &app{engine: alerter.NewEngine(rules, bus.NewEventID), store: store, live: liveness.New(silentAfter),
		feed: liveness.NewFeed(silentAfter, time.Now()), hook: hook, maxAttempts: cfg.Webhook.MaxAttempts,
		tamperSig: map[string]string{}, noSilence: map[string]bool{}}
	if a.maxAttempts <= 0 {
		a.maxAttempts = 20
	}
	nc, js, err := bus.Connect(cfg.NATS.Bus(natsauth.RoleAlerter, "portwarden-alerter", a.connected))
	if err != nil {
		return err
	}
	defer nc.Close()
	stream, err := svc.WaitStream(ctx, js)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Go(func() { a.deliver(ctx) })
	wg.Go(func() { a.watch(ctx) })

	hb, err := heartbeatConsumer(ctx, js, stream, a)
	if err != nil {
		return err
	}
	wg.Go(func() {
		if err := svc.Consume(ctx, hb, a.heartbeat, svc.ConsumeOptions{}); err != nil && ctx.Err() == nil {
			slog.Error("heartbeat consumer stopped", "err", err)
			stop()
		}
	})
	ex, err := bus.Durable(ctx, js, natsauth.ConsumerAlerter, bus.DurableOptions{
		Filters:    []string{"asm.*." + bus.KindExposureChanged, "pwb.cloud.*." + bus.KindVerdict, "pwb.verifier.*." + bus.KindVerdict},
		DeliverNew: true, // a first start does not page for the stream's history
	})
	if err != nil {
		return err
	}
	slog.Info("alerter running", "page_level", rules.PageLevel, "dedupe_window", rules.DedupeWindow.String(),
		"silent_after", silentAfter.String(), "webhook", hook != nil)
	return svc.Consume(ctx, ex, a.exposure, svc.ConsumeOptions{})
}

// heartbeatConsumer re-creates the heartbeat consumer from each host's last heartbeat and
// last tamper event, so a host that died while the alerter was down is still noticed.
// Heartbeats and tamper events share it, so each host's tamper status is judged in the
// host's order. Messages up to the stream's last sequence at creation are a replay: they
// seed liveness and feed the tamper rule (whose marks make it idempotent), never a
// recovery page.
func heartbeatConsumer(ctx context.Context, js jetstream.JetStream, stream jetstream.Stream, a *app) (jetstream.Consumer, error) {
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, err
	}
	a.replayUpTo = info.State.LastSeq
	if err := js.DeleteConsumer(ctx, natsauth.StreamName, natsauth.ConsumerAlerterHB); err != nil && !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return nil, fmt.Errorf("reset heartbeat consumer: %w", err)
	}
	return js.CreateOrUpdateConsumer(ctx, natsauth.StreamName, jetstream.ConsumerConfig{
		Durable: natsauth.ConsumerAlerterHB, FilterSubjects: []string{"asm.*." + bus.KindHeartbeat, "asm.*." + bus.KindTamper},
		DeliverPolicy: jetstream.DeliverLastPerSubjectPolicy, AckPolicy: jetstream.AckExplicitPolicy, AckWait: 30 * time.Second,
	})
}

type app struct {
	engine      *alerter.Engine
	store       *pgstate.Store
	hook        *alerter.Webhook
	maxAttempts int
	replayUpTo  uint64

	mu   sync.Mutex // guards live, feed, tamperSig and noSilence (all on the alerter's own clock)
	live *liveness.Tracker
	feed *liveness.Feed
	// tamperSig is each host's last stored tamper signature; noSilence holds hosts with
	// no outstanding silence page. Both only save database round trips: a miss (after a
	// restart) falls back to the database.
	tamperSig map[string]string
	noSilence map[string]bool
}

func (a *app) connected(ok bool) {
	a.mu.Lock()
	a.feed.SetConnected(ok, time.Now())
	a.mu.Unlock()
}

func (a *app) decide(ctx context.Context, what string, f func(alerter.State) (alerter.Decision, error)) error {
	var d alerter.Decision
	if err := a.store.InTx(ctx, func(st alerter.State) error {
		var err error
		d, err = f(st)
		return err
	}); err != nil {
		return err
	}
	if d.Suppressed != "" {
		slog.Info("alert suppressed", "what", what, "rule", d.Suppressed)
	}
	if d.Alert != nil {
		slog.Info("alert queued", "id", d.Alert.ID, "kind", d.Alert.Kind, "host", d.Alert.Host, "summary", d.Alert.Summary)
	}
	return nil
}

func (a *app) heartbeat(ctx context.Context, m jetstream.Msg) error {
	host, kind, ok := bus.ParseSubject(m.Subject())
	if !ok {
		return nil
	}
	now := time.Now()
	replay := false
	if md, err := m.Metadata(); err == nil && md.Sequence.Stream <= a.replayUpTo {
		replay = true
	}
	status, err := tamperStatus(host, kind, m.Data())
	if err != nil {
		return svc.Permanent(err)
	}
	// Liveness is in memory and recorded first: a database outage must never look like
	// a stalled feed or a silent host (ruling R-h).
	if kind == bus.KindHeartbeat {
		a.mu.Lock()
		a.live.Seen(host, now, now)
		if !replay {
			a.feed.Received(now)
		}
		a.mu.Unlock()
	}
	if status != nil {
		sig := alerter.TamperSignature(status)
		a.mu.Lock()
		last, known := a.tamperSig[host]
		a.mu.Unlock()
		// The database is touched only when the host's pageable flags changed.
		if !known || last != sig {
			if err := a.decide(ctx, "tamper "+host, func(st alerter.State) (alerter.Decision, error) {
				return a.engine.Tamper(ctx, st, host, status, now)
			}); err != nil {
				return err
			}
			a.mu.Lock()
			a.tamperSig[host] = sig
			a.mu.Unlock()
		}
	}
	if kind != bus.KindHeartbeat || replay {
		return nil
	}
	a.mu.Lock()
	quiet := a.noSilence[host]
	a.mu.Unlock()
	if quiet {
		return nil // no silence page outstanding for this host: nothing to recover
	}
	if err := a.decide(ctx, "heartbeat "+host, func(st alerter.State) (alerter.Decision, error) {
		return a.engine.Heard(ctx, st, host, now)
	}); err != nil {
		return err
	}
	a.mu.Lock()
	a.noSilence[host] = true
	a.mu.Unlock()
	return nil
}

// tamperStatus decodes a heartbeat's or tamper event's tamper status (nil when the agent
// sends none). A body naming another host is forged.
func tamperStatus(host, kind string, data []byte) (*asmv1.TamperStatus, error) {
	var hostID string
	var status *asmv1.TamperStatus
	switch kind {
	case bus.KindHeartbeat:
		var hb asmv1.Heartbeat
		if err := proto.Unmarshal(data, &hb); err != nil {
			return nil, err
		}
		hostID, status = hb.GetHostId(), hb.GetTamper()
	case bus.KindTamper:
		var ev asmv1.TamperEvent
		if err := proto.Unmarshal(data, &ev); err != nil {
			return nil, err
		}
		hostID, status = ev.GetHostId(), ev.GetStatus()
		if status == nil {
			status = &asmv1.TamperStatus{}
		}
	default:
		return nil, nil
	}
	if hostID != "" && hostID != host {
		return nil, fmt.Errorf("forged %s (host %q on %s's subject)", kind, hostID, host)
	}
	return status, nil
}

// watch checks the feed and host silence every 5 s.
func (a *app) watch(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-prune.C:
			if err := a.store.Prune(ctx, time.Now(), a.engine.DedupeWindow()); err != nil {
				slog.Warn("prune", "err", err)
			}
		case now := <-t.C:
			a.mu.Lock()
			ev, judge := a.feed.Check(now)
			var silent []liveness.Transition
			if judge {
				silent = a.live.Check(now)
			}
			a.mu.Unlock()
			if ev != liveness.FeedNoChange {
				a.retry(ctx, "feed", func(st alerter.State) (alerter.Decision, error) { return a.engine.Feed(ctx, st, ev, now) })
			}
			for _, tr := range silent {
				a.retry(ctx, "host silent "+tr.Host, func(st alerter.State) (alerter.Decision, error) { return a.engine.Silent(ctx, st, tr) })
				// After the mark is stored: the host's next heartbeat checks it (and pages
				// the recovery).
				a.mu.Lock()
				delete(a.noSilence, tr.Host)
				a.mu.Unlock()
			}
		}
	}
}

// retry stores a decision that has no NATS message to fall back on, until it succeeds.
func (a *app) retry(ctx context.Context, what string, f func(alerter.State) (alerter.Decision, error)) {
	for backoff := time.Second; ; backoff = min(backoff*2, 30*time.Second) {
		err := a.decide(ctx, what, f)
		if err == nil || ctx.Err() != nil {
			return
		}
		slog.Warn("storing a decision failed; retrying", "what", what, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (a *app) exposure(ctx context.Context, m jetstream.Msg) error {
	p, ok := bus.Parse(m.Subject())
	if !ok {
		return nil
	}
	now := time.Now()
	switch {
	case p.Origin == bus.OriginAgent && p.Kind == bus.KindExposureChanged, p.Origin == bus.OriginCloud:
		var ev asmv1.ExposureEvent
		if err := proto.Unmarshal(m.Data(), &ev); err != nil {
			return svc.Permanent(err)
		}
		if (ev.GetHostId() != "" && ev.GetHostId() != p.Host) || (p.Origin == bus.OriginAgent && ev.GetOrigin() != "") {
			return svc.Permanent(errors.New("forged exposure event (host or origin)"))
		}
		return a.decide(ctx, "exposure "+ev.GetListener().GetKey(), func(st alerter.State) (alerter.Decision, error) {
			return a.engine.Exposure(ctx, st, p.Host, p.Origin, &ev, now)
		})
	case p.Origin == bus.OriginVerifier:
		var ev asmv1.ExposureConfirmation
		if err := proto.Unmarshal(m.Data(), &ev); err != nil {
			return svc.Permanent(err)
		}
		if ev.GetHostId() != "" && ev.GetHostId() != p.Host {
			return svc.Permanent(errors.New("forged confirmation (host)"))
		}
		return a.decide(ctx, "confirmation "+ev.GetListener().GetKey(), func(st alerter.State) (alerter.Decision, error) {
			return a.engine.Confirmation(ctx, st, p.Host, &ev, now)
		})
	}
	return nil
}

// deliver sends due pages from the outbox: one JSON line on stdout per page, then the
// webhook with retries (backoff 1 s doubling to 5 min, at most maxAttempts, across
// restarts); a permanent webhook error gives up at once.
func (a *app) deliver(ctx context.Context) {
	enc := json.NewEncoder(os.Stdout)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	printed := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		due, err := a.store.Due(ctx, time.Now(), 50)
		if err != nil {
			slog.Warn("outbox read failed", "err", err)
			continue
		}
		for _, p := range due {
			if !printed[p.ID] {
				_ = enc.Encode(p.Alert)
				printed[p.ID] = true
			}
			if a.hook == nil {
				_ = a.store.Delivered(ctx, p.ID, time.Now())
				continue
			}
			permanent, err := a.hook.SendOnce(ctx, &p.Alert)
			if err == nil {
				slog.Info("alert delivered", "id", p.ID)
				if derr := a.store.Delivered(ctx, p.ID, time.Now()); derr != nil {
					slog.Warn("marking a page delivered failed (it may be sent again)", "id", p.ID, "err", derr)
				}
				delete(printed, p.ID)
				continue
			}
			giveUp := permanent || p.Attempts+1 >= a.maxAttempts
			backoff := min(time.Second<<min(p.Attempts, 10), 5*time.Minute)
			if giveUp {
				slog.Error("alert not delivered; giving up", "id", p.ID, "attempts", p.Attempts+1, "err", err)
			} else {
				slog.Warn("webhook delivery failed; will retry", "id", p.ID, "attempt", p.Attempts+1, "err", err, "in", backoff)
			}
			if ferr := a.store.Failed(ctx, p.ID, time.Now().Add(backoff), giveUp, err.Error()); ferr != nil {
				slog.Warn("outbox update failed", "err", ferr)
			}
		}
	}
}
