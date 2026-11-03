package exposure

import (
	"context"
	"log/slog"
	"time"

	"github.com/thapr0digy/portwarden/internal/netif"
)

// WatchConfig tunes a Watcher.
type WatchConfig struct {
	Config
	// Debounce is how long the watcher waits after a change notification before it reads
	// again, so a burst (iptables-restore, an interface coming up) is read once.
	Debounce time.Duration
	// MaxWait bounds the wait from the first notification of a burst: a steady stream
	// of notifications (a busy ban list, a resyncing kube-proxy) still gets a read.
	MaxWait time.Duration
	// Poll is how often the firewall is re-read when change notifications are not
	// available (the notification socket failed, or an iptables-legacy ruleset is in
	// use, which sends none). A new view is sent only when something changed.
	Poll time.Duration
	// Recheck is how often a new view is built and sent even if nothing seems to have
	// changed (it also refreshes container addresses). 0 disables it.
	Recheck time.Duration
	// FirewallChanges and InterfaceChanges subscribe to change notifications
	// (netif.WatchNftables, netif.WatchAddresses).
	FirewallChanges  func(context.Context) (<-chan struct{}, error)
	InterfaceChanges func(context.Context) (<-chan struct{}, error)
}

// Triggers a view can carry.
const (
	TriggerStart      = "start"
	TriggerFirewall   = "firewall"
	TriggerInterfaces = "interfaces"
	TriggerRecheck    = "recheck"
)

// Watcher rebuilds the view when the firewall or the interfaces change.
type Watcher struct {
	cfg        WatchConfig
	subscribed bool
	fwC, ifC   <-chan struct{}
	fwErr      error
	ifErr      error
}

// NewWatcher returns a watcher; Initial and Run do the work.
func NewWatcher(cfg WatchConfig) *Watcher { return &Watcher{cfg: cfg} }

// Initial joins the change notifications, then builds the first view synchronously
// (each tool read is bounded), so a change made during or right after the read is not
// missed. ctx must be the one Run will get.
func (w *Watcher) Initial(ctx context.Context) *View {
	w.subscribe(ctx)
	v := Build(ctx, w.cfg.Config, TriggerStart)
	logView(v)
	return v
}

func (w *Watcher) subscribe(ctx context.Context) {
	if w.subscribed {
		return
	}
	w.subscribed = true
	w.fwC, w.fwErr = w.cfg.FirewallChanges(ctx)
	w.ifC, w.ifErr = w.cfg.InterfaceChanges(ctx)
}

// Run watches until ctx ends, calling publish with each new view.
func (w *Watcher) Run(ctx context.Context, last *View, publish func(*View)) {
	w.subscribe(ctx)
	fwC, fwNotify := w.fwC, w.fwErr == nil
	if w.fwErr != nil {
		slog.Warn("no firewall change notifications; polling", "error", w.fwErr.Error(), "every", w.cfg.Poll.String())
	}
	ifC, ifNotify := w.ifC, w.ifErr == nil
	if w.ifErr != nil {
		slog.Warn("no interface change notifications; polling", "error", w.ifErr.Error(), "every", w.cfg.Poll.String())
	}

	poll := time.NewTicker(time.Hour)
	poll.Stop()
	polling := false
	setPolling := func(v *View) {
		want := !fwNotify || !ifNotify || (v.fw != nil && v.fw.Legacy)
		if want == polling || w.cfg.Poll <= 0 {
			return
		}
		polling = want
		if want {
			poll.Reset(w.cfg.Poll)
		} else {
			poll.Stop()
		}
	}
	setPolling(last)
	defer poll.Stop()

	var recheckC <-chan time.Time
	if w.cfg.Recheck > 0 {
		t := time.NewTicker(w.cfg.Recheck)
		defer t.Stop()
		recheckC = t.C
	}
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	defer debounce.Stop()
	// pendingSince is when the first notification of the current burst arrived.
	var pendingSince time.Time
	arm := func() {
		now := time.Now()
		if pendingSince.IsZero() {
			pendingSince = now
		}
		wait := w.cfg.Debounce
		if w.cfg.MaxWait > 0 {
			wait = min(wait, max(pendingSince.Add(w.cfg.MaxWait).Sub(now), 0))
		}
		debounce.Reset(wait)
	}

	rebuild := func(force bool) {
		v := Build(ctx, w.cfg.Config, TriggerRecheck)
		if ctx.Err() != nil {
			return
		}
		trigger := changed(last, v)
		switch {
		case trigger != "":
			v.trigger = trigger
		case !force:
			return
		}
		logView(v)
		last = v
		setPolling(v)
		publish(v)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-fwC:
			if !ok {
				fwC, fwNotify = nil, false
				setPolling(last)
				continue
			}
			arm()
		case _, ok := <-ifC:
			if !ok {
				ifC, ifNotify = nil, false
				setPolling(last)
				continue
			}
			arm()
		case <-debounce.C:
			pendingSince = time.Time{}
			rebuild(false)
		case <-poll.C:
			rebuild(false)
		case <-recheckC:
			rebuild(true)
		}
	}
}

// changed names what differs between two views: firewall (rules, or whether they
// could be read) before interfaces; "" when nothing did.
func changed(old, cur *View) string {
	if fwPrint(old) != fwPrint(cur) {
		return TriggerFirewall
	}
	if ifPrint(old) != ifPrint(cur) {
		return TriggerInterfaces
	}
	return ""
}

func fwPrint(v *View) string {
	if v.fw == nil {
		return "error: " + errText(v.fwErr)
	}
	return v.fw.Fingerprint
}

func ifPrint(v *View) string {
	if v.ifErr != nil {
		return "error: " + v.ifErr.Error()
	}
	return netif.Fingerprint(v.ifs)
}

func logView(v *View) {
	if v.fw == nil {
		slog.Warn("firewall unreadable; exposure stays at bound or below", "trigger", v.trigger, "error", errText(v.fwErr))
		return
	}
	attrs := []any{"trigger", v.trigger, "sources", v.fw.Sources, "chains", len(v.fw.Rules.Chains), "nat_mappings", len(v.natMaps)}
	if len(v.fw.Notes) > 0 {
		attrs = append(attrs, "notes", v.fw.Notes)
	}
	slog.Info("firewall read", attrs...)
}
