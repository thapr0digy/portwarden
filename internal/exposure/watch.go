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
	cfg WatchConfig
}

// NewWatcher returns a watcher; Initial and Run do the work.
func NewWatcher(cfg WatchConfig) *Watcher { return &Watcher{cfg: cfg} }

// Initial builds the first view, synchronously (each tool read is bounded).
func (w *Watcher) Initial(ctx context.Context) *View {
	v := Build(ctx, w.cfg.Config, TriggerStart)
	logView(v)
	return v
}

// Run watches until ctx ends, calling publish with each new view.
func (w *Watcher) Run(ctx context.Context, last *View, publish func(*View)) {
	fwC, err := w.cfg.FirewallChanges(ctx)
	fwNotify := err == nil
	if err != nil {
		slog.Warn("no firewall change notifications; polling", "error", err.Error(), "every", w.cfg.Poll.String())
	}
	ifC, err := w.cfg.InterfaceChanges(ctx)
	ifNotify := err == nil
	if err != nil {
		slog.Warn("no interface change notifications; polling", "error", err.Error(), "every", w.cfg.Poll.String())
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
			debounce.Reset(w.cfg.Debounce)
		case _, ok := <-ifC:
			if !ok {
				ifC, ifNotify = nil, false
				setPolling(last)
				continue
			}
			debounce.Reset(w.cfg.Debounce)
		case <-debounce.C:
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
