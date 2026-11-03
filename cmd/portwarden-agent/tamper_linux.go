//go:build linux

package main

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"time"

	"github.com/thapr0digy/portwarden/internal/probes"
	"github.com/thapr0digy/portwarden/internal/publish"
	"github.com/thapr0digy/portwarden/internal/tamper"
)

// newTamperMonitor builds the agent's self-checks (design §9): its links, ptrace, its
// executable, its systemd unit files, extra files, and the ring buffer's drop counter.
// A check whose baseline cannot be read at start (no systemd unit, say) is left out
// with a log line. extra (--tamper-files) may be nil.
func newTamperMonitor(extra *tamper.FileSet, pr *probes.Probes, proxyConns *probes.ProxyConns, log *slog.Logger) *tamper.Monitor {
	checks := []tamper.Check{tamper.NewAttachments("probes", pr.Attachments)}
	if proxyConns != nil {
		checks = append(checks, tamper.NewAttachments("proxy_probes", proxyConns.Attachments))
	}
	checks = append(checks, tamper.SelfTracer())
	if exe, err := tamper.SelfExeCheck(); err != nil {
		log.Warn("tamper: executable check off", "err", err.Error())
	} else {
		checks = append(checks, exe)
	}
	if unit, list, err := tamper.UnitFiles(); err != nil {
		level := slog.LevelWarn
		if errors.Is(err, tamper.ErrNoUnit) {
			level = slog.LevelInfo
		}
		log.Log(context.Background(), level, "tamper: unit file check off", "err", err.Error())
	} else if set, err := tamper.NewFileSet("unit", tamper.KindUnitChanged, list); err != nil {
		log.Warn("tamper: unit file check off", "unit", unit, "err", err.Error())
	} else {
		log.Info("tamper: watching unit files", "unit", unit, "files", set.Files())
		checks = append(checks, set)
	}
	if extra != nil {
		checks = append(checks, extra)
	}
	checks = append(checks, tamper.NewCounter("ringbuf_drops", func() (uint64, error) { return pr.Counters(), nil }))

	mon := tamper.NewMonitor(checks...)
	mon.Stats = func(st *tamper.Status) {
		st.RingbufDrops = pr.Counters()
		if !tamper.BPFStatsEnabled() {
			return
		}
		counts, err := pr.RunCounts()
		if err != nil {
			return
		}
		if proxyConns != nil {
			if more, err := proxyConns.RunCounts(); err == nil {
				maps.Copy(counts, more)
			}
		}
		st.RunCounts = counts
	}
	return mon
}

// tamperLoop runs a pass at once and then every interval: the status goes on later
// heartbeats, and a pass that raised or cleared a flag is published on asm.<host>.tamper.
func tamperLoop(ctx context.Context, every time.Duration, mon *tamper.Monitor, pub *publish.Publisher, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		tr := mon.Pass(time.Now())
		pub.SetTamper(tr.Status)
		if tr.Changed() {
			pub.Tamper(tr)
			for _, f := range tr.Raised {
				log.Warn("tamper signal raised", "kind", f.Kind, "subject", f.Subject, "detail", f.Detail)
			}
			for _, f := range tr.Cleared {
				log.Info("tamper signal cleared", "kind", f.Kind, "subject", f.Subject)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
