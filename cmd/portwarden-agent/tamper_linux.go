//go:build linux

package main

import (
	"context"
	"log/slog"
	"maps"
	"time"

	"github.com/thapr0digy/portwarden/internal/probes"
	"github.com/thapr0digy/portwarden/internal/publish"
	"github.com/thapr0digy/portwarden/internal/tamper"
)

// newTamperMonitor builds the agent's self-checks (design §9): its links, ptrace, its
// executable, its systemd unit files, extra files, the ring buffer's drop counter, and
// that it is still not dumpable (hardenErr is why clearing that at start failed, if it did).
// A check whose baseline cannot be taken yet is retried every pass (reported unknown
// meanwhile), never dropped. extra (--tamper-files) may be nil.
// self is the executable path and hash taken at start (selfIdentity); when the hash is
// empty the check takes its own baseline, retrying every pass.
func newTamperMonitor(self exeIdentity, extra *tamper.FileSet, dropRate float64, pr *probes.Probes, proxyConns *probes.ProxyConns, hardenErr error, log *slog.Logger) *tamper.Monitor {
	checks := []tamper.Check{tamper.NewAttachments("probes", pr.Attachments)}
	if proxyConns != nil {
		checks = append(checks, tamper.NewAttachments("proxy_probes", proxyConns.Attachments))
	}
	checks = append(checks, tamper.SelfTracer(), tamper.SelfDumpable(hardenErr))
	// The package upgrade replaces the executable and unit file; dpkg's records tell
	// that apart from tampering (ruling R-b).
	pkgs := tamper.NewDpkg("portwarden-agent")
	checks = append(checks, &tamper.Lazy{CheckName: "self_exe", Init: func() (tamper.Check, error) {
		if self.hash != "" {
			exe := tamper.NewSelfExe(self.path, self.hash)
			exe.Packages = pkgs
			return exe, nil
		}
		exe, err := tamper.SelfExeCheck()
		if err != nil {
			return nil, err
		}
		exe.Packages = pkgs
		return exe, nil
	}})
	// Early in boot the system bus is not up yet: the unit check retries every pass and
	// reports unknown until it can take its baseline (ruling R-d).
	checks = append(checks, &tamper.Lazy{CheckName: "unit", Init: func() (tamper.Check, error) {
		unit, list, err := tamper.UnitFiles()
		if err != nil {
			return nil, err
		}
		set, err := tamper.NewFileSet("unit", tamper.KindUnitChanged, list)
		if err != nil {
			return nil, err
		}
		set.Packages = pkgs
		log.Info("tamper: watching unit files", "unit", unit, "files", set.Files())
		return set, nil
	}})
	if extra != nil {
		checks = append(checks, extra)
	}
	drops := tamper.NewCounter("ringbuf_drops", func() (uint64, error) { return pr.Counters(), nil })
	drops.PageRate = dropRate
	checks = append(checks, drops)

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
				if f.Info {
					log.Info("tamper information", "kind", f.Kind, "subject", f.Subject, "detail", f.Detail)
					continue
				}
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
