//go:build linux

package main

import (
	"log/slog"

	"github.com/thapr0digy/portwarden/internal/tamper"
)

// hardenProcess marks the agent not dumpable before any secret is in its memory, then
// checks that its own /proc reads still work. Neither failure stops the agent: losing the
// hardening must not lose the inventory. A failed prctl is returned for the dumpable
// tamper check, which reports it as unknown on every pass; a failed self-read is logged
// here and reported by the check that owns it.
func hardenProcess(log *slog.Logger) error {
	err := tamper.Harden()
	if err != nil {
		log.Warn("hardening: prctl PR_SET_DUMPABLE 0 failed; the agent stays dumpable", "error", err.Error())
	}
	failed := tamper.SelfReadProbe()
	for _, e := range failed {
		log.Warn("hardening: self-read failed", "error", e.Error())
	}
	if err == nil && len(failed) == 0 {
		log.Info("hardening: not dumpable; self-reads ok")
	}
	return err
}
