package dpkg

import (
	"context"
	"io/fs"
	"log/slog"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
)

const (
	// DefaultPoll is how often the status file is looked at (a stat) for a change.
	DefaultPoll = 10 * time.Second
	// DefaultSettle is how long the status file must stay unchanged before it is read: dpkg
	// rewrites it many times during one apt run, and the list sent is the one it leaves.
	DefaultSettle = 30 * time.Second
	// DefaultRecheck is how often the list is read and reported whatever it is (daily).
	DefaultRecheck = 24 * time.Hour
)

// Sink takes the package list (the publisher). It must not block.
type Sink interface {
	// HostPackages is called at start, after a settled change and at each recheck.
	HostPackages(*eventsv1.HostPackages)
}

// Config configures Run.
type Config struct {
	// Root is the host's file system ("/").
	Root fs.FS
	// Poll, Settle and Recheck pace the reads (see the defaults); Poll or Recheck 0 never
	// polls or rechecks.
	Poll, Settle, Recheck time.Duration
	Log                   *slog.Logger
}

// stamp is what a stat of the status file shows; a different stamp is a change. dpkg
// replaces the file (status-new renamed over it), so its time changes with every write.
type stamp struct {
	size    int64
	modTime time.Time
	missing bool
}

func statStatus(root fs.FS) stamp {
	fi, err := fs.Stat(root, fsPath(StatusFile))
	if err != nil {
		return stamp{missing: true}
	}
	return stamp{size: fi.Size(), modTime: fi.ModTime()}
}

// Run reports the host's package list to sink until ctx ends: at start, once the status
// file has changed and then stayed unchanged for Settle, and every Recheck.
func Run(ctx context.Context, cfg Config, sink Sink) {
	last := statStatus(cfg.Root)
	report(cfg, sink, "start")
	poll, stopPoll := ticker(cfg.Poll)
	defer stopPoll()
	recheck, stopRecheck := ticker(cfg.Recheck)
	defer stopRecheck()
	var changedAt time.Time // when the stamp last moved; zero when it matches the last read
	seen := last
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-poll:
			s := statStatus(cfg.Root)
			if s != seen {
				seen, changedAt = s, now
			}
			if !changedAt.IsZero() && now.Sub(changedAt) >= cfg.Settle {
				changedAt = time.Time{}
				if seen != last {
					last = seen
					report(cfg, sink, "dpkg_changed")
				}
			}
		case <-recheck:
			last = statStatus(cfg.Root)
			report(cfg, sink, "recheck")
		}
	}
}

// ticker ticks every d; for d <= 0 it never ticks.
func ticker(d time.Duration) (<-chan time.Time, func()) {
	if d <= 0 {
		return nil, func() {}
	}
	t := time.NewTicker(d)
	return t.C, t.Stop
}

func report(cfg Config, sink Sink, trigger string) {
	list, skipped := ReadPackages(cfg.Root)
	switch {
	case !list.GetRead():
		cfg.Log.Warn("the package list cannot be read; Signal is told it cannot tell", "trigger", trigger, "error", list.GetUnreadable())
	case skipped > 0 || list.GetTruncated():
		cfg.Log.Warn("packages left out of the list", "trigger", trigger, "total", list.GetTotal(),
			"sent", len(list.GetPackages()), "outside_signals_forms", skipped, "truncated", list.GetTruncated())
	default:
		cfg.Log.Debug("package list read", "trigger", trigger, "packages", len(list.GetPackages()), "digest", list.GetDigest())
	}
	sink.HostPackages(list)
}
