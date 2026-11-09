package alerter

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// KindAgentRestartedUnclean is an informational alert: a host's agent started a new run
// although its previous run sent no clean-shutdown marker (a crash, a kill, a power loss,
// or a binary replaced and restarted).
const KindAgentRestartedUnclean = "agent_restarted_unclean"

// SeverityInfo marks an alert that is informational, not a page.
const SeverityInfo = "info"

// Run is the alerter's record of a host's current agent run.
type Run struct {
	ID     string
	BootID string
	Number uint64
	// Version is the agent version the run reported (cleaned); Identity is whether it
	// reported one: only a release that reports its version sends the clean-shutdown
	// marker, so only then does a missing marker mean an unclean stop.
	Version  string
	Identity bool
	// CleanStop is set by the run's clean-shutdown marker.
	CleanStop bool
}

// RunSeen is what one agent message (a heartbeat, or a host.changed stop marker) says
// about the run it came from.
type RunSeen struct {
	RunID     string
	BootID    string
	RunNumber uint64
	Version   string
	Stopping  bool
}

// maxFieldBytes caps each run field (id, boot id, version) the state and alerts carry:
// the host controls them. Agents send a ULID, a UUID and a short version.
const maxFieldBytes = 64

// older reports whether seen comes from a run before r: same boot and a lower run counter
// (a late resend from the spool). Runs of another boot, or without counters, are taken
// as newer.
func (r Run) older(seen RunSeen) bool {
	return r.BootID != "" && seen.BootID == r.BootID && seen.RunNumber > 0 && r.Number > 0 && seen.RunNumber < r.Number
}

func runOf(seen RunSeen) Run {
	v := cleanField(seen.Version)
	return Run{ID: seen.RunID, BootID: seen.BootID, Number: seen.RunNumber, Version: v, Identity: v != "", CleanStop: seen.Stopping}
}

// RestartPrefix is the prefix of a host's restart dedupe mark.
func RestartPrefix(host string) string { return "restart:" + host }

// Run judges a host's run as one agent message reports it (in the host's stream order):
// the first run seen is recorded; a stop marker marks the current run clean; a new run
// after a run that reported its version and sent no stop marker raises one informational
// agent_restarted_unclean alert (at most one per host per dedupe window, so a crash loop
// does not flood). Messages of an older run are ignored. An empty run id changes nothing.
func (e *Engine) Run(ctx context.Context, st State, host string, seen RunSeen, now time.Time) (Decision, error) {
	seen.RunID, seen.BootID = cleanField(seen.RunID), cleanField(seen.BootID)
	if seen.RunID == "" {
		return Decision{}, nil
	}
	stored, ok, err := st.Run(ctx, host)
	if err != nil {
		return Decision{}, err
	}
	switch {
	case ok && stored.ID == seen.RunID:
		next := stored
		if v := cleanField(seen.Version); v != "" && !stored.Identity {
			next.Version, next.Identity = v, true
		}
		next.CleanStop = stored.CleanStop || seen.Stopping
		if next == stored {
			return Decision{}, nil
		}
		return Decision{}, st.SetRun(ctx, host, next)
	case ok && stored.older(seen):
		return Decision{Suppressed: "older run"}, nil
	}
	if err := st.SetRun(ctx, host, runOf(seen)); err != nil {
		return Decision{}, err
	}
	if !ok || !stored.Identity || stored.CleanStop || seen.Stopping {
		// First sighting; a previous run from a release without stop markers; a clean
		// stop; or a stop marker of a run never seen running (nothing to judge).
		return Decision{}, nil
	}
	if !e.rules.PageOnUncleanRestart {
		return Decision{}, nil
	}
	if dup, err := e.dedupe(ctx, st, RestartPrefix(host), now); err != nil || dup {
		return Decision{Suppressed: "dedupe"}, err
	}
	next := runOf(seen)
	return e.queue(ctx, st, &Alert{ID: e.newID(), Kind: KindAgentRestartedUnclean, Severity: SeverityInfo, Host: host, At: now,
		Origin: "agent",
		Evidence: []string{
			"previous run " + describeRun(stored) + ": no clean-shutdown marker",
			"new run " + describeRun(next),
		},
		Summary: fmt.Sprintf("host %s: the agent restarted without a clean shutdown (version %s)", host, orUnknown(next.Version))})
}

func describeRun(r Run) string {
	return fmt.Sprintf("%s (boot %s, run %d, version %s)", r.ID, orUnknown(r.BootID), r.Number, orUnknown(r.Version))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// cleanField drops non-printable characters (invalid UTF-8 included) and caps the
// length on a character boundary.
func cleanField(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		i += size
		if (r == utf8.RuneError && size <= 1) || !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxFieldBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
