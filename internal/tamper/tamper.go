// Package tamper holds the agent's self-checks (design §9, "the agent checks that its
// probes are still attached"): its eBPF links still attached and running the programs it
// loaded, nobody ptracing it, its executable and systemd unit files unchanged on disk,
// and its kernel drop counters only ever rising. Every check is a fixed rule; a check
// that cannot read its evidence reports "unknown", never tamper.
//
// A Monitor runs the checks in passes and turns successive results into transitions
// (flags raised and cleared), which the agent publishes on asm.<host>.tamper; the latest
// status rides on every heartbeat.
package tamper

import (
	"slices"
	"strings"
	"time"
)

// Flag kinds.
const (
	// KindProbeDetached: a link the agent attached is no longer attached (a cgroup link
	// detached with BPF_LINK_DETACH, a tracing link whose target is gone).
	KindProbeDetached = "probe_detached"
	// KindProgramReplaced: a link now runs a program other than the one the agent loaded
	// (BPF_LINK_UPDATE).
	KindProgramReplaced = "program_replaced"
	// KindPtraced: a thread of the agent has a tracer (TracerPid in /proc/self/task/*/status).
	KindPtraced = "ptraced"
	// KindBinaryReplaced: the agent's executable on disk no longer hashes like the
	// running image.
	KindBinaryReplaced = "binary_replaced"
	// KindBinaryMissing: the agent's executable path is gone.
	KindBinaryMissing = "binary_missing"
	// KindUnitChanged: the agent's systemd unit file or one of its drop-ins changed, was
	// added or removed since start.
	KindUnitChanged = "unit_changed"
	// KindFileChanged: a file named with --tamper-files changed or disappeared.
	KindFileChanged = "file_changed"
	// KindCounterReset: a kernel counter the agent reads went down (its map was written).
	KindCounterReset = "counter_reset"
	// KindEventsDropped: the ring buffer dropped events since the last pass.
	KindEventsDropped = "events_dropped"
)

// Flag is one tamper signal. A flag is identified by Kind and Subject; Detail may change
// from pass to pass without making it a new flag.
type Flag struct {
	Kind    string
	Subject string
	Detail  string
	// Since is when the monitor first saw it.
	Since time.Time
}

func (f Flag) key() string { return f.Kind + "\x00" + f.Subject }

// Check is one self-check.
type Check interface {
	// Name names the check in Status.Checks ("probes", "self_exe", "unit", ...).
	Name() string
	// Run returns the flags it sees now. An error means the evidence could not be read:
	// the check's flags from the previous pass are kept and the error is reported as
	// unknown.
	Run() ([]Flag, error)
}

// Status is the result of one pass.
type Status struct {
	Flags     []Flag
	CheckedAt time.Time
	Checks    []string
	Unknown   []string
	// RunCounts are per-program run counts while kernel.bpf_stats_enabled is 1 (nil
	// otherwise); RingbufDrops is the ring buffer's drop counter. Both are informational.
	RunCounts    map[string]uint64
	RingbufDrops uint64
}

// Clean reports whether no flag is raised.
func (s Status) Clean() bool { return len(s.Flags) == 0 }

// Transition is what changed between two passes.
type Transition struct {
	Raised, Cleared []Flag
	Status          Status
}

// Changed reports whether any flag was raised or cleared.
func (t Transition) Changed() bool { return len(t.Raised) > 0 || len(t.Cleared) > 0 }

// Monitor runs checks in passes. It is not safe for concurrent use.
type Monitor struct {
	checks []Check
	// Stats, when set, fills the informational counters of each pass.
	Stats func(*Status)
	// last holds each check's flags from its last successful run, by check index.
	last [][]Flag
	// since remembers when each currently raised flag was first seen.
	since map[string]time.Time
}

// NewMonitor returns a monitor over checks.
func NewMonitor(checks ...Check) *Monitor {
	return &Monitor{checks: checks, last: make([][]Flag, len(checks)), since: map[string]time.Time{}}
}

// Pass runs every check once and returns the status and what changed since the last pass.
func (m *Monitor) Pass(now time.Time) Transition {
	st := Status{CheckedAt: now}
	current := map[string]Flag{}
	for i, c := range m.checks {
		st.Checks = append(st.Checks, c.Name())
		flags, err := c.Run()
		if err != nil {
			st.Unknown = append(st.Unknown, c.Name()+": "+err.Error())
			flags = m.last[i] // keep what it last saw: unknown never clears a flag
		} else {
			m.last[i] = flags
		}
		for _, f := range flags {
			current[f.key()] = f
		}
	}

	var tr Transition
	for k, f := range current {
		since, seen := m.since[k]
		if !seen {
			since = now
			m.since[k] = now
			f.Since = now
			tr.Raised = append(tr.Raised, f)
		}
		f.Since = since
		st.Flags = append(st.Flags, f)
	}
	for k, since := range m.since {
		if _, ok := current[k]; !ok {
			kind, subject, _ := strings.Cut(k, "\x00")
			tr.Cleared = append(tr.Cleared, Flag{Kind: kind, Subject: subject, Since: since})
			delete(m.since, k)
		}
	}
	sortFlags(st.Flags)
	sortFlags(tr.Raised)
	sortFlags(tr.Cleared)
	if m.Stats != nil {
		m.Stats(&st)
	}
	tr.Status = st
	return tr
}

func sortFlags(fs []Flag) {
	slices.SortFunc(fs, func(a, b Flag) int { return strings.Compare(a.key(), b.key()) })
}
