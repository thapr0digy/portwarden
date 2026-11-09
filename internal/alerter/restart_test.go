package alerter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func beat(run string, n uint64, version string) RunSeen {
	return RunSeen{RunID: run, BootID: "b1", RunNumber: n, Version: version}
}

func stopped(run string, n uint64, version string) RunSeen {
	s := beat(run, n, version)
	s.Stopping = true
	return s
}

// feed applies run reports in order, one minute apart, and returns the queued alerts.
func feed(t *testing.T, e *Engine, st *MemState, reports ...RunSeen) []*Alert {
	t.Helper()
	for i, r := range reports {
		if _, err := e.Run(context.Background(), st, "h1", r, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	return st.Queue
}

func restartRules() Rules { return Rules{PageOnUncleanRestart: true} }

func TestRestartClean(t *testing.T) {
	st := NewMemState()
	got := feed(t, engine(t, restartRules()), st,
		beat("01A", 1, "1.4.0"), beat("01A", 1, "1.4.0"), stopped("01A", 1, "1.4.0"), beat("01B", 2, "1.4.0"))
	if len(got) != 0 {
		t.Fatalf("a clean restart raised %+v", got[0])
	}
	if r := st.Runs["h1"]; r.ID != "01B" || r.CleanStop || !r.Identity {
		t.Fatalf("stored run %+v", r)
	}
}

func TestRestartUnclean(t *testing.T) {
	st := NewMemState()
	got := feed(t, engine(t, restartRules()), st, beat("01A", 1, "1.4.0"), beat("01B", 2, "1.5.0"))
	if len(got) != 1 {
		t.Fatalf("alerts %d, want 1", len(got))
	}
	a := got[0]
	if a.Kind != KindAgentRestartedUnclean || a.Severity != SeverityInfo || a.Host != "h1" || len(a.Evidence) != 2 ||
		!strings.Contains(a.Evidence[0], "01A") || !strings.Contains(a.Evidence[1], "01B") || !strings.Contains(a.Summary, "1.5.0") {
		t.Fatalf("alert %+v", a)
	}
	b, _ := json.Marshal(a)
	if !strings.Contains(string(b), `"severity":"info"`) {
		t.Fatalf("payload %s", b)
	}
}

// Existing alert kinds keep their payloads: no severity field.
func TestSeverityOmittedOnPages(t *testing.T) {
	b, _ := json.Marshal(&Alert{ID: "x", Kind: KindTamper})
	if strings.Contains(string(b), "severity") {
		t.Fatalf("payload %s", b)
	}
}

func TestRestartFirstSighting(t *testing.T) {
	st := NewMemState()
	if got := feed(t, engine(t, restartRules()), st, beat("01B", 2, "1.4.0")); len(got) != 0 {
		t.Fatalf("first sighting raised %+v", got[0])
	}
}

// Older releases never send the stop marker: their restart (the upgrade to this release
// included) must not raise.
func TestRestartOldAgent(t *testing.T) {
	st := NewMemState()
	if got := feed(t, engine(t, restartRules()), st, beat("01A", 1, ""), beat("01B", 2, "1.4.0")); len(got) != 0 {
		t.Fatalf("restart out of an older agent raised %+v", got[0])
	}
	// From then on the host is judged.
	if got := feed(t, engine(t, restartRules()), st, beat("01C", 3, "1.4.0")); len(got) != 1 {
		t.Fatalf("alerts %d after the upgrade, want 1", len(got))
	}
}

// A late resend from an older run of the same boot (the spool after a power loss) is
// not a new run.
func TestRestartLateOldRun(t *testing.T) {
	st := NewMemState()
	e := engine(t, restartRules())
	got := feed(t, e, st, beat("01B", 2, "1.4.0"), beat("01A", 1, "1.4.0"))
	if len(got) != 0 || st.Runs["h1"].ID != "01B" {
		t.Fatalf("older run: alerts %d, stored %+v", len(got), st.Runs["h1"])
	}
	d, err := e.Run(context.Background(), st, "h1", beat("01A", 1, "1.4.0"), t0)
	if err != nil || d.Suppressed != "older run" {
		t.Fatalf("decision %+v %v", d, err)
	}
	// A new boot is newer whatever its counter.
	next := beat("01C", 1, "1.4.0")
	next.BootID = "b2"
	if got := feed(t, e, st, next); len(got) != 1 {
		t.Fatalf("new boot without a stop marker: alerts %d, want 1", len(got))
	}
}

func TestRestartCrashLoopDedupe(t *testing.T) {
	st := NewMemState()
	got := feed(t, engine(t, restartRules()), st,
		beat("01A", 1, "1.4.0"), beat("01B", 2, "1.4.0"), beat("01C", 3, "1.4.0"), beat("01D", 4, "1.4.0"))
	if len(got) != 1 {
		t.Fatalf("crash loop within the dedupe window: alerts %d, want 1", len(got))
	}
	if st.Runs["h1"].ID != "01D" {
		t.Fatalf("stored run %+v: deduped restarts must still move the run", st.Runs["h1"])
	}
	// Past the window, the next unclean restart raises again.
	if _, err := engine(t, restartRules()).Run(context.Background(), st, "h1", beat("01E", 5, "1.4.0"), t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(st.Queue) != 2 {
		t.Fatalf("alerts %d after the window, want 2", len(st.Queue))
	}
}

func TestRestartDisabled(t *testing.T) {
	st := NewMemState()
	if got := feed(t, engine(t, Rules{}), st, beat("01A", 1, "1.4.0"), beat("01B", 2, "1.4.0")); len(got) != 0 {
		t.Fatalf("page_on_unclean_restart=false raised %+v", got[0])
	}
	if st.Runs["h1"].ID != "01B" {
		t.Fatal("the run must be tracked even with the rule off")
	}
}

func TestRestartAfterForget(t *testing.T) {
	st := NewMemState()
	e := engine(t, restartRules())
	feed(t, e, st, beat("01A", 1, "1.4.0"), beat("01B", 2, "1.4.0"))
	if err := e.Forget(context.Background(), st, "h1", ForgetMark{Seq: 10, Stream: t0}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Runs["h1"]; ok {
		t.Fatal("forget must drop the run")
	}
	if _, ok := st.Paged[RestartPrefix("h1")]; ok {
		t.Fatal("forget must drop the restart mark")
	}
	if got := feed(t, e, st, beat("01C", 3, "1.4.0")); len(got) != 1 { // only the earlier alert
		t.Fatalf("a forgotten host's first run is a first sighting: alerts %d", len(got))
	}
}

// The design assumes the alerter sees a run's stop marker before the next run's
// heartbeat (stream order, also in the start-up replay of the last message per subject);
// a stop marker of a run never seen running records it clean without raising.
func TestRestartReplayOrder(t *testing.T) {
	st := NewMemState()
	e := engine(t, restartRules())
	// The alerter was down: the replay holds the old run's stop marker, then the new
	// run's last heartbeat; the stored run is older still.
	feed(t, e, st, beat("01A", 1, "1.4.0"))
	if got := feed(t, e, st, stopped("01B", 2, "1.4.0"), beat("01C", 3, "1.4.0")); len(got) != 0 {
		t.Fatalf("replay raised %+v", got[0])
	}
	// The same replay out of order (heartbeat first) is the false notice the README
	// documents: it raises.
	st2 := NewMemState()
	feed(t, e, st2, beat("01A", 1, "1.4.0"))
	if got := feed(t, e, st2, beat("01C", 3, "1.4.0")); len(got) != 1 {
		t.Fatalf("missed stop marker: alerts %d, want 1", len(got))
	}
}

// Hostile run fields are cleaned and capped before they are stored or shown.
func TestRestartHostileFields(t *testing.T) {
	st := NewMemState()
	e := engine(t, restartRules())
	big := strings.Repeat("v", 1<<20)
	feed(t, e, st, beat("01A", 1, "1.4.0"), RunSeen{RunID: big + "\x00\n", BootID: big, RunNumber: 2, Version: big + "\x1b"})
	r := st.Runs["h1"]
	if len(r.ID) != maxFieldBytes || len(r.BootID) != maxFieldBytes || len(r.Version) != maxFieldBytes {
		t.Fatalf("stored %d/%d/%d bytes", len(r.ID), len(r.BootID), len(r.Version))
	}
	a := st.Queue[0]
	if len(a.Summary) > 200 || strings.ContainsAny(a.Summary+strings.Join(a.Evidence, ""), "\x00\n\x1b") {
		t.Fatalf("alert carries raw input: %q", a.Summary)
	}
	if d, err := e.Run(context.Background(), st, "h1", RunSeen{}, t0); err != nil || d.Alert != nil {
		t.Fatalf("empty run id: %+v %v", d, err)
	}
}
