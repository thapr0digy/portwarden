package alerter

import (
	"strings"
	"testing"
	"time"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

func tamperStatus(flags ...string) *asmv1.TamperStatus {
	st := &asmv1.TamperStatus{Checks: []string{"probes", "ptrace"}}
	for _, f := range flags {
		kind, subject, _ := strings.Cut(f, ":")
		st.Flags = append(st.Flags, &asmv1.TamperFlag{Kind: kind, Subject: subject, Detail: "d-" + kind})
	}
	return st
}

func TestTamperPagesOncePerNewFlag(t *testing.T) {
	e := engine(t, Rules{PageOnTamper: true})
	st := NewMemState()
	must := mustD(t)
	now := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)

	if d := must(e.Tamper(bg, st, "h1", tamperStatus(), now)); d.Alert != nil {
		t.Fatalf("clean status paged: %+v", d.Alert)
	}
	d := must(e.Tamper(bg, st, "h1", tamperStatus("ptraced:self"), now))
	if d.Alert == nil || d.Alert.Kind != KindTamper || d.Alert.Host != "h1" ||
		len(d.Alert.Evidence) != 1 || d.Alert.Evidence[0] != "ptraced:self: d-ptraced" {
		t.Fatalf("first flag: %+v", d.Alert)
	}
	// The same flag on every later heartbeat: no new page.
	for range 3 {
		if d := must(e.Tamper(bg, st, "h1", tamperStatus("ptraced:self"), now.Add(time.Minute))); d.Alert != nil {
			t.Fatalf("repeated flag paged again: %+v", d.Alert)
		}
	}
	// A second flag pages for itself only.
	d = must(e.Tamper(bg, st, "h1", tamperStatus("ptraced:self", "probe_detached:on_connect4@/x"), now))
	if d.Alert == nil || len(d.Alert.Evidence) != 1 || !strings.HasPrefix(d.Alert.Evidence[0], "probe_detached:on_connect4@/x") {
		t.Fatalf("second flag: %+v", d.Alert)
	}
	// Cleared (the agent restarted, or the tracer left), then raised again: pages again.
	must(e.Tamper(bg, st, "h1", tamperStatus(), now))
	if len(st.Paged) != 0 {
		t.Fatalf("cleared flags must drop their marks: %v", st.Paged)
	}
	if d := must(e.Tamper(bg, st, "h1", tamperStatus("ptraced:self"), now)); d.Alert == nil {
		t.Fatal("a flag raised again after clearing must page")
	}
	// Another host's marks are its own.
	if d := must(e.Tamper(bg, st, "h2", tamperStatus("ptraced:self"), now)); d.Alert == nil || d.Alert.Host != "h2" {
		t.Fatalf("h2: %+v", d.Alert)
	}
	if len(st.Queue) != 4 {
		t.Fatalf("pages queued: %d", len(st.Queue))
	}
}

func TestTamperIgnoreAndOff(t *testing.T) {
	must := mustD(t)
	now := time.Now()
	e := engine(t, Rules{PageOnTamper: true, TamperIgnore: []string{"events_dropped"}})
	st := NewMemState()
	if d := must(e.Tamper(bg, st, "h1", tamperStatus("events_dropped:ringbuf_drops"), now)); d.Alert != nil || d.Suppressed != "" {
		t.Fatalf("ignored kind: %+v", d)
	}
	off := engine(t, Rules{PageOnTamper: false})
	if d := must(off.Tamper(bg, NewMemState(), "h1", tamperStatus("ptraced:self"), now)); d.Alert != nil {
		t.Fatalf("page_on_tamper=false paged: %+v", d.Alert)
	}
	// A heartbeat from an agent without tamper checks changes nothing.
	st = NewMemState()
	must(e.Tamper(bg, st, "h1", tamperStatus("ptraced:self"), now))
	if d := must(e.Tamper(bg, st, "h1", nil, now)); d.Alert != nil || len(st.Paged) != 1 {
		t.Fatalf("nil status: %+v %v", d, st.Paged)
	}
}
