package protocol

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
)

const host = "0123456789abcdef0123456789abcdef"

var agent = Principal{ID: "p1", Kind: eventsv1.ProducerAgent, HostID: host}

func hb(run string, seq uint64) *eventsv1.Event {
	return &eventsv1.Event{
		Id: "id" + run + string(rune('a'+seq)), Type: "asm.agent.heartbeat", Subject: "host:" + host,
		Time:     timestamppb.Now(),
		Sequence: &eventsv1.Sequence{RunId: run, Seq: seq, BootId: "b1", RunNumber: 1},
		Data:     &eventsv1.Event_Heartbeat{Heartbeat: &eventsv1.Heartbeat{AgentVersion: "v1", SpoolEvents: seq}},
	}
}

func els(evs ...*eventsv1.Event) []validate.Element {
	out := make([]validate.Element, len(evs))
	for i, e := range evs {
		out[i] = validate.Element{Index: i, Event: e}
	}
	return out
}

func TestCursorCases(t *testing.T) {
	now := time.Unix(1000, 0)
	o := Options{Now: now}
	st := State{Run: Run{ID: "r1", BootID: "b1", RunNumber: 1, LastSeq: 5}}

	p := PlanBatch(agent, st, els(hb("r1", 5), hb("r1", 6)), o)
	if p.Items[0].Verdict != Duplicate || p.Items[1].Verdict != Store || p.State.Run.LastSeq != 6 {
		t.Fatalf("dup/next: %+v", p.Items)
	}
	p = PlanBatch(agent, st, els(hb("r1", 9)), o)
	if len(p.Gaps) != 1 || p.Gaps[0].From != 6 || p.Gaps[0].To != 8 || len(p.Directives) != 1 ||
		p.Directives[0].Kind != eventsv1.Directive_RESYNC_SNAPSHOT {
		t.Fatalf("gap: %+v %+v", p.Gaps, p.Directives)
	}
	// An overflow in the same batch explains the gap: no resync.
	so := hb("r1", 10)
	so.Type = "asm.agent.spool_overflow"
	so.Data = &eventsv1.Event_SpoolOverflow{SpoolOverflow: &eventsv1.SpoolOverflow{RunId: "r1", FirstSeq: 6, LastSeq: 8, Dropped: 3}}
	p = PlanBatch(agent, st, els(hb("r1", 9), so), o)
	if !p.Gaps[0].Explained || len(p.Directives) != 0 {
		t.Fatalf("explained: %+v %+v", p.Gaps, p.Directives)
	}
	// The full snapshot a resync sends explains every earlier gap of its run (R10).
	snap := hb("r1", 10)
	snap.Type = "asm.host.snapshot"
	snap.Data = &eventsv1.Event_HostSnapshot{HostSnapshot: &eventsv1.HostSnapshot{Digest: "ab"}}
	p = PlanBatch(agent, st, els(hb("r1", 9), snap), o)
	if !p.Gaps[0].Explained || len(p.Directives) != 0 || len(p.Explains) != 1 || p.Explains[0].To != 9 {
		t.Fatalf("resync snapshot: %+v %+v %+v", p.Gaps, p.Explains, p.Directives)
	}
	// A newer run (new boot) retires the old cursor; an older run number of the same boot is stale.
	n := hb("r2", 1)
	n.Sequence.BootId = "b2"
	p = PlanBatch(agent, st, els(n), o)
	if p.Items[0].Verdict != Store || !p.Items[0].Retired || p.State.Run.ID != "r2" {
		t.Fatalf("new run: %+v", p.Items[0])
	}
	// A late event of the replaced run (another boot) is history: r2 stays the run (R2).
	late := PlanBatch(agent, p.State, els(hb("r1", 11)), o)
	if late.Items[0].Verdict != Duplicate || !late.Items[0].Stale || late.State.Run.ID != "r2" || len(late.Gaps) != 0 {
		t.Fatalf("late event of a retired run: %+v %+v", late.Items[0], late.State.Run)
	}
	old := hb("r0", 1)
	old.Sequence.RunNumber = 0
	p = PlanBatch(agent, st, els(old), o)
	if p.Items[0].Verdict != Duplicate || !p.Items[0].Stale || p.State.Run.ID != "r1" {
		t.Fatalf("stale run: %+v", p.Items[0])
	}
}

func TestAuthorizeScopes(t *testing.T) {
	other := hb("r1", 1)
	other.Subject = "host:ffffffffffffffffffffffffffffffff"
	if p := PlanBatch(agent, State{}, els(other), Options{}); p.Items[0].Problem == nil || p.Items[0].Problem.Code != validate.CodeForbiddenSubject {
		t.Fatalf("agent wrote another host: %+v", p.Items[0])
	}
	scanner := Principal{ID: "s", Kind: eventsv1.ProducerScanner, Scope: Scope{CIDRs: []string{"203.0.113.0/24"}, DNSSuffixes: []string{"example.com"}, RepoOwners: []string{"github.com/acme"}}}
	for subject, want := range map[string]bool{
		"ip:203.0.113.9": true, "ip:198.51.100.1": false, "dns:api.example.com": true, "dns:example.com": true,
		"dns:badexample.com": false, "svc:203.0.113.9:tcp/443": true, "svc:api.example.com:tcp/443": true,
		"url:https://api.example.com/x": true, "repo:github.com/acme/app": true, "repo:github.com/evil/app": false,
		"cidr:203.0.113.0/25": true, "cidr:203.0.112.0/23": false, "host:" + host: false, "scan:01JC8Z0000000000000000000A": true,
	} {
		if got := scanner.Scope.Allows(subject); got != want {
			t.Errorf("Allows(%q) = %v, want %v", subject, got, want)
		}
	}
	if p := Authorize(scanner, hb("r1", 1)); p == nil || p.Code != CodeForbiddenType {
		t.Fatalf("scanner sent an agent type: %v", p)
	}
}

func TestUnchangedSnapshotAndHeartbeatSampling(t *testing.T) {
	now := time.Unix(1000, 0)
	snap := func(seq uint64, digest string, unchanged bool) *eventsv1.Event {
		e := hb("r1", seq)
		e.Type = "asm.host.snapshot"
		e.Data = &eventsv1.Event_HostSnapshot{HostSnapshot: &eventsv1.HostSnapshot{Digest: digest, Unchanged: unchanged}}
		return e
	}
	st := State{Run: Run{ID: "r1", BootID: "b1", RunNumber: 1}}
	p := PlanBatch(agent, st, els(snap(1, "aa", false), snap(2, "aa", true), snap(3, "bb", true)), Options{Now: now})
	if p.Items[0].Verdict != Store || p.Items[1].Verdict != Confirm || p.Items[2].Verdict != Confirm {
		t.Fatalf("verdicts: %+v", p.Items)
	}
	if len(p.Directives) != 1 || p.Directives[0].Kind != eventsv1.Directive_RESYNC_SNAPSHOT {
		t.Fatalf("unknown digest must ask for a snapshot: %+v", p.Directives)
	}
	o := Options{Now: now, HeartbeatEvery: 5 * time.Minute}
	p = PlanBatch(agent, State{Run: Run{ID: "r1", BootID: "b1", RunNumber: 1}}, els(hb("r1", 1), hb("r1", 2)), o)
	if p.Items[0].Verdict != Store || p.Items[1].Verdict != Sample {
		t.Fatalf("heartbeats: %+v", p.Items)
	}
	changed := hb("r1", 3)
	changed.Data.(*eventsv1.Event_Heartbeat).Heartbeat.AgentVersion = "v2"
	p2 := PlanBatch(agent, p.State, els(changed), Options{Now: now.Add(time.Second), HeartbeatEvery: 5 * time.Minute})
	if p2.Items[0].Verdict != Store {
		t.Fatalf("a changed field must be stored: %+v", p2.Items[0])
	}
}

func TestRejectedEventStillAdvancesCursor(t *testing.T) {
	bad := hb("r1", 1)
	p := PlanBatch(agent, State{}, []validate.Element{{Index: 0, Event: bad, Problem: &validate.Problem{Code: validate.CodeInvalidPayload}}, {Index: 1, Event: hb("r1", 2)}}, Options{})
	if p.Items[0].Verdict != Reject || p.Items[1].Verdict != Store || len(p.Gaps) != 0 || p.State.Run.LastSeq != 2 {
		t.Fatalf("%+v %+v", p.Items, p.State)
	}
}

// The access state and the package list ride with the snapshot: a known unchanged digest is
// confirmed, an unknown one asks for the snapshot resync that also carries them, and the resync
// forgets every digest it will resend.
func TestUnchangedStatesRideWithSnapshot(t *testing.T) {
	for _, c := range []struct {
		typ, key string
		set      func(e *eventsv1.Event, digest string, unchanged bool)
	}{
		{"asm.host.access", "access", func(e *eventsv1.Event, d string, u bool) {
			e.Data = &eventsv1.Event_HostAccess{HostAccess: &eventsv1.HostAccess{Digest: d, Unchanged: u}}
		}},
		{"asm.host.packages", "packages", func(e *eventsv1.Event, d string, u bool) {
			e.Data = &eventsv1.Event_HostPackages{HostPackages: &eventsv1.HostPackages{Digest: d, Unchanged: u}}
		}},
	} {
		ev := func(seq uint64, digest string, unchanged bool) *eventsv1.Event {
			e := hb("r1", seq)
			e.Type = c.typ
			c.set(e, digest, unchanged)
			return e
		}
		st := State{Run: Run{ID: "r1", BootID: "b1", RunNumber: 1}}
		p := PlanBatch(agent, st, els(ev(1, "aa", false), ev(2, "aa", true)), Options{Now: time.Unix(1000, 0)})
		if p.Items[0].Verdict != Store || p.Items[1].Verdict != Confirm || len(p.Directives) != 0 {
			t.Fatalf("%s known digest: %+v %+v", c.typ, p.Items, p.Directives)
		}
		p = PlanBatch(agent, p.State, els(ev(3, "bb", true)), Options{Now: time.Unix(1001, 0)})
		if p.Items[0].Verdict != Confirm || len(p.Directives) != 1 || p.Directives[0].Kind != eventsv1.Directive_RESYNC_SNAPSHOT {
			t.Fatalf("%s unknown digest must ask for a resync: %+v %+v", c.typ, p.Items, p.Directives)
		}
		if p.State.Digests[c.key] != "" {
			t.Fatalf("%s: the resync forgets the digest: %+v", c.typ, p.State.Digests)
		}
	}
}
