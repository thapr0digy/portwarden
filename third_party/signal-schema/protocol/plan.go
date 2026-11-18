package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
)

// Verdict is what the server does with one event of a batch.
type Verdict int

const (
	// Store appends the event to the log.
	Store Verdict = iota
	// Duplicate means the event is at or below the cursor (a retry); it is not stored.
	Duplicate
	// Reject means the event is quarantined (Item.Problem says why) and still advances the cursor.
	Reject
	// Confirm means an unchanged snapshot or route set whose digest the server holds; it is
	// acknowledged and counted, not stored.
	Confirm
	// Sample means a heartbeat that adds nothing new since the last stored one; acknowledged,
	// not stored.
	Sample
)

// Run is a producer's newest run as the server remembers it.
type Run struct {
	ID        string
	BootID    string
	RunNumber uint64
	LastSeq   uint64
}

// State is what the server holds for one principal and is all Plan reads.
type State struct {
	// Run is the newest run; zero when the principal has none.
	Run Run
	// Retired holds the ids of the principal's runs a newer one replaced: a late event of
	// one is history, never a reason to adopt it again.
	Retired map[string]bool
	// Digests maps "snapshot", "access", "packages" and "routes:<proxy id>" to the last full state's digest.
	Digests map[string]string
	// HeartbeatStoredAt and HeartbeatFields describe the last stored heartbeat of this run.
	HeartbeatStoredAt time.Time
	HeartbeatFields   string
}

// Options are the rule inputs.
type Options struct {
	Now time.Time
	// HeartbeatEvery is how often an unchanged heartbeat is stored (0: every one).
	HeartbeatEvery time.Duration
}

// Gap is a missing stretch of one run's sequence numbers.
type Gap struct {
	RunID    string
	From, To uint64
	// Explained is true when a SpoolOverflow in the same batch covers it.
	Explained bool
}

// Item is the plan for one element of the batch.
type Item struct {
	Index   int
	Event   *eventsv1.Event
	Verdict Verdict
	Problem *validate.Problem
	// Retired is set on the first event of a run that replaced an older one.
	Retired bool
	// Stale marks events of a run older than the newest: history only.
	Stale bool
}

// Plan is the outcome of a batch for one principal.
type Plan struct {
	Items []Item
	Gaps  []Gap
	// Explains are SpoolOverflow ranges whose gap may already be stored: the store marks
	// them explained. A full snapshot stored at seq N explains every gap of its run before N:
	// the state it lists replaces whatever the gap lost.
	Explains []Gap
	// Directives are the commands for the producer's next request.
	Directives []*eventsv1.Directive
	// State is the principal's state after the batch commits.
	State State
}

// Count returns how many items have verdict v.
func (p Plan) Count(v Verdict) int {
	n := 0
	for _, it := range p.Items {
		if it.Verdict == v {
			n++
		}
	}
	return n
}

// ridersOfSnapshot are the full states an agent resends with its snapshot on RESYNC_SNAPSHOT,
// each under its digest key.
var ridersOfSnapshot = []string{"access", "packages"} //nolint:gochecknoglobals // fixed table

// ridesWithSnapshot applies a full state that rides with the snapshot (its digest under key): an
// unchanged report is confirmed, and asks for the resync when its digest is not the one held; a
// changed one records its digest.
func (st *State) ridesWithSnapshot(key string, unchanged bool, digest string) (confirmed, resync bool) {
	switch {
	case unchanged:
		return true, st.Digests[key] == "" || digest != st.Digests[key]
	case digest != "":
		st.Digests[key] = digest
	}
	return false, false
}

// Resync is a Directive asking for a full snapshot.
func resync(k eventsv1.Directive_Kind, reason string) *eventsv1.Directive {
	return &eventsv1.Directive{Kind: k, Reason: reason}
}

// PlanBatch applies a validated, in-order batch to st. Elements with a decode or validation
// Problem are rejected; the rest are authorized, then checked against the run cursor
// (the cases in the schema README), digests and the heartbeat rule. It never mutates st.
func PlanBatch(p Principal, st State, els []validate.Element, o Options) Plan {
	plan := Plan{State: clone(st)}
	cur := &plan.State
	wantSnapshot, wantProxies := false, false
	for _, e := range els {
		it := Item{Index: e.Index, Event: e.Event}
		switch {
		case e.Problem != nil:
			it.Verdict, it.Problem = Reject, e.Problem
		default:
			if prob := Authorize(p, e.Event); prob != nil {
				prob.Index = e.Index
				it.Verdict, it.Problem = Reject, prob
			}
		}
		seq := e.Event.GetSequence()
		if it.Verdict == Reject {
			// A refused event still advances a sequenced producer's cursor: it must not be resent.
			if seq.GetSeq() > 0 {
				advance(cur, seq, &it, &plan)
			}
			plan.Items = append(plan.Items, it)
			continue
		}
		if seq.GetSeq() > 0 {
			advance(cur, seq, &it, &plan)
		}
		if it.Verdict == Store {
			switch d := e.Event.GetData().(type) {
			case *eventsv1.Event_HostSnapshot:
				snap := d.HostSnapshot
				switch {
				case snap.GetUnchanged() && cur.Digests["snapshot"] != "" && snap.GetDigest() == cur.Digests["snapshot"]:
					it.Verdict = Confirm
				case snap.GetUnchanged():
					it.Verdict, wantSnapshot = Confirm, true
				case snap.GetDigest() != "":
					cur.Digests["snapshot"] = snap.GetDigest()
				}
				if !snap.GetUnchanged() && seq.GetSeq() > 1 {
					plan.Explains = append(plan.Explains, Gap{RunID: cur.Run.ID, From: 1, To: seq.GetSeq() - 1, Explained: true})
				}
			case *eventsv1.Event_ProxyRoutes:
				pr := d.ProxyRoutes
				key := "routes:" + pr.GetProxy().GetId()
				switch {
				case pr.GetUnchanged() && cur.Digests[key] != "" && pr.GetRoutesDigest() == cur.Digests[key]:
					it.Verdict = Confirm
				case pr.GetUnchanged():
					it.Verdict, wantProxies = Confirm, true
				case pr.GetRoutesDigest() != "":
					cur.Digests[key] = pr.GetRoutesDigest()
				}
			case *eventsv1.Event_HostAccess:
				// The SSH access state and the package list ride with the snapshot: an unknown
				// digest asks for the same resync, whose answer carries them all.
				if confirmed, resync := cur.ridesWithSnapshot("access", d.HostAccess.GetUnchanged(), d.HostAccess.GetDigest()); confirmed {
					it.Verdict, wantSnapshot = Confirm, wantSnapshot || resync
				}
			case *eventsv1.Event_HostPackages:
				if confirmed, resync := cur.ridesWithSnapshot("packages", d.HostPackages.GetUnchanged(), d.HostPackages.GetDigest()); confirmed {
					it.Verdict, wantSnapshot = Confirm, wantSnapshot || resync
				}
			case *eventsv1.Event_Heartbeat:
				fields := heartbeatFields(d.Heartbeat)
				due := o.HeartbeatEvery <= 0 || cur.HeartbeatStoredAt.IsZero() ||
					o.Now.Sub(cur.HeartbeatStoredAt) >= o.HeartbeatEvery || fields != cur.HeartbeatFields
				if due {
					cur.HeartbeatStoredAt, cur.HeartbeatFields = o.Now, fields
				} else {
					it.Verdict = Sample
				}
			case *eventsv1.Event_SpoolOverflow:
				so := d.SpoolOverflow
				plan.Explains = append(plan.Explains, Gap{RunID: so.GetRunId(), From: so.GetFirstSeq(), To: so.GetLastSeq(), Explained: true})
			}
		}
		plan.Items = append(plan.Items, it)
	}
	for i := range plan.Gaps {
		g := &plan.Gaps[i]
		for _, x := range plan.Explains {
			if x.RunID == g.RunID && x.From <= g.From && x.To >= g.To {
				g.Explained = true
			}
		}
	}
	for _, g := range plan.Gaps {
		if !g.Explained {
			wantSnapshot = true
		}
	}
	if wantSnapshot {
		plan.Directives = append(plan.Directives, resync(eventsv1.Directive_RESYNC_SNAPSHOT, "sequence gap or unknown snapshot digest"))
		delete(cur.Digests, "snapshot")
		for _, key := range ridersOfSnapshot {
			delete(cur.Digests, key)
		}
	}
	if wantProxies {
		plan.Directives = append(plan.Directives, resync(eventsv1.Directive_RESYNC_PROXIES, "unknown route digest"))
	}
	return plan
}

func clone(s State) State {
	d := make(map[string]string, len(s.Digests))
	for k, v := range s.Digests {
		d[k] = v
	}
	s.Digests = d
	r := make(map[string]bool, len(s.Retired))
	for k := range s.Retired {
		r[k] = true
	}
	s.Retired = r
	return s
}

// advance applies one sequenced event to the run cursor and sets the item's verdict
// (Store, Duplicate; Reject is kept) and any gap.
func advance(cur *State, seq *eventsv1.Sequence, it *Item, plan *Plan) {
	reject := it.Verdict == Reject
	setVerdict := func(v Verdict) {
		if !reject {
			it.Verdict = v
		}
	}
	r := &cur.Run
	if seq.GetRunId() != r.ID {
		switch {
		case cur.Retired[seq.GetRunId()],
			r.ID != "" && seq.GetBootId() == r.BootID && seq.GetRunNumber() <= r.RunNumber:
			// A run a newer one replaced, or an older run of the same boot: history,
			// answered as duplicates.
			it.Stale = true
			setVerdict(Duplicate)
			return
		}
		if r.ID != "" {
			it.Retired = true
			cur.Retired[r.ID] = true
		}
		*r = Run{ID: seq.GetRunId(), BootID: seq.GetBootId(), RunNumber: seq.GetRunNumber()}
		cur.HeartbeatStoredAt, cur.HeartbeatFields = time.Time{}, ""
		cur.Digests = map[string]string{}
	}
	switch s := seq.GetSeq(); {
	case s <= r.LastSeq:
		setVerdict(Duplicate)
	case s == r.LastSeq+1:
		r.LastSeq = s
	default:
		plan.Gaps = append(plan.Gaps, Gap{RunID: r.ID, From: r.LastSeq + 1, To: s - 1})
		r.LastSeq = s
	}
}

func heartbeatFields(h *eventsv1.Heartbeat) string {
	c := &eventsv1.Heartbeat{
		Tamper: h.GetTamper(), FirewallFingerprint: h.FirewallFingerprint,
		AgentVersion: h.GetAgentVersion(), ExeSha256: h.GetExeSha256(), StateDigest: h.GetStateDigest(),
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		return "unmarshalable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
