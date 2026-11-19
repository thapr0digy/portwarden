package publish

import (
	"fmt"
	"slices"
	"strings"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/thapr0digy/portwarden/internal/spool"
)

// Host facts (README "Host identity facts", "Host packages", "Connection flows") exist only in
// Signal's schema:
// they are spooled as Signal events (eventsv1.Event with the run cursor filled in) under
// asm.<host>.<suffix>, and never sent to NATS, whose consumers and per-host permissions do
// not know them.
const (
	suffixHostAccess   = "host.access"
	suffixSignIns      = "host.sign_ins"
	suffixHostPackages = "host.packages"
	suffixHostFlows    = "host.flows"
)

// signalOnlySuffixes are the Signal-only kinds.
var signalOnlySuffixes = []string{suffixHostAccess, suffixSignIns, suffixHostPackages, suffixHostFlows} //nolint:gochecknoglobals // fixed table

// ridersOfSnapshot are the full states that ride with the snapshot: Signal forgets their
// digests on RESYNC_SNAPSHOT, so each is queued again with every resnapshot, in this order.
var ridersOfSnapshot = []string{suffixHostAccess, suffixHostPackages} //nolint:gochecknoglobals // fixed table

// signalOnly reports whether a spooled subject is a Signal-only event.
func signalOnly(subject string) bool {
	return slices.ContainsFunc(signalOnlySuffixes, func(s string) bool { return strings.HasSuffix(subject, "."+s) })
}

// rider is the last full state queued of one kind that rides with the snapshot.
type rider struct {
	digest string
	full   *eventsv1.Event
}

// HostAccess queues asm.host.access: the full state, or only its digest (unchanged) when
// it equals the last full state queued this run, and the full state again with every
// resnapshot.
func (p *Publisher) HostAccess(a *eventsv1.HostAccess) {
	p.queueRider(suffixHostAccess, a.GetDigest(),
		&eventsv1.Event{Data: &eventsv1.Event_HostAccess{HostAccess: proto.CloneOf(a)}},
		&eventsv1.Event{Data: &eventsv1.Event_HostAccess{HostAccess: &eventsv1.HostAccess{Digest: a.GetDigest(), Unchanged: true}}})
}

// HostPackages queues asm.host.packages by the same rule as HostAccess.
func (p *Publisher) HostPackages(l *eventsv1.HostPackages) {
	p.queueRider(suffixHostPackages, l.GetDigest(),
		&eventsv1.Event{Data: &eventsv1.Event_HostPackages{HostPackages: proto.CloneOf(l)}},
		&eventsv1.Event{Data: &eventsv1.Event_HostPackages{HostPackages: &eventsv1.HostPackages{Digest: l.GetDigest(), Unchanged: true}}})
}

// queueRider queues unchanged when digest is the last full state's of the kind (an empty
// digest never is), else full, which it keeps for the resnapshots.
func (p *Publisher) queueRider(suffix, digest string, full, unchanged *eventsv1.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if last, ok := p.riders[suffix]; ok && digest != "" && digest == last.digest {
		p.enqueueSignalLocked(suffix, unchanged)
		return
	}
	p.riders[suffix] = rider{digest: digest, full: full}
	p.enqueueSignalLocked(suffix, proto.CloneOf(full))
}

// enqueueRidersLocked queues every full state that rides with the snapshot again.
func (p *Publisher) enqueueRidersLocked() {
	for _, suffix := range ridersOfSnapshot {
		if r, ok := p.riders[suffix]; ok {
			p.enqueueSignalLocked(suffix, proto.CloneOf(r.full))
		}
	}
}

// SignIns queues asm.host.sign_ins.
func (p *Publisher) SignIns(s *eventsv1.SignInSummary) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enqueueSignalLocked(suffixSignIns, &eventsv1.Event{Data: &eventsv1.Event_SignIns{SignIns: s}})
}

// HostFlows queues asm.host.flows: one window's connections, a delta like SignIns.
func (p *Publisher) HostFlows(f *eventsv1.HostFlows) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enqueueSignalLocked(suffixHostFlows, &eventsv1.Event{Data: &eventsv1.Event_HostFlows{HostFlows: f}})
}

// enqueueSignalLocked fills in ev's type, id, time, subject and run cursor and queues it.
// ev is marshalled here, so the caller's message may change afterwards.
func (p *Publisher) enqueueSignalLocked(suffix string, ev *eventsv1.Event) {
	id, seq := p.nextIDLocked()
	ev.Id, ev.Type, ev.Time = id, "asm."+suffix, timestamppb.Now()
	ev.Subject = string(eventsv1.SchemeHost) + p.hostID
	ev.Sequence = &eventsv1.Sequence{RunId: p.runID, Seq: seq, BootId: p.bootID, RunNumber: p.runNumber}
	p.enqueueLocked(suffix, id, seq, ev)
}

// spooledSignalEvent reads a Signal-only message: the event as it was queued, checked
// against the message (type, host, id, seq) as the converted kinds are.
func spooledSignalEvent(m spool.Msg, suffix, hostID string) (*eventsv1.Event, error) {
	ev := &eventsv1.Event{}
	if err := proto.Unmarshal(m.Data, ev); err != nil {
		return nil, fmt.Errorf("%s: %w", m.Subject, err)
	}
	if ev.GetType() != "asm."+suffix || ev.GetSubject() != string(eventsv1.SchemeHost)+hostID || ev.GetId() != m.ID ||
		ev.GetTime() == nil || ev.GetSequence().GetSeq() != m.Seq {
		return nil, fmt.Errorf("%s: the event's type, host, id, time or seq does not match the message", m.Subject)
	}
	return ev, nil
}
