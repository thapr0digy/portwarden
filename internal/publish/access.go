package publish

import (
	"fmt"
	"strings"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/thapr0digy/portwarden/internal/spool"
)

// Host identity facts (README "Host identity facts") exist only in Signal's schema: they
// are spooled as Signal events (eventsv1.Event with the run cursor filled in) under
// asm.<host>.<suffix>, and never sent to NATS, whose consumers and per-host permissions do
// not know them.
const (
	suffixHostAccess = "host.access"
	suffixSignIns    = "host.sign_ins"
)

// signalOnly reports whether a spooled subject is a Signal-only event.
func signalOnly(subject string) bool {
	return strings.HasSuffix(subject, "."+suffixHostAccess) || strings.HasSuffix(subject, "."+suffixSignIns)
}

// HostAccess queues asm.host.access: the full state, or only its digest (unchanged) when
// it equals the last full state queued this run. The full state is kept and queued again
// with every resnapshot (Signal's RESYNC_SNAPSHOT asks for both).
func (p *Publisher) HostAccess(a *eventsv1.HostAccess) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.access != nil && a.GetDigest() != "" && a.GetDigest() == p.access.GetDigest() {
		p.enqueueSignalLocked(suffixHostAccess, &eventsv1.Event{Data: &eventsv1.Event_HostAccess{
			HostAccess: &eventsv1.HostAccess{Digest: a.GetDigest(), Unchanged: true}}})
		return
	}
	p.access = proto.CloneOf(a)
	p.enqueueAccessLocked()
}

func (p *Publisher) enqueueAccessLocked() {
	p.enqueueSignalLocked(suffixHostAccess, &eventsv1.Event{Data: &eventsv1.Event_HostAccess{HostAccess: p.access}})
}

// SignIns queues asm.host.sign_ins.
func (p *Publisher) SignIns(s *eventsv1.SignInSummary) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enqueueSignalLocked(suffixSignIns, &eventsv1.Event{Data: &eventsv1.Event_SignIns{SignIns: s}})
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
