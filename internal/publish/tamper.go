package publish

import (
	"maps"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/tamper"
)

// SetTamper replaces the tamper status carried on later heartbeats.
func (p *Publisher) SetTamper(st tamper.Status) {
	ps := tamperStatusToProto(st)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tamper = ps
}

// Tamper enqueues one asm.<host>.tamper event for a pass that raised or cleared flags.
func (p *Publisher) Tamper(tr tamper.Transition) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, seq := p.nextIDLocked()
	at := tr.Status.CheckedAt
	if at.IsZero() {
		at = time.Now()
	}
	p.enqueueLocked("tamper", id, seq, &asmv1.TamperEvent{
		EventId: id,
		HostId:  p.hostID,
		RunId:   p.runID, BootId: p.bootID, RunNumber: p.runNumber,
		Seq:        seq,
		ObservedAt: timestamppb.New(at),
		Status:     tamperStatusToProto(tr.Status),
		Raised:     tamperFlagsToProto(tr.Raised),
		Cleared:    tamperFlagsToProto(tr.Cleared),
	})
}

// tamperLocked is the status for a heartbeat: a copy, so the heartbeat owns its message.
func (p *Publisher) tamperLocked() *asmv1.TamperStatus {
	if p.tamper == nil {
		return nil
	}
	return proto.Clone(p.tamper).(*asmv1.TamperStatus)
}

func tamperStatusToProto(st tamper.Status) *asmv1.TamperStatus {
	out := &asmv1.TamperStatus{
		Flags:        tamperFlagsToProto(st.Flags),
		Checks:       append([]string(nil), st.Checks...),
		Unknown:      append([]string(nil), st.Unknown...),
		RingbufDrops: st.RingbufDrops,
	}
	if !st.CheckedAt.IsZero() {
		out.CheckedAt = timestamppb.New(st.CheckedAt)
	}
	if len(st.RunCounts) > 0 {
		out.ProgRunCounts = maps.Clone(st.RunCounts)
	}
	return out
}

func tamperFlagsToProto(flags []tamper.Flag) []*asmv1.TamperFlag {
	out := make([]*asmv1.TamperFlag, 0, len(flags))
	for _, f := range flags {
		pf := &asmv1.TamperFlag{Kind: f.Kind, Subject: f.Subject, Detail: f.Detail, Fingerprint: f.Fingerprint, Info: f.Info}
		if !f.Since.IsZero() {
			pf.Since = timestamppb.New(f.Since)
		}
		out = append(out, pf)
	}
	return out
}
