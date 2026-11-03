package inventory

import (
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
)

// Firewall is a host's published firewall fingerprint (M7) and when it last changed.
type Firewall struct {
	// Known is false until an agent message carried a fingerprint.
	Known bool
	// Fingerprint is the agent's digest of its ruleset; "" while its firewall cannot be
	// read in full (the host's fw:unreadable condition says why).
	Fingerprint string
	// ChangedAt is when the stored value last differed from the one before it; first
	// sight sets it too.
	ChangedAt time.Time
}

// Observe applies one agent message's fingerprint seen at at (the stream's time). It
// returns the new state, whether it must be written (anything differs), and whether the
// value changed (false on first sight, which sets ChangedAt but is not a change). The
// consumer applies a host's messages in run and sequence order and skips stale ones, so
// a late message never reaches Observe.
func (f Firewall) Observe(fp string, at time.Time) (next Firewall, write, changed bool) {
	if f.Known && f.Fingerprint == fp {
		return f, false, false
	}
	return Firewall{Known: true, Fingerprint: fp, ChangedAt: at}, true, f.Known
}

// FirewallFingerprint returns the firewall fingerprint an agent message carries: the
// heartbeat's own field or the host block's (snapshot, listener, exposure and
// host.changed events). ok is false when the message carries none (an agent without M7,
// a message without a host block) or comes from the backend (a cloud verdict).
func FirewallFingerprint(m proto.Message) (fp string, ok bool) {
	var p *string
	switch e := m.(type) {
	case *asmv1.Heartbeat:
		p = e.FirewallFingerprint
	case *asmv1.Snapshot:
		p = hostFirewall(e.GetHost())
	case *asmv1.ListenerEvent:
		p = hostFirewall(e.GetHost())
	case *asmv1.ExposureEvent:
		if e.GetOrigin() != bus.OriginAgent {
			return "", false
		}
		p = hostFirewall(e.GetHost())
	case *asmv1.HostEvent:
		p = hostFirewall(e.GetHost())
	}
	if p == nil {
		return "", false
	}
	return *p, true
}

func hostFirewall(h *asmv1.HostInfo) *string {
	if h == nil {
		return nil
	}
	return h.FirewallFingerprint
}
