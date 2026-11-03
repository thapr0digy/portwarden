package inventory

import (
	"time"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
	"github.com/thapr0digy/portwarden/internal/backend/bus"
)

// Firewall is a host's published firewall fingerprint (M7) and when it last changed.
type Firewall struct {
	// Known is false until an agent message carried a non-empty fingerprint.
	Known bool
	// Fingerprint is the agent's digest of its ruleset (64 lowercase hex characters).
	Fingerprint string
	// ChangedAt is the stream time (when the backend received it, not when the rule
	// changed) of the message whose fingerprint differed from the stored one; first
	// sight sets it too.
	ChangedAt time.Time
}

// Observe applies one agent message's fingerprint seen at at (the stream's time). It
// returns the new state, whether it must be written (anything differs), and whether the
// value changed (false on first sight, which sets ChangedAt but is not a change). An
// empty fingerprint (the agent could not read its firewall in full; the host's
// fw:unreadable condition says so) is unknown, not a value: the last good one is kept,
// so ChangedAt moves only for a real rule change (X, "", X is no change). The consumer
// applies a host's messages in run and sequence order and skips stale ones, so a late
// message never reaches Observe.
func (f Firewall) Observe(fp string, at time.Time) (next Firewall, write, changed bool) {
	if fp == "" || (f.Known && f.Fingerprint == fp) {
		return f, false, false
	}
	return Firewall{Known: true, Fingerprint: fp, ChangedAt: at}, true, f.Known
}

// ValidFirewallFingerprint reports whether fp is what an agent sends: "" or exactly 64
// lowercase hex characters (a SHA-256).
func ValidFirewallFingerprint(fp string) bool {
	if fp == "" {
		return true
	}
	if len(fp) != 64 {
		return false
	}
	for i := 0; i < len(fp); i++ {
		if c := fp[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// FirewallFingerprint returns the firewall fingerprint an agent message carries: the
// heartbeat's own field or the host block's of a snapshot, listener, exposure or
// host.changed event (proxy.routes host blocks are not read; the inventory keeps no host
// state from them). ok is false when the message carries none (an agent without M7, a
// message without a host block) or comes from the backend (a cloud verdict). The value
// is not validated (ValidFirewallFingerprint).
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
