package inventory

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

// MaxAgentVersionBytes caps a stored agent version; the agent sends a short release
// string ("1.4.0", "dev"), so anything longer is cut.
const MaxAgentVersionBytes = 64

// Identity is what an agent message says about the agent itself (M11): its version, the
// SHA-256 of its executable, and whether the message is the run's clean-shutdown marker.
// Self-reported by the host: a visibility aid, not attestation.
type Identity struct {
	Version   string
	ExeSHA256 string
	Stopping  bool
}

// AgentIdentity returns the identity an agent message carries: a heartbeat's own fields,
// or the host block of a snapshot or host.changed event (a stopping host.changed is the
// clean-shutdown marker). ok is false for other messages and for those without a host
// block. Empty values (an older agent, an unread executable) are returned as they are:
// the latest message is the truth. The values are not cleaned (CleanIdentity).
func AgentIdentity(m proto.Message) (Identity, bool) {
	switch e := m.(type) {
	case *asmv1.Heartbeat:
		return Identity{Version: e.GetAgentVersion(), ExeSHA256: e.GetExeSha256()}, true
	case *asmv1.Snapshot:
		if h := e.GetHost(); h != nil {
			return Identity{Version: h.GetAgentVersion(), ExeSHA256: h.GetExeSha256()}, true
		}
	case *asmv1.HostEvent:
		if h := e.GetHost(); h != nil {
			return Identity{Version: h.GetAgentVersion(), ExeSHA256: h.GetExeSha256(), Stopping: e.GetStopping()}, true
		}
	}
	return Identity{}, false
}

// CleanIdentity makes an identity safe to store and show: the version loses control and
// non-printable characters (invalid UTF-8 included) and is cut to MaxAgentVersionBytes on
// a character boundary; a hash that is not "" or exactly 64 lowercase hex characters is
// dropped (badHash true, so the caller can log it).
func CleanIdentity(id Identity) (out Identity, badHash bool) {
	out = Identity{Version: CleanAgentVersion(id.Version), Stopping: id.Stopping}
	if ValidExeSHA256(id.ExeSHA256) {
		out.ExeSHA256 = id.ExeSHA256
	} else {
		badHash = true
	}
	return out, badHash
}

// CleanAgentVersion drops control, non-printable and invalid characters from v and cuts
// it to MaxAgentVersionBytes on a character boundary.
func CleanAgentVersion(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		i += size
		if (r == utf8.RuneError && size <= 1) || !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > MaxAgentVersionBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ValidExeSHA256 reports whether h is what an agent sends: "" (unread) or a SHA-256 as
// 64 lowercase hex characters (the same shape as a firewall fingerprint).
func ValidExeSHA256(h string) bool { return ValidFirewallFingerprint(h) }
