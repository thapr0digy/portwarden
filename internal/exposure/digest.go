package exposure

import (
	"crypto/sha256"
	"encoding/hex"
)

// FirewallDigest is what the agent publishes of its firewall fingerprint: lowercase hex
// SHA-256 of the internal fingerprint (the parsed rules; counters and dump timestamps
// excluded), so a rule change that moves no listener is still visible and no rule text
// leaves the host. It is empty while the firewall cannot be read in full: a digest of
// part of the ruleset would change when the missing part came back, and the
// "fw:unreadable" condition already says what is missing.
func (v *View) FirewallDigest() string {
	if v.fw == nil || len(v.fw.Partial) > 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(v.fw.Fingerprint))
	return hex.EncodeToString(sum[:])
}
