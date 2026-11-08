package inventory

import (
	"strings"
	"testing"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

func TestAgentIdentityFromMessages(t *testing.T) {
	hash := strings.Repeat("a", 64)
	if id, ok := AgentIdentity(&asmv1.Heartbeat{AgentVersion: "1.0.0", ExeSha256: hash}); !ok || id.Version != "1.0.0" || id.ExeSHA256 != hash || id.Stopping {
		t.Errorf("heartbeat: %+v %v", id, ok)
	}
	if id, ok := AgentIdentity(&asmv1.Heartbeat{}); !ok || id != (Identity{}) {
		t.Errorf("old heartbeat must report empty identity, got %+v %v", id, ok)
	}
	if id, ok := AgentIdentity(&asmv1.Snapshot{Host: &asmv1.HostInfo{AgentVersion: "1.0.0"}}); !ok || id.Version != "1.0.0" {
		t.Errorf("snapshot: %+v %v", id, ok)
	}
	if _, ok := AgentIdentity(&asmv1.Snapshot{}); ok {
		t.Error("snapshot without a host block carries no identity")
	}
	if id, ok := AgentIdentity(&asmv1.HostEvent{Host: &asmv1.HostInfo{AgentVersion: "1.0.0"}, Stopping: true}); !ok || !id.Stopping {
		t.Errorf("stopping host event: %+v %v", id, ok)
	}
	if _, ok := AgentIdentity(&asmv1.ListenerEvent{Host: &asmv1.HostInfo{AgentVersion: "1.0.0"}}); ok {
		t.Error("listener events are not read for identity")
	}
}

// Hostile input: the host controls both values.
func TestIdentityHostile(t *testing.T) {
	big := strings.Repeat("v", 1<<20)
	if got := CleanAgentVersion(big); len(got) != MaxAgentVersionBytes {
		t.Errorf("1 MiB version kept %d bytes", len(got))
	}
	if got := CleanAgentVersion("1.0\x00\n\x1b[31m‮-rc\xff"); got != "1.0[31m-rc" {
		t.Errorf("control, bidi and invalid characters kept: %q", got)
	}
	// Cut on a character boundary: 63 ASCII bytes then a 3-byte rune.
	if got := CleanAgentVersion(strings.Repeat("a", 63) + "€"); got != strings.Repeat("a", 63) {
		t.Errorf("cut mid-character: %q", got)
	}
	good := strings.Repeat("0123456789abcdef", 4)
	for _, h := range []string{strings.ToUpper(good), good[:63], good + "0", strings.Repeat("z", 64), big} {
		id, bad := CleanIdentity(Identity{Version: "1", ExeSHA256: h})
		if !bad || id.ExeSHA256 != "" {
			t.Errorf("hash %.70q kept (%q, bad=%v)", h, id.ExeSHA256, bad)
		}
	}
	for _, h := range []string{"", good} {
		if id, bad := CleanIdentity(Identity{ExeSHA256: h, Stopping: true}); bad || id.ExeSHA256 != h || !id.Stopping {
			t.Errorf("valid hash %q: %+v bad=%v", h, id, bad)
		}
	}
}
