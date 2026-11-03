package exposure

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func digestOf(t *testing.T, in MergeInput) string {
	t.Helper()
	fw, err := Merge(in)
	if err != nil {
		t.Fatal(err)
	}
	return NewView(TriggerStart, 0, fw, nil, nil, nil).FirewallDigest()
}

func TestFirewallDigestStable(t *testing.T) {
	full := MergeInput{
		NFT:  readFixture(t, "docker-iptables-nft.json"),
		IPT4: readFixture(t, "docker-iptables-nft.v4.txt"),
		IPT6: readFixture(t, "docker-iptables-nft.v6.txt"),
	}
	a, b := digestOf(t, full), digestOf(t, full) // two separate parses of the same rules
	if !hex64.MatchString(a) {
		t.Fatalf("digest %q is not 64 lowercase hex", a)
	}
	if a != b {
		t.Fatalf("same rules, different digests: %s %s", a, b)
	}
	counters := full
	counters.IPT4 = []byte(strings.ReplaceAll(strings.ReplaceAll(string(full.IPT4), "[0:0]", "[7:999]"), "Mon Nov", "Tue Nov"))
	if string(counters.IPT4) == string(full.IPT4) {
		t.Fatal("fixture has no counters to vary")
	}
	if got := digestOf(t, counters); got != a {
		t.Fatalf("counters or dump timestamps changed the digest: %s, want %s", got, a)
	}
	other := full
	other.IPT4 = readFixture(t, "ufw-docker.v4.txt")
	if got := digestOf(t, other); got == a {
		t.Fatal("different rules, same digest")
	}
}

func TestFirewallDigestIsNotRuleText(t *testing.T) {
	fw, err := Merge(MergeInput{IPT4: readFixture(t, "ufw-docker.v4.txt")})
	if err != nil {
		t.Fatal(err)
	}
	d := NewView(TriggerStart, 0, fw, nil, nil, nil).FirewallDigest()
	if !hex64.MatchString(d) || strings.Contains(fw.Fingerprint, d) {
		t.Fatalf("digest %q is not a fixed-length digest of the internal fingerprint %q", d, fw.Fingerprint)
	}
}

func TestFirewallDigestEmptyWhenUnreadable(t *testing.T) {
	v := NewView(TriggerStart, 0, nil, errors.New("nft: Operation not permitted"), nil, nil)
	if d := v.FirewallDigest(); d != "" {
		t.Fatalf("unreadable firewall: digest %q, want empty", d)
	}
	if c := strings.Join(v.Conditions(), ";"); !strings.Contains(c, "fw:unreadable") {
		t.Fatalf("an empty digest must come with an fw:unreadable condition, got %q", c)
	}
	partial := MergeInput{NFT: []byte(`{"nftables":[]}`), IPT4Err: errors.New("iptables-save: Permission denied")}
	if d := digestOf(t, partial); d != "" {
		t.Fatalf("partly read firewall: digest %q, want empty", d)
	}
}
