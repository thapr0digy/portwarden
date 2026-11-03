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

// Golden digests: the published value must be the same in every process and release for
// the same rules (an agent restart must not look like a rule change). A change to the
// canonical encoding changes these on purpose, and moves every host's changed_at once.
func TestFirewallDigestGolden(t *testing.T) {
	cases := []struct {
		name, want string
		in         MergeInput
		addrs      []string // address-bearing values that must appear in the canonical text
	}{
		{"iptables-save with DNAT targets", "e00b53db0c53b8dc4332e6e208f27727de1d166861b82ac3a8e9f343aac03332",
			MergeInput{IPT4: readFixture(t, "docker-iptables-nft.v4.txt")}, []string{"172.17.0.2", "172.17.0.0/16"}},
		{"native nft host firewall", "514199ac07b8d9e85d19e9621cfb023646dfee35346bfa55075e851e66e9bd41",
			MergeInput{NFT: readFixture(t, "../nft/testdata/host-firewall.json")}, []string{"10.0.0.0/8", "fe80::/10"}},
	}
	for _, c := range cases {
		fw, err := Merge(c.in)
		if err != nil {
			t.Fatal(err)
		}
		canon := fw.Rules.Canonical()
		if i := strings.Index(canon, "0x"); i >= 0 {
			t.Errorf("%s: canonical text holds a pointer or hex dump near %q", c.name, canon[max(0, i-40):min(len(canon), i+40)])
		}
		if strings.Contains(canon, "expr type=") {
			t.Errorf("%s: an expression type has no canonical encoding", c.name)
		}
		for _, a := range c.addrs {
			if !strings.Contains(canon, a) {
				t.Errorf("%s: canonical text lacks %s", c.name, a)
			}
		}
		if got := NewView(TriggerStart, 0, fw, nil, nil, nil).FirewallDigest(); got != c.want {
			t.Errorf("%s: digest %s, want %s", c.name, got, c.want)
		}
	}
}
