package reach

import (
	"net/netip"
	"slices"
	"testing"
)

func cidrs(s Set) []string {
	var out []string
	for _, p := range s.CIDRs() {
		out = append(out, p.String())
	}
	return out
}

func TestSetOps(t *testing.T) {
	a := MustParse("10.0.0.0/24", "10.0.1.0/24") // adjacent: merged
	if got := cidrs(a); !slices.Equal(got, []string{"10.0.0.0/23"}) {
		t.Fatalf("union %v", got)
	}
	b := a.Subtract(MustParse("10.0.0.128/25"))
	if got := cidrs(b); !slices.Equal(got, []string{"10.0.0.0/25", "10.0.1.0/24"}) {
		t.Fatalf("subtract %v", got)
	}
	if got := cidrs(b.Intersect(MustParse("10.0.1.64/26", "192.0.2.0/24"))); !slices.Equal(got, []string{"10.0.1.64/26"}) {
		t.Fatalf("intersect %v", got)
	}
	if !MustParse("0.0.0.0/0").Subtract(MustParse("0.0.0.0/1", "128.0.0.0/1")).IsEmpty() {
		t.Fatal("two halves do not cover the whole")
	}
	if got := cidrs(MustParse("0.0.0.0/1", "128.0.0.0/1")); !slices.Equal(got, []string{"0.0.0.0/0"}) {
		t.Fatalf("halves %v", got)
	}
	if !MustParse("::/0").Intersect(MustParse("0.0.0.0/0")).IsEmpty() {
		t.Fatal("::/0 holds IPv4")
	}
	// The families never overlap.
	if !MustParse("0.0.0.0/0").Intersect(All(V6)).IsEmpty() {
		t.Fatal("IPv4 inside IPv6")
	}
	if got := cidrs(MustParse("::/0").Subtract(MustParse("::/1"))); !slices.Equal(got, []string{"8000::/1"}) {
		t.Fatalf("v6 subtract %v", got)
	}
}

// The user's rule (M10 review): open unless every allowed source is private or in the
// operator's VPN ranges.
func TestPolicyUserRule(t *testing.T) {
	p := NewPolicy(nil)
	cases := []struct {
		name    string
		allowed Set
		open    bool
	}{
		{"anywhere", MustParse("0.0.0.0/0"), true},
		{"an office's public /32 is the internet", MustParse("81.2.69.160/32"), true},
		{"rfc1918", MustParse("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"), false},
		{"cgnat", MustParse("100.64.0.0/10"), false},
		{"ula", MustParse("fc00::/7"), false},
		{"documentation ranges are not the internet", MustParse("203.0.113.0/24", "2001:db8::/32"), false},
		{"v6 anywhere", MustParse("::/0"), true},
		{"global v6 /64", MustParse("2a00:1450:4001::/64"), true},
		{"nothing", Set{}, false},
	}
	for _, c := range cases {
		if got := !p.Exposed(c.allowed).IsEmpty(); got != c.open {
			t.Errorf("%s: open=%v", c.name, got)
		}
	}
	vpn := NewPolicy([]netip.Prefix{netip.MustParsePrefix("81.2.69.160/28")})
	if !vpn.Exposed(MustParse("81.2.69.160/32")).IsEmpty() {
		t.Error("a VPN-listed address counted as the internet")
	}
	if vpn.Exposed(MustParse("81.2.69.0/24")).IsEmpty() {
		t.Error("a range wider than the VPN list counted as closed")
	}
}

func TestDescribe(t *testing.T) {
	p := NewPolicy(nil)
	if got := p.Describe(p.Exposed(MustParse("0.0.0.0/0")), 4); got != "0.0.0.0/0" {
		t.Errorf("v4 anywhere: %q", got)
	}
	if got := p.Describe(p.Exposed(MustParse("::/0")), 4); got != "::/0" {
		t.Errorf("v6 anywhere: %q", got)
	}
	if got := p.Describe(MustParse("81.2.69.160/32"), 4); got != "81.2.69.160/32" {
		t.Errorf("one range: %q", got)
	}
	if got := p.Describe(MustParse("1.0.0.0/32", "1.0.0.2/32", "1.0.0.4/32"), 2); got != "1.0.0.0/32, 1.0.0.2/32, +1 more" {
		t.Errorf("capped: %q", got)
	}
}

func TestParseVPN(t *testing.T) {
	ps, err := ParseVPN([]string{" 81.2.69.161/28 ", "2a00::/16"})
	if err != nil || ps[0].String() != "81.2.69.160/28" {
		t.Fatalf("%v %v", ps, err)
	}
	if _, err := ParseVPN([]string{"not-a-cidr"}); err == nil {
		t.Fatal("bad cidr accepted")
	}
}
