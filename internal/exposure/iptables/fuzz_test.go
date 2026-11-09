package iptables

import (
	"bytes"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/exposure/firewall"
	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

// iptablesBudget bounds one Parse; the agent caps the tool's output at 64 MiB. The seeds
// allocate at most 21 bytes per input byte: this is over 10 times that.
var iptablesBudget = fuzzcheck.Budget{Time: 2 * time.Second, Base: 4 << 20, PerByte: 256}

// Anyone able to load iptables rules shapes the iptables-save output the privileged
// agent parses: any dump must parse or fail without a panic, within budget, and never
// yield more rules or chains than it has lines.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzcheck.Files(f, "../testdata/*.v4.txt") {
		f.Add(s, false)
	}
	for _, s := range fuzzcheck.Files(f, "../testdata/*.v6.txt") {
		f.Add(s, true)
	}
	for _, s := range fuzzcheck.Files(f, "../testdata/kube-proxy.restore") {
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, data []byte, v6 bool) {
		fam := firewall.FamilyIP
		if v6 {
			fam = firewall.FamilyIP6
		}
		var rs *Ruleset
		var err error
		fuzzcheck.Bounded(t, iptablesBudget, len(data), func() { rs, err = Parse(data, fam) })
		if err != nil {
			return
		}
		lines := bytes.Count(data, []byte("\n")) + 1
		rules := 0
		for _, c := range rs.Chains {
			rules += len(c.Rules)
		}
		if len(rs.Chains) > lines || rules > lines {
			t.Errorf("%d chains and %d rules from %d lines", len(rs.Chains), rules, lines)
		}
	})
}
