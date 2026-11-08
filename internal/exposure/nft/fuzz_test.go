package nft

import (
	"bytes"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

// nftBudget bounds one Parse. The agent caps nft's output at 64 MiB (exposure.toolMaxOutput);
// a fuzz input is far smaller, so this bounds the parse itself. The seeds allocate at most
// 22 bytes per input byte (1.4 MiB for 64 KiB): this is over 10 times that.
var nftBudget = fuzzcheck.Budget{Time: 2 * time.Second, Base: 4 << 20, PerByte: 256}

// Anyone able to load nf_tables rules shapes the `nft -j list ruleset` the privileged
// agent parses: any document must parse or fail without a panic, within budget, and
// never yield more rules or chains than the document has objects.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzcheck.Files(f, "testdata/*.json", "../testdata/*nft*.json") {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var rs *Ruleset
		var err error
		fuzzcheck.Bounded(t, nftBudget, len(data), func() { rs, err = Parse(data) })
		if err != nil {
			return
		}
		objects := bytes.Count(data, []byte("{"))
		rules := 0
		for _, c := range rs.Chains {
			rules += len(c.Rules)
		}
		if len(rs.Chains) > objects || rules > objects {
			t.Errorf("%d chains and %d rules from a document with %d objects", len(rs.Chains), rules, objects)
		}
	})
}
