package caddy

import (
	"testing"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// Whoever answers on Caddy's admin endpoint controls the /config/ answer (the reader
// caps it at conf.MaxTotalBytes): any bytes must parse without a panic, within the
// proxy budget and the conf limits.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzcheck.Files(f, "testdata/*/config.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"apps":{"http":{"servers":{"s":{"listen":[":80"],"routes":[{"match":[{"host":["a"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"unix//x"}]}]}]}]}]}}}}}`))
	names := conf.LoadNames(nil)
	f.Fuzz(func(t *testing.T, data []byte) {
		var res conf.Result
		fuzzcheck.Bounded(t, fuzzcheck.ProxyBudget, len(data), func() { res, _ = Parse(data, "127.0.0.1:2019", names) })
		if len(res.Routes) > MaxRoutes {
			t.Errorf("%d routes, limit %d", len(res.Routes), MaxRoutes)
		}
		if len(res.Notes) > conf.MaxNotes {
			t.Errorf("%d notes, limit %d", len(res.Notes), conf.MaxNotes)
		}
	})
}
