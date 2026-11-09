package haproxy

import (
	"testing"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// A hostile container image controls the HAProxy config the agent reads: any file tree
// must load without a panic, within the time and memory budget and the conf limits.
func FuzzLoad(f *testing.F) {
	for _, s := range fuzzcheck.ProxySeeds(f, "etc/*/haproxy.cfg") {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		main, fsys := conf.DecodeFiles(data)
		var res conf.Result
		fuzzcheck.Bounded(t, fuzzcheck.ProxyBudget, len(data), func() { res = Load(fsys, []string{main}) })
		fuzzcheck.ProxyResult(t, res)
	})
}
