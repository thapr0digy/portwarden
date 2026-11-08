package apache

import (
	"path"
	"testing"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// A hostile container image controls the Apache config the agent reads: any file tree
// must load without a panic, within the time and memory budget and the conf limits.
// The main file's directory is the ServerRoot, as for Debian's /etc/apache2.
func FuzzLoad(f *testing.F) {
	for _, s := range fuzzcheck.ProxySeeds(f, "etc/*/"+DebianConfig) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		main, fsys := conf.DecodeFiles(data)
		o := Options{ServerRoot: path.Dir(main), ConfigFile: path.Base(main), Env: ubuntuEnv}
		var res conf.Result
		fuzzcheck.Bounded(t, fuzzcheck.ProxyBudget, len(data), func() { res = Load(fsys, o) })
		fuzzcheck.ProxyResult(t, res)
	})
}
