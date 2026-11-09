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

// Whoever answers on an HAProxy stats socket controls "show servers state": any answer
// (the reader caps it at conf.MaxTotalBytes) must parse and fold into routes without a
// panic, within the budget, and the overlay must never drop a file backend.
func FuzzServersState(f *testing.F) {
	f.Add([]byte(header + stateLine("app", "s1", "127.0.0.1", "2", "0", "8000") + stateLine("app", "s2", "-", "0", "32", "0")))
	f.Add([]byte("1\n# srv_port be_name srv_name srv_addr srv_admin_state srv_op_state\n8000 app web1 ::1 8 2\n"))
	for _, s := range fuzzcheck.Files(f, "testdata/*/servers-state.txt") {
		f.Add(s)
	}
	file := Load(conf.MemFS{DefaultConfig: []byte("frontend f\n bind :80\n default_backend app\nbackend app\n server s1 127.0.0.1:8000\n server-template web 3 127.0.0.1:8100\n")}, []string{DefaultConfig})
	f.Fuzz(func(t *testing.T, data []byte) {
		var out []conf.Route
		fuzzcheck.Bounded(t, fuzzcheck.ProxyBudget, len(data), func() {
			rs, _ := ParseServersState(data)
			out = Overlay(file.Routes, rs)
		})
		for i := range file.Routes {
			if len(out[i].Backends) < len(file.Routes[i].Backends) {
				t.Fatalf("overlay dropped backends: %d < %d", len(out[i].Backends), len(file.Routes[i].Backends))
			}
		}
	})
}
