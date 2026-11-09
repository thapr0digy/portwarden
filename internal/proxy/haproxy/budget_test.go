package haproxy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// A container's HAProxy config is the image author's: dense config files given together
// read up to conf.MaxTotalBytes, within every limit. That load must fit
// fuzzcheck.ProxyBudget and the agent's memory (fuzzcheck.ProxyHeapLimit).
func TestLoadAtTheReadLimitFitsBudgetAndMemory(t *testing.T) {
	block := "frontend f\n  bind :80\n  use_backend b if { hdr(host) -i a.example }\n  default_backend b\nbackend b\n  server s 127.0.0.1:9000\n"
	big := []byte(strings.Repeat(block, (1<<20)/len(block)))
	fsys := conf.MemFS{}
	var paths []string
	for i := range 2 * conf.MaxTotalBytes / len(big) {
		p := fmt.Sprintf("/etc/haproxy/conf.d/%02d.cfg", i)
		fsys[p] = big
		paths = append(paths, p)
	}
	fuzzcheck.AtReadLimit(t, func() conf.Result { return Load(fsys, paths) })
}
