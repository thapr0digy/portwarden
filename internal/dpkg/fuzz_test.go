package dpkg

import (
	"testing"
	"testing/fstest"
	"time"

	"github.com/slidehq/signal/schema/validate"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

// parseBudget bounds one read of a fuzzed status file and os-release.
var parseBudget = fuzzcheck.Budget{Time: 2 * time.Second, Base: 4 << 20, PerByte: 256}

// FuzzReadPackages feeds a status file and an os-release to the reader. A package's fields
// come from its .deb's control file, whoever built it: the reader must never panic, stay
// bounded, and what it builds must pass Signal's validator (a refused list is a lost one).
func FuzzReadPackages(f *testing.F) {
	f.Add(ubuntuStatus, ubuntuOSRelease)
	f.Add("Package: a\nStatus: install ok installed\nSource: b (1:2)\nVersion: 1\nArchitecture: all\n", "ID=debian\nVERSION_ID='12'\n")
	f.Add("Package: x\nStatus:   hold  ok  installed \nSource: (\nVersion: \x00\nArchitecture: AMD64\n\n\n", "ID=\"ubu\\\"ntu\"\nVERSION_ID=\"\n")
	f.Fuzz(func(t *testing.T, status, osRelease string) {
		root := fstest.MapFS{
			"var/lib/dpkg/status": {Data: []byte(status)},
			"etc/os-release":      {Data: []byte(osRelease)},
		}
		fuzzcheck.Bounded(t, parseBudget, len(status)+len(osRelease), func() {
			l, _ := ReadPackages(root)
			if err := validate.Event(packagesEvent(l), validate.Options{}); err != nil {
				t.Fatalf("Signal refuses the list: %v\n%v", err, l)
			}
		})
	})
}
