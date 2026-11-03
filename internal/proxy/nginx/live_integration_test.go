//go:build linux && integration

package nginx

import (
	"os/exec"
	"slices"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

// The loader, reading the host's own /etc/nginx through openat2(RESOLVE_IN_ROOT), loads
// what `nginx -T` dumps right now.
func TestLoaderMatchesLiveNginxDump(t *testing.T) {
	bin, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx not installed")
	}
	out, err := exec.Command(bin, "-T").Output()
	if err != nil {
		t.Fatalf("nginx -T: %v", err)
	}
	main, files, order, err := ParseDump(out)
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := rootfs.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	res := Load(fsys, main)
	if !slices.Equal(res.Files, order) {
		t.Fatalf("files = %v\nnginx -T = %v", res.Files, order)
	}
	for _, f := range res.Files {
		got, err := fsys.ReadFile(f)
		if err != nil || string(got) != string(files[f]) {
			t.Errorf("%s differs from the dump (%v)", f, err)
		}
	}
}
