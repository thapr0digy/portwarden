package tamper

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDpkg(t *testing.T) {
	dir := t.TempDir()
	d := &Dpkg{Package: "portwarden-agent", Marker: filepath.Join(dir, "upgrading"), InfoDir: dir,
		Status: filepath.Join(dir, "status"), MaxAge: 10 * time.Minute, Now: time.Now}
	if _, ok := d.Upgrading(); ok {
		t.Fatal("no marker, no upgrade")
	}
	write(t, d.Marker, "1.2.0-1\n")
	if v, ok := d.Upgrading(); !ok || v != "1.2.0-1" {
		t.Fatalf("marker: %q %v", v, ok)
	}
	write(t, d.Status, "Package: other\nVersion: 1.2.0-1\n\nPackage: portwarden-agent\nStatus: install ok unpacked\nVersion: 1.2.0-1\n\n")
	write(t, filepath.Join(dir, "portwarden-agent.md5sums"), "0123  usr/bin/portwarden-agent\n4567  usr/lib/systemd/system/portwarden-agent.service\n")
	if !d.Ships("1.2.0-1", "/usr/bin/portwarden-agent", "0123") || d.Ships("1.2.0-1", "/usr/bin/portwarden-agent", "9999") ||
		d.Ships("1.1.0-1", "/usr/bin/portwarden-agent", "0123") || d.Ships("1.2.0-1", "/etc/passwd", "0123") {
		t.Fatal("Ships")
	}
	// A stale marker (a failed upgrade long ago) is no upgrade.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(d.Marker, old, old); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Upgrading(); ok {
		t.Fatal("a stale marker must be ignored")
	}
}
