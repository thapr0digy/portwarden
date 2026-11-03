package publish

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNextRunNumber(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	for want := uint64(1); want <= 3; want++ {
		n, err := NextRunNumber(dir)
		if err != nil || n != want {
			t.Fatalf("got %d %v, want %d", n, err, want)
		}
	}
	if n, _ := NextRunNumber(""); n != 0 {
		t.Fatal("no spool dir must give 0")
	}
	os.WriteFile(filepath.Join(dir, runCounterFile), []byte("junk"), 0o600)
	if _, err := NextRunNumber(dir); err == nil {
		t.Fatal("a corrupt counter must be an error")
	}
	b := filepath.Join(t.TempDir(), "boot_id")
	os.WriteFile(b, []byte("abc-123\n"), 0o644)
	if ReadBootID(b) != "abc-123" || ReadBootID("/nonexistent") != "" {
		t.Fatal("boot id")
	}
}
