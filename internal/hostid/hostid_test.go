package hostid

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "machine-id")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadTrimsAndAccepts(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	got, err := Read(write(t, id+"\n"))
	if err != nil || got != id {
		t.Fatalf("Read = %q, %v; want %q", got, err, id)
	}
}

func TestHostIDRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"abc", "", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef0123456789abcdeg", "0123456789abcdef0123456789abcdef00"} {
		if got, err := Read(write(t, bad)); err == nil {
			t.Errorf("Read(%q) = %q, want error", bad, got)
		}
	}
}

func TestReadMissingFile(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("want error for missing file")
	}
}
