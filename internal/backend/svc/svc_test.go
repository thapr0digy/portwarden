package svc

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAndSecrets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	var cfg struct {
		Every Duration `json:"every"`
	}
	os.WriteFile(p, []byte(`{"every":"90s"}`), 0o600)
	if err := Load(p, &cfg); err != nil || cfg.Every.D(0) != 90*time.Second {
		t.Fatalf("%v %v", cfg, err)
	}
	os.WriteFile(p, []byte(`{"every":"90s","typo":1}`), 0o600)
	if err := Load(p, &cfg); err == nil {
		t.Fatal("unknown key accepted")
	}
	os.WriteFile(p, []byte(`{"every":"-1s"}`), 0o600)
	if err := Load(p, &cfg); err == nil {
		t.Fatal("negative duration accepted")
	}
	if Duration(0).D(time.Minute) != time.Minute {
		t.Fatal("default")
	}

	f := filepath.Join(dir, "tok")
	os.WriteFile(f, []byte("  s3cret\n"), 0o600)
	t.Setenv("PW_TEST_SECRET", "")
	if v, err := Secret("PW_TEST_SECRET", f); err != nil || v != "s3cret" {
		t.Fatalf("%q %v", v, err)
	}
	t.Setenv("PW_TEST_SECRET", "fromenv")
	if v, _ := Secret("PW_TEST_SECRET", f); v != "fromenv" {
		t.Fatal("env must win")
	}
	t.Setenv("PW_TEST_SECRET", "")
	if _, err := Secret("PW_TEST_SECRET", ""); err == nil {
		t.Fatal("no secret accepted")
	}
}
