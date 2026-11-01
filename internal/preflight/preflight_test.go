package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckKernelRelease(t *testing.T) {
	tests := []struct {
		release string
		wantErr bool
	}{
		{"6.8.0-31-generic", false},
		{"6.8.0", false},
		{"6.14.0-1-generic", false},
		{"7.0.1", false},
		{"6.10.3+deb13-arm64", false},
		{"6.7.12-generic", true},
		{"5.15.0-100-generic", true},
		{"6.8", false},
		{"", true},
		{"garbage", true},
		{"6.x.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.release, func(t *testing.T) {
			err := CheckKernelRelease(tt.release)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckKernelRelease(%q) error = %v, wantErr %v", tt.release, err, tt.wantErr)
			}
		})
	}
}

func TestCheckLockdown(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		wantErr  bool
	}{
		{"none", "[none] integrity confidentiality\n", false},
		{"integrity", "none [integrity] confidentiality\n", false},
		{"confidentiality", "none integrity [confidentiality]\n", true},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckLockdown(tt.contents)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckLockdown(%q) error = %v, wantErr %v", tt.contents, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "confidentiality") {
				t.Fatalf("error should name confidentiality: %v", err)
			}
		})
	}
}

func TestCheckBTF(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkBTF(present); err != nil {
		t.Fatalf("present BTF: %v", err)
	}
	if err := checkBTF(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing BTF should be an error")
	}
}

func TestCheckLockdownFileMissingIsFine(t *testing.T) {
	if err := checkLockdownFile(filepath.Join(t.TempDir(), "lockdown")); err != nil {
		t.Fatalf("a kernel without the lockdown LSM must pass: %v", err)
	}
}

func TestCheckLockdownFileConfidentiality(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lockdown")
	if err := os.WriteFile(p, []byte("none integrity [confidentiality]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkLockdownFile(p); err == nil {
		t.Fatal("confidentiality must be refused")
	}
}
