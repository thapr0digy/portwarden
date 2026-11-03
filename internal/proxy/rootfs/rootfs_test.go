package rootfs

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// tree builds:
//
//	outside/secret            (next to the root: must never be readable)
//	root/etc/nginx/nginx.conf
//	root/etc/nginx/sites-available/default
//	root/etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default (absolute)
//	root/etc/nginx/sites-enabled/rel -> ../sites-available/default
//	root/etc/escape-abs -> /../../outside/secret
//	root/etc/escape-rel -> ../../../outside/secret
//	root/etc/loop -> loop
func tree(t *testing.T) (root string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	write := func(p, data string) {
		full := filepath.Join(base, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		full := filepath.Join(base, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	write("outside/secret", "host secret")
	write("root/outside/secret", "in-root decoy")
	write("root/etc/nginx/nginx.conf", "events {}")
	write("root/etc/nginx/sites-available/default", "server {}")
	link("/etc/nginx/sites-available/default", "root/etc/nginx/sites-enabled/default")
	link("../sites-available/default", "root/etc/nginx/sites-enabled/rel")
	link("/../../outside/secret", "root/etc/escape-abs")
	link("../../../outside/secret", "root/etc/escape-rel")
	link("loop", "root/etc/loop")
	return root
}

func implementations(t *testing.T, root string) map[string]FS {
	k, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return map[string]FS{"walker": Walker(root), "open": k}
}

func TestReadsInsideRoot(t *testing.T) {
	root := tree(t)
	for name, f := range implementations(t, root) {
		t.Run(name, func(t *testing.T) {
			for p, want := range map[string]string{
				"/etc/nginx/nginx.conf":                           "events {}",
				"/etc/nginx/sites-enabled/default":                "server {}",
				"/etc/nginx/sites-enabled/rel":                    "server {}",
				"/etc/nginx/../nginx/./nginx.conf":                "events {}",
				"/etc/escape-abs":                                 "in-root decoy",
				"/etc/escape-rel":                                 "in-root decoy",
				"/../../../etc/nginx/sites-enabled/../nginx.conf": "events {}",
			} {
				got, err := f.ReadFile(p)
				if err != nil || string(got) != want {
					t.Errorf("ReadFile(%s) = %q, %v; want %q", p, got, err, want)
				}
			}
			if _, err := f.ReadFile("/etc/loop"); err == nil {
				t.Error("a symlink loop must fail")
			}
			if _, err := f.ReadFile("/etc/nginx/missing"); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("missing file: %v", err)
			}
			if _, err := f.ReadFile("/etc/nginx"); err == nil {
				t.Error("reading a directory must fail")
			}
			if _, err := f.ReadFile("etc/nginx/nginx.conf"); err == nil {
				t.Error("a relative path must fail")
			}
			names, err := f.ReadDir("/etc/nginx/sites-enabled")
			if err != nil || !slices.Equal(names, []string{"default", "rel"}) {
				t.Errorf("ReadDir = %v, %v", names, err)
			}
			in, err := f.Stat("/etc/nginx/sites-enabled/default")
			if err != nil || in.Dir || in.Size != int64(len("server {}")) || in.Ino == 0 {
				t.Errorf("Stat = %+v, %v", in, err)
			}
			dir, err := f.Stat("/etc/nginx")
			if err != nil || !dir.Dir {
				t.Errorf("Stat dir = %+v, %v", dir, err)
			}
		})
	}
}

func TestReadFileBounded(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "big"), []byte(strings.Repeat("x", MaxFileSize+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, f := range implementations(t, root) {
		if _, err := f.ReadFile("/big"); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: big file: %v", name, err)
		}
	}
}
