package conf

import (
	"maps"
	"slices"
	"testing"
)

func TestEncodeDecodeFilesRoundTrip(t *testing.T) {
	in := MemFS{"/etc/nginx/nginx.conf": []byte("include conf.d/*.conf;"), "/etc/nginx/conf.d/a.conf": []byte("x"), "/e": nil}
	main, out := DecodeFiles(EncodeFiles("/etc/nginx/nginx.conf", in))
	if main != "/etc/nginx/nginx.conf" {
		t.Fatalf("main = %q", main)
	}
	for p := range in {
		if string(out[p]) != string(in[p]) {
			t.Fatalf("%s = %q, want %q", p, out[p], in[p])
		}
	}
	if len(out) != len(in) {
		t.Fatalf("files = %v", slices.Sorted(maps.Keys(out)))
	}
}

func TestDecodeFilesNormalisesPaths(t *testing.T) {
	main, fsys := DecodeFiles([]byte("etc//a/../b\x00one\x00/etc/b\x00dup\x00/c"))
	if main != "/etc/b" || string(fsys["/etc/b"]) != "one" {
		t.Fatalf("main = %q, files = %q", main, fsys)
	}
	if b, ok := fsys["/c"]; !ok || len(b) != 0 {
		t.Fatalf("a trailing path must be an empty file: %q", fsys)
	}
	if main, fsys := DecodeFiles(nil); main != "/" || len(fsys) != 0 {
		t.Fatalf("empty input: main %q, files %q", main, fsys)
	}
}

func TestLoadTreeFollowsSymlinksInsideRoot(t *testing.T) {
	fsys, err := LoadTree("../apache/testdata/ubuntu-default/root")
	if err != nil {
		t.Fatal(err)
	}
	// sites-enabled/000-default.conf is a symlink to ../sites-available/000-default.conf.
	got, want := fsys["/etc/apache2/sites-enabled/000-default.conf"], fsys["/etc/apache2/sites-available/000-default.conf"]
	if len(want) == 0 || string(got) != string(want) {
		t.Fatalf("symlinked site = %d bytes, target = %d bytes", len(got), len(want))
	}
}
