package conf

import (
	"net/netip"
	"slices"
	"testing"
)

func TestGlobLikeGlob3(t *testing.T) {
	fsys := MemFS{
		"/etc/nginx/conf.d/b.conf":    nil,
		"/etc/nginx/conf.d/a.conf":    nil,
		"/etc/nginx/conf.d/.hid.conf": nil,
		"/etc/nginx/conf.d/x.txt":     nil,
		"/etc/nginx/sites/one/s.conf": nil,
		"/etc/nginx/sites/two/s.conf": nil,
	}
	r := NewReader()
	if got := Glob(fsys, r, "/etc/nginx/conf.d/*.conf"); !slices.Equal(got, []string{"/etc/nginx/conf.d/a.conf", "/etc/nginx/conf.d/b.conf"}) {
		t.Errorf("glob = %v", got)
	}
	if got := Glob(fsys, r, "/etc/nginx/sites/*/s.conf"); !slices.Equal(got, []string{"/etc/nginx/sites/one/s.conf", "/etc/nginx/sites/two/s.conf"}) {
		t.Errorf("glob dir = %v", got)
	}
	if got := Glob(fsys, r, "/etc/nginx/missing/*"); len(got) != 0 {
		t.Errorf("missing = %v", got)
	}
	if !slices.Contains(r.watch, "/etc/nginx/conf.d") || !slices.Contains(r.watch, "/etc/nginx/sites") {
		t.Errorf("watch = %v", r.watch)
	}
}

func TestNamesWithoutDNS(t *testing.T) {
	n := LoadNames(MemFS{"/etc/hosts": []byte("127.0.0.1 localhost\n10.0.0.5 app app.internal # comment\n::1 ip6-localhost\n")})
	for host, want := range map[string]string{"app": "10.0.0.5", "APP.internal": "10.0.0.5", "[::1]": "::1", "192.0.2.1": "192.0.2.1"} {
		got, ok := n.Lookup(host)
		if !ok || got[0] != netip.MustParseAddr(want) {
			t.Errorf("Lookup(%s) = %v %v", host, got, ok)
		}
	}
	if _, ok := n.Lookup("example.com"); ok {
		t.Error("example.com must stay unresolved")
	}
	b := LoadNames(nil).Endpoint("localhost:8000", "localhost:8000", 80, "")
	if len(b.Addrs) != 2 || b.Addrs[0] != netip.MustParseAddrPort("127.0.0.1:8000") {
		t.Errorf("localhost endpoint = %+v", b)
	}
	if b := n.Endpoint("db.example.com", "db.example.com", 80, "backup"); len(b.Addrs) != 0 || b.Note != "backup; unresolved: hostname db.example.com (no DNS lookups)" {
		t.Errorf("unresolved endpoint = %+v", b)
	}
	for in, want := range map[string]string{"[::]:80": ":: 80", "*:8080": "* 8080", "app": "app 80", "::1": "::1 80"} {
		h, p, ok := SplitHostPort(in, 80)
		if !ok || h+" "+itoa(p) != want {
			t.Errorf("SplitHostPort(%s) = %s %d %v", in, h, p, ok)
		}
	}
}

func itoa(p uint16) string { return netip.AddrPortFrom(netip.IPv4Unspecified(), p).String()[8:] }
