package model

import (
	"net/netip"
	"testing"
)

func TestKeyUnmapsV4Mapped(t *testing.T) {
	k := NewKey(1, "tcp", netip.MustParseAddr("::ffff:127.0.0.1"), 80)
	if k.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Fatal(k.Addr)
	}
}

func TestKeyStringFormats(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"0.0.0.0", "4026531840/tcp/0.0.0.0:8080"},
		{"::", "4026531840/tcp/[::]:8080"},
	}
	for _, tc := range tests {
		got := NewKey(4026531840, "tcp", netip.MustParseAddr(tc.addr), 8080).String()
		if got != tc.want {
			t.Errorf("addr %s: got %q, want %q", tc.addr, got, tc.want)
		}
	}
}
