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

func TestProcessIsZero(t *testing.T) {
	if !(Process{}).IsZero() {
		t.Error("empty Process should be zero")
	}
	if (Process{CgroupID: 1}).IsZero() {
		t.Error("Process with a cgroup id should not be zero")
	}
}

func TestProcessEqualComparesCmdline(t *testing.T) {
	base := Process{PID: 1, Comm: "nginx", Cmdline: []string{"nginx", "-g", "daemon off;"}, Container: Container{Runtime: "docker", ID: "abc"}}
	same := base
	same.Cmdline = []string{"nginx", "-g", "daemon off;"}
	if !base.Equal(same) {
		t.Error("identical processes should be equal")
	}
	diff := base
	diff.Cmdline = []string{"nginx", "-g", "daemon on;"}
	if base.Equal(diff) {
		t.Error("a differing cmdline argument should make processes unequal")
	}
	if !(Process{Cmdline: nil}).Equal(Process{Cmdline: []string{}}) {
		t.Error("nil and empty cmdline should be equal")
	}
}
