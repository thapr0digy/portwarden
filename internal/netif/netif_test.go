package netif

import (
	"net/netip"
	"testing"
)

func TestContainerNetAndExternal(t *testing.T) {
	for name, want := range map[string]bool{
		"eth0": false, "ens5": false, "enp0s1": false, "wlan0": false, "bond0": false,
		"docker0": true, "br-1a2b": true, "veth3348d69": true, "cni0": true, "flannel.1": true,
		"cali123": true, "cilium_host": true, "lxc0": true, "virbr0": true, "podman0": true,
	} {
		if got := (Interface{Name: name}).ContainerNet(); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	if (Interface{Name: "eth0", Up: false}).External() {
		t.Error("a down interface is not external")
	}
	if (Interface{Name: "lo", Up: true, Loopback: true}).External() {
		t.Error("loopback is not external")
	}
	if !(Interface{Name: "eth0", Up: true}).External() {
		t.Error("eth0 is external")
	}
}

func TestOwnerAndRoute(t *testing.T) {
	ifs := []Interface{
		{Name: "lo", Up: true, Loopback: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.5.15/24"), netip.MustParsePrefix("fe80::1/64")}},
		{Name: "docker0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "br-x", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("172.17.5.1/24")}},
	}
	if i, ok := Owner(ifs, netip.MustParseAddr("192.168.5.15")); !ok || i.Name != "eth0" {
		t.Errorf("owner: %v %v", i, ok)
	}
	if _, ok := Owner(ifs, netip.MustParseAddr("192.168.5.16")); ok {
		t.Error("a neighbour's address has no owner")
	}
	for addr, want := range map[string]string{"172.17.0.2": "docker0", "172.17.5.9": "br-x", "192.168.5.200": "eth0", "10.0.0.1": ""} {
		got, _ := Route(ifs, netip.MustParseAddr(addr))
		if got != want {
			t.Errorf("route %s: %q, want %q", addr, got, want)
		}
	}
}

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"34.120.1.7": true, "8.8.8.8": true, "2600:1f18::1": true,
		"10.0.0.1": false, "172.16.4.4": false, "192.168.1.1": false, "100.64.0.1": false,
		"127.0.0.1": false, "169.254.169.254": false, "203.0.113.7": false, "192.0.2.1": false,
		"::1": false, "fe80::1": false, "fd00::1": false, "2001:db8::1": false, "ff02::1": false,
		"::ffff:34.120.1.7": true, "0.0.0.0": false, "224.0.0.1": false, "255.255.255.255": false,
	} {
		if got := IsPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
}

func TestSnapshotHasLoopback(t *testing.T) {
	ifs, err := Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range ifs {
		if i.Loopback {
			found = true
			for _, p := range i.Prefixes {
				if p.Addr().Is4() && p.Bits() > 32 {
					t.Errorf("bad v4 prefix %v", p)
				}
			}
		}
	}
	if !found {
		t.Fatalf("no loopback in %+v", ifs)
	}
	if Fingerprint(ifs) != Fingerprint(ifs) || Fingerprint(ifs) == "" {
		t.Fatal("fingerprint not stable")
	}
}
