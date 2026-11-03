package model

import (
	"net/netip"
	"testing"
)

func TestExposureLevelString(t *testing.T) {
	cases := map[ExposureLevel]string{
		ExposureUnknown: "unknown", ExposureLocal: "local", ExposureBound: "bound",
		ExposureHostFirewallOpen: "host_firewall_open", ExposureCloudOpen: "cloud_open",
		ExposureConfirmed: "confirmed", ExposureLevel(42): "unknown", ExposureLevel(-1): "unknown",
	}
	for l, want := range cases {
		if got := l.String(); got != want {
			t.Errorf("%d: got %q, want %q", int(l), got, want)
		}
	}
	if !(ExposureLocal < ExposureBound && ExposureBound < ExposureHostFirewallOpen) {
		t.Fatal("levels must rise with exposure")
	}
}

func TestExposureEqual(t *testing.T) {
	a := Exposure{Level: ExposureBound, Evidence: []string{"bind:any"}}
	if !a.Equal(Exposure{Level: ExposureBound, Evidence: []string{"bind:any"}}) {
		t.Fatal("same exposure not equal")
	}
	if a.Equal(Exposure{Level: ExposureBound, Evidence: []string{"bind:any", "x"}}) {
		t.Fatal("different evidence equal")
	}
	if a.Equal(Exposure{Level: ExposureLocal, Evidence: []string{"bind:any"}}) {
		t.Fatal("different level equal")
	}
}

func TestHostInfoEqualAndClone(t *testing.T) {
	h := HostInfo{Cloud: "aws", InstanceID: "i-1", PublicIPs: []PublicIP{{IP: netip.MustParseAddr("203.0.113.7"), Via: ViaIMDS, Dir: DirIn}}}
	c := h.Clone()
	if !h.Equal(c) {
		t.Fatal("clone not equal")
	}
	c.PublicIPs[0].Via = ViaNetlink
	if h.PublicIPs[0].Via != ViaIMDS {
		t.Fatal("clone shares its slice")
	}
	if h.Equal(c) {
		t.Fatal("changed clone still equal")
	}
}
