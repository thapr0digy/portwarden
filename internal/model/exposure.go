package model

import (
	"net/netip"
	"slices"
)

// ExposureLevel is how reachable a listener is, by the design's levels 0–4 (§4). It only
// rises as evidence comes in. The zero value is "not judged".
type ExposureLevel int

const (
	ExposureUnknown ExposureLevel = iota
	// ExposureLocal (level 0): loopback, or a listener in another netns that no host port
	// mapping points at.
	ExposureLocal
	// ExposureBound (level 1): bound to all addresses or to a real interface address.
	ExposureBound
	// ExposureHostFirewallOpen (level 2): the host firewall lets a packet from 0/0 in.
	ExposureHostFirewallOpen
	// ExposureCloudOpen (level 3) is reserved for the backend's cloud look-up.
	ExposureCloudOpen
	// ExposureConfirmed (level 4) is reserved for the outside checker.
	ExposureConfirmed
)

var levelNames = [...]string{"unknown", "local", "bound", "host_firewall_open", "cloud_open", "confirmed"}

// String is the level's wire name, e.g. "host_firewall_open".
func (l ExposureLevel) String() string {
	if l < 0 || int(l) >= len(levelNames) {
		return "unknown"
	}
	return levelNames[l]
}

// Exposure is a listener's level and the evidence for it, in order.
type Exposure struct {
	Level    ExposureLevel
	Evidence []string
	// Degraded: judged while the firewall or interfaces could not be fully read. The
	// agent then keeps a listener's last known level and adds this evidence instead.
	Degraded bool
}

// Equal compares level and evidence.
func (e Exposure) Equal(f Exposure) bool {
	return e.Level == f.Level && slices.Equal(e.Evidence, f.Evidence) && e.Degraded == f.Degraded
}

// Public-IP candidate sources and directions (design §5).
const (
	ViaNetlink     = "netlink"
	ViaIMDS        = "imds"
	ViaIngestLocal = "ingest-local"
	DirIn          = "in"
	DirOut         = "out"
)

// PublicIP is one candidate for the server's public address.
type PublicIP struct {
	IP    netip.Addr
	Via   string
	Dir   string
	Iface string
}

// HostInfo is the host block: public-IP candidates and the cloud identity.
type HostInfo struct {
	PublicIPs  []PublicIP
	Cloud      string
	InstanceID string
	// Region is the cloud region, for the backend's cloud look-up.
	Region string
	// Conditions are host-level problems that weaken the agent's judgements, e.g.
	// "fw:unreadable iptables-save: Permission denied".
	Conditions []string
}

// Equal compares every field, candidates and conditions in order.
func (h HostInfo) Equal(g HostInfo) bool {
	return h.Cloud == g.Cloud && h.InstanceID == g.InstanceID && h.Region == g.Region && slices.Equal(h.PublicIPs, g.PublicIPs) &&
		slices.Equal(h.Conditions, g.Conditions)
}

// Clone returns a copy that shares no slice with h.
func (h HostInfo) Clone() HostInfo {
	h.PublicIPs = slices.Clone(h.PublicIPs)
	h.Conditions = slices.Clone(h.Conditions)
	return h
}
