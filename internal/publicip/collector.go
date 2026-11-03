package publicip

import (
	"net/netip"
	"slices"
	"sync"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
)

// Collector merges the candidates from each source into the host block and hands every
// new version to publish (in order; it is called with the collector's lock held, so
// publish must not call back into the collector).
type Collector struct {
	mu      sync.Mutex
	publish func(model.HostInfo)
	ifaces  []model.PublicIP
	cloud   Info
	ingest  netip.Addr
	conds   []string
	last    model.HostInfo
	started bool
}

// NewCollector returns a collector that calls publish whenever the host block changes.
func NewCollector(publish func(model.HostInfo)) *Collector {
	return &Collector{publish: publish}
}

// SetInterfaces takes the public addresses of the host's interfaces (inbound).
func (c *Collector) SetInterfaces(ifs []netif.Interface) {
	var ips []model.PublicIP
	for _, i := range ifs {
		if !i.Up || i.Loopback {
			continue
		}
		for _, p := range i.Prefixes {
			if netif.IsPublic(p.Addr()) {
				ips = append(ips, model.PublicIP{IP: p.Addr(), Via: model.ViaNetlink, Dir: model.DirIn, Iface: i.Name})
			}
		}
	}
	c.update(func() { c.ifaces = ips })
}

// SetCloud takes cloud metadata (the attached public or elastic IPs are inbound).
func (c *Collector) SetCloud(info Info) {
	c.update(func() { c.cloud = info })
}

// SetIngestLocal takes the local address of the agent's NATS connection. It is kept
// only when public: then it is the address the server connects out from. Behind NAT
// the outbound address is only visible to the server side (a backend task).
func (c *Collector) SetIngestLocal(a netip.Addr) {
	if !netif.IsPublic(a) {
		a = netip.Addr{}
	}
	c.update(func() { c.ingest = a })
}

// SetConditions takes the host-level conditions (an incomplete firewall read).
func (c *Collector) SetConditions(conds []string) {
	conds = slices.Clone(conds)
	c.update(func() { c.conds = conds })
}

// Host returns the current host block.
func (c *Collector) Host() model.HostInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.build()
}

func (c *Collector) update(change func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	change()
	h := c.build()
	if c.started && h.Equal(c.last) {
		return
	}
	c.started, c.last = true, h.Clone()
	c.publish(h)
}

// build orders the candidates: cloud metadata, then interfaces, then the ingest view.
func (c *Collector) build() model.HostInfo {
	h := model.HostInfo{Cloud: c.cloud.Cloud, InstanceID: c.cloud.InstanceID, Region: c.cloud.Region, Conditions: slices.Clone(c.conds)}
	for _, a := range c.cloud.PublicIPs {
		h.PublicIPs = append(h.PublicIPs, model.PublicIP{IP: a.Unmap(), Via: model.ViaIMDS, Dir: model.DirIn})
	}
	h.PublicIPs = append(h.PublicIPs, c.ifaces...)
	if c.ingest.IsValid() {
		h.PublicIPs = append(h.PublicIPs, model.PublicIP{IP: c.ingest, Via: model.ViaIngestLocal, Dir: model.DirOut})
	}
	h.PublicIPs = slices.CompactFunc(h.PublicIPs, func(a, b model.PublicIP) bool { return a == b })
	return h
}
