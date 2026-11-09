//go:build linux

package main

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/thapr0digy/portwarden/internal/agent"
	"github.com/thapr0digy/portwarden/internal/exposure"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/probes"
	"github.com/thapr0digy/portwarden/internal/procinfo"
	"github.com/thapr0digy/portwarden/internal/proxy"
	"github.com/thapr0digy/portwarden/internal/proxy/admin"
	"github.com/thapr0digy/portwarden/internal/proxy/discover"
	"github.com/thapr0digy/portwarden/internal/proxy/mapper"
	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

// startProxyMapping starts the proxy mapper and wires it into the agent options. The
// connect-counting probes are optional: when they cannot load, routes come from the
// configs alone (and say so). It returns the probes to close at exit, or nil.
func startProxyMapping(ctx context.Context, opts options, hostNetNS uint32, resolver *procinfo.Resolver,
	hostCgroup func(string) string, agentOpts *agent.Options, log *slog.Logger) *probes.ProxyConns {
	procs := discover.NewProcFS("/proc")
	procs.HostCgroup = hostCgroup
	selfNS, _ := procs.SelfMountNS()
	cfg := mapper.Config{
		Procs: procs, SelfMountNS: selfNS, Enrich: resolver.Enrich,
		OpenRoot:   rootfs.Open,
		NetnsAddrs: netnsAddrs(hostNetNS),
		Poll:       opts.proxyPoll, Settle: proxySettle, Recheck: opts.recheck,
	}
	if len(opts.proxyAdmin) > 0 {
		host := admin.ProcHost{ProcRoot: "/proc", PPIDFunc: procs.PPID, ExeFunc: procs.Exe}
		cfg.Admin = &mapper.AdminConfig{
			Kinds: opts.proxyAdmin, Poll: opts.proxyAdminPoll, SelfNetNS: hostNetNS,
			Read: func(ctx context.Context, p admin.Proxy, ep admin.Endpoint, q admin.Query) (admin.Answer, error) {
				return admin.Read(ctx, host, p, ep, q)
			},
			HostContainerNet: hostContainerNet,
		}
	}
	pc, err := probes.StartProxyConns()
	if err != nil {
		log.Warn("proxy connection counting unavailable; proxy routes come from configs only",
			"error", err.Error())
		pc = nil
	} else {
		cfg.Conns = proxyConnsAdapter{pc}
	}
	m := mapper.New(cfg)
	updates := make(chan proxy.Update, 1)
	go m.Run(ctx, func(u proxy.Update) { offerLatestUpdate(updates, u) })
	agentOpts.Proxies = updates
	agentOpts.ProxyListeners = m.Listeners
	return pc
}

// netnsAddrs lists a netns's addresses: the host's from its interfaces (loopback
// included), another's through one of its processes' /proc/<pid>/net.
func netnsAddrs(hostNetNS uint32) func(netns, pid uint32) ([]netip.Addr, error) {
	procAddrs := exposure.ProcNetnsAddrs("/proc")
	return func(netns, pid uint32) ([]netip.Addr, error) {
		if netns != hostNetNS {
			return procAddrs(pid)
		}
		ifs, err := netif.Snapshot()
		if err != nil {
			return nil, err
		}
		var out []netip.Addr
		for _, i := range ifs {
			for _, p := range i.Prefixes {
				out = append(out, p.Addr().Unmap())
			}
		}
		return out, nil
	}
}

// hostContainerNet reports whether the host reaches addr over one of its container
// networks (a Docker bridge, a CNI veth), so an admin read of a container proxy's own
// address cannot leave the host. The interfaces are read on every call (one netlink dump
// per container-proxy admin read).
func hostContainerNet(addr netip.Addr) bool {
	ifs, err := netif.Snapshot()
	if err != nil {
		return false
	}
	name, ok := netif.Route(ifs, addr)
	if !ok {
		return false
	}
	for _, i := range ifs {
		if i.Name == name {
			return i.ContainerNet() && !i.Loopback
		}
	}
	return false
}

type proxyConnsAdapter struct{ *probes.ProxyConns }

func (a proxyConnsAdapter) Read() ([]mapper.Conn, error) {
	conns, err := a.ProxyConns.Read()
	out := make([]mapper.Conn, 0, len(conns))
	for _, c := range conns {
		out = append(out, mapper.Conn{Proxy: c.Proxy, Addr: c.Addr, Count: c.Count, Last: c.Last})
	}
	return out, err
}

// offerLatestUpdate hands u to the agent loop, replacing an update it has not taken.
func offerLatestUpdate(ch chan proxy.Update, u proxy.Update) {
	for {
		select {
		case ch <- u:
			return
		default:
		}
		select {
		case <-ch:
		default:
		}
	}
}
