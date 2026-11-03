// Package exposure judges how reachable each listener is (design §4, levels 0–2): from
// its bind address, the host's interfaces, and the host firewall (nftables / iptables),
// following Docker and Kubernetes port mappings to container listeners.
package exposure

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/exposure/firewall"
	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
	"github.com/thapr0digy/portwarden/internal/state"
)

// Config says how a View reads the host.
type Config struct {
	// HostNetNS is the inode of the host network namespace.
	HostNetNS uint32
	// Run runs nft and iptables-save (ExecRunner).
	Run Runner
	// Interfaces lists the host's interfaces (netif.Snapshot).
	Interfaces func() ([]netif.Interface, error)
	// NetnsAddrs lists the addresses of the netns a process is in (ProcNetnsAddrs).
	NetnsAddrs func(pid uint32) ([]netip.Addr, error)
}

// View is one reading of the host's firewall and interfaces. Judge is meant for one
// goroutine (the agent loop): it caches evaluations and netns addresses as it goes.
type View struct {
	trigger   string
	hostNetNS uint32
	fw        *Firewall
	fwErr     error
	ifs       []netif.Interface
	ifErr     error
	nsAddrs   func(pid uint32) ([]netip.Addr, error)
	env       firewall.Env

	// natMaps are the host-port-to-elsewhere DNATs found by simulating packets.
	natMaps []Mapping
	// natTargets are every DNAT target in a NAT table, whatever leads to it.
	natTargets []netip.AddrPort
	// opaque names NAT mechanisms the simulation cannot follow (kube-proxy nftables or
	// IPVS mode, Cilium, Swarm ingress, LoadBalancer IPs, DNATs without a port match):
	// with any of them, an unmapped container listener is undetermined, not local.
	opaque []string
	// unreadable lists what could not be read ("fw:unreadable …"); judgements are then
	// Degraded.
	unreadable []string
	results    map[packetKey]firewall.Result
	nsCache    map[uint32][]netip.Addr
}

type packetKey struct {
	proto string
	addr  netip.Addr
	iface string
	port  uint16
}

// Mapping points a host port at another address (a container's): a DNAT rule or a
// docker-proxy process.
type Mapping struct {
	Proto string
	// Host is the host side; an unspecified address means every address of its family.
	Host   netip.AddrPort
	Target netip.AddrPort
	// Evidence: "nat: dnat tcp/18080 -> 172.17.0.2:80" or
	// "docker-proxy: 0.0.0.0:18080->172.17.0.2:80".
	Evidence string
}

// Build reads the firewall and the interfaces. A failed read is recorded, not returned:
// the view then judges without it and says so in the evidence.
func Build(ctx context.Context, cfg Config, trigger string) *View {
	v := &View{
		trigger: trigger, hostNetNS: cfg.HostNetNS, nsAddrs: cfg.NetnsAddrs,
		results: make(map[packetKey]firewall.Result), nsCache: make(map[uint32][]netip.Addr),
	}
	v.ifs, v.ifErr = cfg.Interfaces()
	v.fw, v.fwErr = ReadFirewall(ctx, cfg.Run)
	v.init()
	return v
}

// NewView builds a view from readings already made (tests, and the watcher's
// fingerprint path).
func NewView(trigger string, hostNetNS uint32, fw *Firewall, fwErr error, ifs []netif.Interface, nsAddrs func(uint32) ([]netip.Addr, error)) *View {
	v := &View{
		trigger: trigger, hostNetNS: hostNetNS, fw: fw, fwErr: fwErr, ifs: ifs, nsAddrs: nsAddrs,
		results: make(map[packetKey]firewall.Result), nsCache: make(map[uint32][]netip.Addr),
	}
	if fw == nil && fwErr == nil {
		v.fwErr = fmt.Errorf("not read")
	}
	v.init()
	return v
}

func (v *View) init() {
	v.env = firewall.Env{
		IsLocal: func(a netip.Addr) bool {
			if a.IsLoopback() {
				return true
			}
			_, ok := netif.Owner(v.ifs, a)
			return ok
		},
		Route: func(a netip.Addr) (string, bool) { return netif.Route(v.ifs, a) },
	}
	if v.fw != nil {
		v.natMaps = v.findNATMappings()
		v.natTargets, v.opaque = v.scanNAT()
		for _, p := range v.fw.Partial {
			v.unreadable = append(v.unreadable, "fw:unreadable "+p)
		}
	} else {
		v.unreadable = append(v.unreadable, "fw:unreadable firewall ("+errText(v.fwErr)+")")
	}
	if v.ifErr != nil {
		v.unreadable = append(v.unreadable, "fw:unreadable interfaces ("+v.ifErr.Error()+")")
	}
	for _, i := range v.ifs {
		switch {
		case i.Name == "kube-ipvs0":
			v.opaque = append(v.opaque, "kube-proxy IPVS mode")
		case strings.HasPrefix(i.Name, "cilium_"):
			v.opaque = append(v.opaque, "Cilium")
		}
	}
	slices.Sort(v.opaque)
	v.opaque = slices.Compact(v.opaque)
}

// Conditions lists what this view could not read, for the host block; empty when the
// firewall and the interfaces were read in full.
func (v *View) Conditions() []string { return slices.Clone(v.unreadable) }

// Trigger says why the view was built: start, firewall, interfaces or recheck.
func (v *View) Trigger() string { return v.trigger }

// Firewall returns the ruleset read (nil when the read failed) and the read error.
func (v *View) Firewall() (*Firewall, error) { return v.fw, v.fwErr }

// Interfaces returns the interface list read, and its error.
func (v *View) Interfaces() ([]netif.Interface, error) { return v.ifs, v.ifErr }

// NATMappings returns the DNAT mappings found at build time.
func (v *View) NATMappings() []Mapping { return slices.Clone(v.natMaps) }

// Judge returns every listener's exposure.
func (v *View) Judge(ls []state.Listener) map[model.ListenerKey]model.Exposure {
	maps := append(dockerProxyMappings(ls, v.hostNetNS), v.natMaps...)
	out := make(map[model.ListenerKey]model.Exposure, len(ls))
	for _, l := range ls {
		var e model.Exposure
		if l.Key.NetNS == v.hostNetNS {
			e = v.judgeHostPort(l.Key.Proto, l.Key.Addr, l.Key.Port)
		} else {
			e = v.judgeNetns(l, maps)
		}
		if len(v.unreadable) > 0 && !(e.Level == model.ExposureLocal && slices.Contains(e.Evidence, "bind:loopback")) {
			e = v.degraded(e)
		}
		e.Evidence = dedupeKeepOrder(e.Evidence)
		out[l.Key] = e
	}
	return out
}

// degraded is a judgement made without a full reading: level 1 undetermined, keeping
// only the bind evidence. The agent keeps a listener's last known level instead when it
// has one.
func (v *View) degraded(e model.Exposure) model.Exposure {
	out := model.Exposure{Level: model.ExposureBound, Degraded: true}
	for _, ev := range e.Evidence {
		if strings.HasPrefix(ev, "bind:") {
			out.Evidence = append(out.Evidence, ev)
		}
	}
	out.Evidence = append(out.Evidence, v.unreadable...)
	out.Evidence = append(out.Evidence, "fw:undetermined read incomplete")
	return out
}

func dedupeKeepOrder(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

type candidate struct {
	addr  netip.Addr
	iface string
}

// external lists the addresses a packet from the outside can be sent to: those on
// external interfaces, IPv4 and/or IPv6, link-local excluded, by interface name.
func (v *View) external(v4, v6 bool) []candidate {
	var out []candidate
	for _, fam := range []bool{true, false} {
		if (fam && !v4) || (!fam && !v6) {
			continue
		}
		for _, i := range v.ifs {
			if !i.External() {
				continue
			}
			for _, p := range i.Prefixes {
				a := p.Addr()
				if a.Is4() != fam || a.IsLinkLocalUnicast() || a.IsLoopback() || a.IsMulticast() {
					continue
				}
				out = append(out, candidate{a, i.Name})
			}
		}
	}
	return out
}

// judgeHostPort judges a host-netns port bound to addr.
func (v *View) judgeHostPort(proto string, addr netip.Addr, port uint16) model.Exposure {
	var ev []string
	var cands []candidate
	switch {
	case addr.IsLoopback():
		return model.Exposure{Level: model.ExposureLocal, Evidence: []string{"bind:loopback"}}
	case addr.IsUnspecified():
		ev = []string{"bind:any"}
		// A [::] socket also takes IPv4 unless it is IPV6_V6ONLY, which the key does
		// not carry: it is judged for both.
		cands = v.external(true, addr.Is6())
	default:
		if v.ifErr != nil {
			return model.Exposure{Level: model.ExposureBound, Evidence: []string{"bind:" + addr.String(), "interfaces: unreadable (" + v.ifErr.Error() + ")"}}
		}
		ifc, ok := netif.Owner(v.ifs, addr)
		switch {
		case !ok:
			return model.Exposure{Level: model.ExposureBound, Evidence: []string{
				"bind:" + addr.String() + " (no interface)", "firewall: not judged (address on no interface)"}}
		case ifc.Loopback:
			return model.Exposure{Level: model.ExposureLocal, Evidence: []string{"bind:" + addr.String() + " (" + ifc.Name + ")"}}
		case ifc.ContainerNet():
			return model.Exposure{Level: model.ExposureBound, Evidence: []string{
				"bind:" + addr.String() + " (" + ifc.Name + ")", "firewall: not judged (container network interface)"}}
		case !ifc.Up:
			return model.Exposure{Level: model.ExposureBound, Evidence: []string{
				"bind:" + addr.String() + " (" + ifc.Name + ")", "firewall: not judged (interface down)"}}
		}
		ev = []string{"bind:" + addr.String() + " (" + ifc.Name + ")"}
		cands = []candidate{{addr, ifc.Name}}
	}
	return v.judgeFirewall(proto, port, ev, cands)
}

// judgeFirewall rises to level 2 when a packet from 0/0 to any candidate is accepted
// on every path; otherwise level 1 with the first candidate's verdict as evidence.
func (v *View) judgeFirewall(proto string, port uint16, ev []string, cands []candidate) model.Exposure {
	e := model.Exposure{Level: model.ExposureBound, Evidence: ev}
	switch {
	case v.ifErr != nil:
		e.Evidence = append(e.Evidence, "interfaces: unreadable ("+v.ifErr.Error()+")")
		return e
	case v.fw == nil:
		e.Evidence = append(e.Evidence, "firewall: unreadable ("+errText(v.fwErr)+")")
		return e
	case len(cands) == 0:
		e.Evidence = append(e.Evidence, "firewall: no external interface")
		return e
	}
	var first []string
	for _, c := range cands {
		r := v.evaluate(proto, c, port)
		if r.Decision() == firewall.Open {
			e.Level = model.ExposureHostFirewallOpen
			e.Evidence = append(e.Evidence, natEvidence(proto, port, r)...)
			e.Evidence = append(e.Evidence, describe(proto, port, c, r)...)
			return e
		}
		if first == nil {
			first = append(natEvidence(proto, port, r), describe(proto, port, c, r)...)
		}
	}
	e.Evidence = append(e.Evidence, first...)
	return e
}

func errText(err error) string {
	if err == nil {
		return "unknown error"
	}
	return err.Error()
}

func (v *View) evaluate(proto string, c candidate, port uint16) firewall.Result {
	k := packetKey{proto, c.addr, c.iface, port}
	if r, ok := v.results[k]; ok {
		return r
	}
	fam := firewall.FamilyIP
	if c.addr.Is6() {
		fam = firewall.FamilyIP6
	}
	r := v.fw.Rules.Evaluate(firewall.Packet{Family: fam, Proto: proto, DAddr: c.addr, DPort: port, IIf: c.iface}, v.env)
	v.results[k] = r
	return r
}

// natEvidence lists where DNATs sent the packet ("nat: dnat tcp/18080 -> 172.17.0.2:80").
func natEvidence(proto string, port uint16, r firewall.Result) []string {
	var out []string
	for _, o := range r.Outcomes {
		if o.Forwarded || o.DPort != port {
			out = append(out, fmt.Sprintf("nat: dnat %s/%d -> %s", proto, port, netip.AddrPortFrom(o.DAddr, o.DPort)))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// describe renders the verdict for one candidate, e.g.
// "nft: accept tcp/8443 from 0/0 (eth0, inet filter input)"; a drop of a port allowed
// only from listed sources adds "restricted by source (<chain>)", an undecided one reads
// "fw:undetermined <reasons> (…)".
func describe(proto string, port uint16, c candidate, r firewall.Result) []string {
	origin, where := "firewall", "no filter rules"
	pick := func(accept bool) {
		for _, o := range r.Outcomes {
			if o.Accept == accept && !o.Undecidable {
				if o.Origin != "" {
					origin = o.Origin
				}
				if o.Where != "" {
					where = o.Where
				}
				return
			}
		}
	}
	notes := r.Notes()
	switch r.Decision() {
	case firewall.Open:
		pick(true)
		line := fmt.Sprintf("%s: accept %s/%d from 0/0 (%s, %s)", origin, proto, port, c.iface, where)
		if slices.Contains(notes, "rate-limited") {
			line += ", rate-limited"
		}
		return []string{line}
	case firewall.Closed:
		pick(false)
		out := []string{fmt.Sprintf("%s: drop %s/%d from 0/0 (%s, %s)", origin, proto, port, c.iface, where)}
		for _, n := range notes {
			if chain, ok := strings.CutPrefix(n, "source-restricted:"); ok {
				out = append(out, "restricted by source ("+chain+")")
			}
		}
		return out
	}
	for _, o := range r.Outcomes {
		if o.Origin != "" {
			origin = o.Origin
			break
		}
	}
	return []string{fmt.Sprintf("fw:undetermined %s (%s: %s/%d from 0/0, %s)", strings.Join(r.MaybeReasons(), ", "), origin, proto, port, c.iface)}
}

// judgeNetns judges a listener outside the host netns. A mapping that points the host
// at it gives it the mapped host port's exposure. Without one it is local only when
// that is certain: its addresses were read, no DNAT targets it, and the ruleset holds
// no NAT mechanism the simulation cannot follow; otherwise it is bound, undetermined.
func (v *View) judgeNetns(l state.Listener, maps []Mapping) model.Exposure {
	k := l.Key
	if k.Addr.IsLoopback() {
		return model.Exposure{Level: model.ExposureLocal, Evidence: []string{"bind:loopback"}}
	}
	addrs := []netip.Addr{k.Addr}
	var addrErr error
	if k.Addr.IsUnspecified() {
		all, err := v.netnsAddrs(k.NetNS, l.Procs)
		addrErr = err
		addrs = nil
		for _, a := range all {
			if a.Is4() || k.Addr.Is6() {
				addrs = append(addrs, a)
			}
		}
	}
	targets := func(t netip.AddrPort) bool {
		// Addresses unknown: any target on the listener's port may be it.
		return t.Port() == k.Port && (addrErr != nil || slices.Contains(addrs, t.Addr()))
	}
	var best model.Exposure
	found := false
	for _, m := range maps {
		if m.Proto != k.Proto || !targets(m.Target) {
			continue
		}
		e := v.judgeHostPort(m.Proto, m.Host.Addr(), m.Host.Port())
		e.Evidence = append([]string{m.Evidence}, e.Evidence...)
		if !found || e.Level > best.Level {
			best, found = e, true
		}
	}
	unreadable := ""
	if addrErr != nil {
		unreadable = "netns: addresses unreadable (" + addrErr.Error() + ")"
	}
	if found {
		if unreadable != "" {
			best.Evidence = append(best.Evidence, unreadable)
		}
		return best
	}
	for _, a := range addrs {
		if netif.IsPublic(a) {
			return model.Exposure{Level: model.ExposureBound, Evidence: []string{
				"netns: public address " + a.String(), "firewall: not judged (other netns)"}}
		}
	}
	var why []string
	if unreadable != "" {
		why = append(why, unreadable)
	}
	for _, t := range v.natTargets {
		if (t.Port() == 0 || t.Port() == k.Port) && (addrErr != nil || slices.Contains(addrs, t.Addr())) {
			why = append(why, "nat: dnat target "+t.String()+" (path not judged)")
		}
	}
	if len(v.opaque) > 0 {
		why = append(why, "fw:undetermined netns mapping ("+strings.Join(v.opaque, ", ")+")")
	}
	if len(why) > 0 {
		return model.Exposure{Level: model.ExposureBound, Evidence: why}
	}
	return model.Exposure{Level: model.ExposureLocal, Evidence: []string{"netns: no host port mapping"}}
}

// netnsAddrs returns the addresses of a netns, read through one of its holders' /proc
// entries and cached for the view's life.
func (v *View) netnsAddrs(netns uint32, procs []model.Process) ([]netip.Addr, error) {
	if a, ok := v.nsCache[netns]; ok {
		return a, nil
	}
	if v.nsAddrs == nil {
		return nil, fmt.Errorf("no reader")
	}
	err := fmt.Errorf("no holder process")
	for _, p := range procs {
		if p.PID == 0 {
			continue
		}
		a, e := v.nsAddrs(p.PID)
		if e == nil {
			v.nsCache[netns] = a
			return a, nil
		}
		err = e
	}
	return nil, err
}

// scanNAT lists every DNAT target in the NAT tables and the NAT mechanisms the packet
// simulation cannot follow.
func (v *View) scanNAT() (targets []netip.AddrPort, opaque []string) {
	natTable := map[string]bool{}
	for _, c := range v.fw.Rules.Chains {
		if c.Type == firewall.TypeNAT {
			natTable[c.Origin+" "+c.Family.String()+" "+c.Table] = true
		}
		switch {
		case c.Origin == "nft" && c.Table == "kube-proxy":
			opaque = append(opaque, "kube-proxy nftables mode")
		case strings.HasPrefix(c.Name, "CILIUM_") || c.Table == "cilium":
			opaque = append(opaque, "Cilium")
		case c.Name == "DOCKER-INGRESS":
			opaque = append(opaque, "Docker Swarm ingress")
		}
	}
	for _, c := range v.fw.Rules.Chains {
		if !natTable[c.Origin+" "+c.Family.String()+" "+c.Table] {
			continue
		}
		for _, r := range c.Rules {
			hasDPort, hasForeignDAddr := false, false
			for _, x := range r.Exprs {
				switch x := x.(type) {
				case firewall.Match:
					if x.Field == firewall.FieldDPort && x.Op == firewall.OpEq {
						hasDPort = true
					}
					if x.Field == firewall.FieldDAddr && x.Op == firewall.OpEq && !v.anyLocal(x.Pfx) {
						hasForeignDAddr = true
					}
				case firewall.VMap:
					if x.Unknown != "" {
						opaque = append(opaque, "unreadable NAT rule ("+x.Unknown+")")
					}
				case firewall.NAT:
					switch {
					case x.Unknown != "":
						opaque = append(opaque, "unreadable NAT rule ("+x.Unknown+")")
					case x.Kind == firewall.NATDnat:
						targets = append(targets, netip.AddrPortFrom(x.Addr, x.Port))
						if !hasDPort && (hasForeignDAddr || c.Hook != firewall.HookNone) {
							opaque = append(opaque, "DNAT without a port match")
						}
					}
				case firewall.Verdict:
					if hasForeignDAddr && (strings.HasPrefix(x.Target, "KUBE-EXT-") || strings.HasPrefix(x.Target, "KUBE-FW-")) {
						opaque = append(opaque, "kube-proxy LoadBalancer/external IPs")
					}
				}
			}
		}
	}
	slices.SortFunc(targets, netip.AddrPort.Compare)
	return slices.Compact(targets), opaque
}

// anyLocal reports whether a prefix list covers one of the host's addresses.
func (v *View) anyLocal(pfx []netip.Prefix) bool {
	for _, p := range pfx {
		for _, i := range v.ifs {
			for _, a := range i.Prefixes {
				if p.Contains(a.Addr()) {
					return true
				}
			}
		}
	}
	return false
}

// dockerProxyMappings reads the port mappings of host-netns listeners held by
// docker-proxy, from its command line:
// docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 18080 -container-ip 172.17.0.2 -container-port 80
func dockerProxyMappings(ls []state.Listener, hostNetNS uint32) []Mapping {
	var out []Mapping
	for _, l := range ls {
		if l.Key.NetNS != hostNetNS {
			continue
		}
		for _, p := range l.Procs {
			if path.Base(p.Exe) != "docker-proxy" && p.Comm != "docker-proxy" {
				continue
			}
			if m, ok := ParseDockerProxy(p.Cmdline); ok && m.Proto == l.Key.Proto && m.Host.Port() == l.Key.Port {
				out = append(out, m)
			}
		}
	}
	slices.SortFunc(out, func(a, b Mapping) int { return cmp.Compare(a.Evidence, b.Evidence) })
	return slices.CompactFunc(out, func(a, b Mapping) bool { return a == b })
}

// ParseDockerProxy reads a docker-proxy command line.
func ParseDockerProxy(cmdline []string) (Mapping, bool) {
	flags := map[string]string{}
	for i := 1; i < len(cmdline); i++ {
		name, ok := strings.CutPrefix(cmdline[i], "-")
		if !ok {
			continue
		}
		name = strings.TrimPrefix(name, "-")
		if k, val, has := strings.Cut(name, "="); has {
			flags[k] = val
			continue
		}
		if i+1 < len(cmdline) && !strings.HasPrefix(cmdline[i+1], "-") {
			flags[name] = cmdline[i+1]
			i++
		}
	}
	hostIP, err1 := netip.ParseAddr(flags["host-ip"])
	ctrIP, err2 := netip.ParseAddr(flags["container-ip"])
	hostPort, err3 := strconv.ParseUint(flags["host-port"], 10, 16)
	ctrPort, err4 := strconv.ParseUint(flags["container-port"], 10, 16)
	proto := flags["proto"]
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || (proto != "tcp" && proto != "udp") {
		return Mapping{}, false
	}
	host := netip.AddrPortFrom(hostIP.Unmap(), uint16(hostPort))
	target := netip.AddrPortFrom(ctrIP.Unmap(), uint16(ctrPort))
	return Mapping{Proto: proto, Host: host, Target: target, Evidence: fmt.Sprintf("docker-proxy: %s->%s", host, target)}, true
}

// natPortLimit bounds how many ports one dport range in a NAT table contributes.
const natPortLimit = 64

// findNATMappings simulates a packet from the outside to every (protocol, port) a NAT
// table matches on, at every external address, and keeps each forwarded outcome.
func (v *View) findNATMappings() []Mapping {
	type pp struct {
		proto string
		port  uint16
	}
	seen := map[pp]bool{}
	var ports []pp
	add := func(proto string, port uint16) {
		for _, p := range []string{"tcp", "udp"} {
			if (proto == "" || proto == p) && !seen[pp{p, port}] {
				seen[pp{p, port}] = true
				ports = append(ports, pp{p, port})
			}
		}
	}
	type tableID struct {
		origin string
		family firewall.Family
		table  string
	}
	natTables := map[tableID]bool{}
	for _, c := range v.fw.Rules.Chains {
		if c.Type == firewall.TypeNAT && c.Hook == firewall.HookPrerouting {
			natTables[tableID{c.Origin, c.Family, c.Table}] = true
		}
	}
	for _, c := range v.fw.Rules.Chains {
		if !natTables[tableID{c.Origin, c.Family, c.Table}] {
			continue
		}
		for _, r := range c.Rules {
			for _, x := range r.Exprs {
				m, ok := x.(firewall.Match)
				if !ok || m.Field != firewall.FieldDPort || m.Op != firewall.OpEq {
					continue
				}
				for _, pr := range m.Ports {
					if int(pr.Hi)-int(pr.Lo) >= natPortLimit {
						continue
					}
					for p := int(pr.Lo); p <= int(pr.Hi); p++ {
						add(m.Proto, uint16(p))
					}
				}
			}
		}
	}
	var out []Mapping
	cands := v.external(true, true)
	for _, p := range ports {
		for _, c := range cands {
			r := v.evaluate(p.proto, c, p.port)
			for _, o := range r.Outcomes {
				if !o.Forwarded {
					continue
				}
				host := netip.AddrPortFrom(c.addr, p.port)
				target := netip.AddrPortFrom(o.DAddr, o.DPort)
				out = append(out, Mapping{Proto: p.proto, Host: host, Target: target,
					Evidence: fmt.Sprintf("nat: dnat %s/%d -> %s", p.proto, p.port, target)})
			}
		}
	}
	return slices.CompactFunc(out, func(a, b Mapping) bool { return a == b })
}
