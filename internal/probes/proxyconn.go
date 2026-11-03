//go:build linux

package probes

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/tamper"
)

// CgroupRoot is where the cgroup v2 hierarchy is mounted.
const CgroupRoot = "/sys/fs/cgroup"

// ProxyConn is one destination a proxy connected to, as counted in the kernel.
type ProxyConn struct {
	// Proxy is the tracked tgid the connect was attributed to (the connecting process
	// or its parent).
	Proxy uint32
	Addr  netip.AddrPort
	Count uint64
	Last  time.Time
}

// ProxyConns owns the connect-counting programs of bpf/proxyconn.bpf.c. They are
// attached per cgroup (SetCgroups), only to the cgroups proxies run in, and count only
// the processes SetPIDs names and their children.
type ProxyConns struct {
	mu    sync.Mutex
	objs  proxyconnObjects
	links map[string][]attachedLink // cgroup path -> connect4, connect6 links
}

// StartProxyConns loads the programs; nothing is attached until SetCgroups.
func StartProxyConns() (*ProxyConns, error) {
	spec, err := loadProxyconn()
	if err != nil {
		return nil, err
	}
	p := &ProxyConns{links: make(map[string][]attachedLink)}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		return nil, fmt.Errorf("load proxy connect programs: %w", WithVerifierLog(err))
	}
	return p, nil
}

// SetCgroups attaches the programs to every cgroup in paths (cgroup v2 paths such as
// "/system.slice/nginx.service") not yet attached, and detaches the others. A cgroup
// that cannot be attached is reported in the error; the rest are still applied.
func (p *ProxyConns) SetCgroups(paths []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	want := make(map[string]bool, len(paths))
	var errs []error
	for _, cg := range paths {
		want[cg] = true
		if _, ok := p.links[cg]; ok {
			continue
		}
		dir := filepath.Join(CgroupRoot, filepath.Clean("/"+cg))
		var ls []attachedLink
		for _, a := range []struct {
			name string
			typ  ebpf.AttachType
			prog *ebpf.Program
		}{{proxyconnProgOnConnect4, ebpf.AttachCGroupInet4Connect, p.objs.OnConnect4},
			{proxyconnProgOnConnect6, ebpf.AttachCGroupInet6Connect, p.objs.OnConnect6}} {
			l, err := link.AttachCgroup(link.CgroupOptions{Path: dir, Attach: a.typ, Program: a.prog})
			if err != nil {
				errs = append(errs, fmt.Errorf("attach to cgroup %s: %w", dir, err))
				break
			}
			al, err := newAttachedLink(a.name, cg, a.prog, l)
			if err != nil {
				_ = l.Close()
				errs = append(errs, err)
				break
			}
			ls = append(ls, al)
		}
		if len(ls) != 2 {
			for _, l := range ls {
				_ = l.link.Close()
			}
			continue
		}
		p.links[cg] = ls
	}
	for cg, ls := range p.links {
		if want[cg] {
			continue
		}
		for _, l := range ls {
			if err := l.link.Close(); err != nil {
				errs = append(errs, fmt.Errorf("detach from cgroup %s: %w", cg, err))
			}
		}
		delete(p.links, cg)
	}
	return errors.Join(errs...)
}

// Attachments reports, for the tamper checks, each connect link with the program the
// agent attached and what the kernel reports for it now. A link that reads detached
// because its cgroup was removed (the proxy's unit stopped) is left out: that is not
// tamper, and the next SetCgroups drops it.
func (p *ProxyConns) Attachments() ([]tamper.Attachment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var all []attachedLink
	for _, cg := range slices.Sorted(maps.Keys(p.links)) {
		all = append(all, p.links[cg]...)
	}
	return observe(all, func(a attachedLink) bool {
		_, err := os.Stat(filepath.Join(CgroupRoot, filepath.Clean("/"+a.where)))
		return errors.Is(err, fs.ErrNotExist)
	})
}

// Cgroups lists the attached cgroups, sorted.
func (p *ProxyConns) Cgroups() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.links))
	for cg := range p.links {
		out = append(out, cg)
	}
	slices.Sort(out)
	return out
}

// SetPIDs replaces the tracked tgids, and drops the counts of tgids no longer tracked.
func (p *ProxyConns) SetPIDs(pids []uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	want := make(map[uint32]bool, len(pids))
	var errs []error
	for _, pid := range pids {
		want[pid] = true
		if err := p.objs.ProxyTgids.Put(pid, uint8(1)); err != nil {
			errs = append(errs, fmt.Errorf("track pid %d: %w", pid, err))
		}
	}
	var stale []uint32
	var k uint32
	var v uint8
	it := p.objs.ProxyTgids.Iterate()
	for it.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		errs = append(errs, err)
	}
	for _, pid := range stale {
		if err := p.objs.ProxyTgids.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	var ck proxyconnConnKey
	var cv proxyconnConnVal
	var drop []proxyconnConnKey
	cit := p.objs.Conns.Iterate()
	for cit.Next(&ck, &cv) {
		if !want[ck.Proxy] {
			drop = append(drop, ck)
		}
	}
	if err := cit.Err(); err != nil {
		errs = append(errs, err)
	}
	for _, key := range drop {
		if err := p.objs.Conns.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Read returns every counted destination.
func (p *ProxyConns) Read() ([]ProxyConn, error) {
	var out []ProxyConn
	var k proxyconnConnKey
	var v proxyconnConnVal
	it := p.objs.Conns.Iterate()
	for it.Next(&k, &v) {
		var a netip.Addr
		switch k.Family {
		case unix.AF_INET:
			a = netip.AddrFrom4([4]byte(k.Addr[:4]))
		case unix.AF_INET6:
			a = netip.AddrFrom16(k.Addr).Unmap()
		default:
			continue
		}
		out = append(out, ProxyConn{Proxy: k.Proxy, Addr: netip.AddrPortFrom(a, k.Port), Count: v.Count, Last: monotonicToWall(v.LastNs)})
	}
	if err := it.Err(); err != nil {
		return out, fmt.Errorf("read proxy connections: %w", err)
	}
	return out, nil
}

// RunCounts returns how often each connect program ran (needs kernel.bpf_stats_enabled).
func (p *ProxyConns) RunCounts() (map[string]uint64, error) {
	counts := make(map[string]uint64)
	for name, prog := range map[string]*ebpf.Program{
		proxyconnProgOnConnect4: p.objs.OnConnect4, proxyconnProgOnConnect6: p.objs.OnConnect6,
	} {
		st, err := prog.Stats()
		if err != nil {
			return nil, fmt.Errorf("stats of %s: %w", name, err)
		}
		counts[name] = st.RunCount
	}
	return counts, nil
}

// Close detaches every program and releases the kernel objects.
func (p *ProxyConns) Close() error {
	errs := []error{p.SetCgroups(nil)}
	p.mu.Lock()
	defer p.mu.Unlock()
	errs = append(errs, p.objs.Close())
	return errors.Join(errs...)
}
