// Package discover finds the reverse proxies among the processes holding listeners:
// it groups each proxy's processes under its master (the root of the same-executable
// process tree), and works out from the master's command line, environment and binary
// where its configuration lives and which root to read it from. Nothing is executed.
package discover

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/proxy/apache"
	"github.com/thapr0digy/portwarden/internal/proxy/haproxy"
	"github.com/thapr0digy/portwarden/internal/proxy/nginx"
	"github.com/thapr0digy/portwarden/internal/state"
)

// Proxy kinds.
const (
	KindNginx   = "nginx"
	KindApache  = "apache"
	KindHAProxy = "haproxy"
	KindCaddy   = "caddy"
	KindEnvoy   = "envoy"
	KindTraefik = "traefik"
)

var kinds = map[string]string{
	"nginx": KindNginx, "openresty": KindNginx,
	"apache2": KindApache, "httpd": KindApache, "httpd.worker": KindApache, "httpd.event": KindApache,
	"haproxy": KindHAProxy,
	"caddy":   KindCaddy, "envoy": KindEnvoy, "traefik": KindTraefik,
}

// KindOf names the proxy a process is, from its executable's base name (or its comm
// when the executable is unknown); "" when it is not a known proxy.
func KindOf(exe, comm string) string {
	name := path.Base(strings.TrimSuffix(exe, " (deleted)"))
	if exe == "" {
		name = comm
	}
	return kinds[name]
}

// ConfigReadable reports whether the agent reads this kind's configuration (the others
// are known from observed connections only).
func ConfigReadable(kind string) bool {
	return kind == KindNginx || kind == KindApache || kind == KindHAProxy
}

// Procs is the /proc access discovery needs (ProcFS in production).
type Procs interface {
	PPID(pid uint32) (uint32, bool)
	Exe(pid uint32) string
	Cmdline(pid uint32) []string
	Environ(pid uint32) map[string]string
	// MountNS is the inode of the process's mount namespace.
	MountNS(pid uint32) (uint64, bool)
	// ExeString finds prefix in the executable and returns what follows it up to a byte
	// of stop (compiled-in defaults).
	ExeString(pid uint32, prefix, stop string) (string, bool)
	// Cgroup is the cgroup v2 path ("/system.slice/nginx.service").
	Cgroup(pid uint32) string
	// EUID is the process's effective uid.
	EUID(pid uint32) (uint32, bool)
	// ExeOwner stats the very executable the process runs (/proc/<pid>/exe): its owner
	// and permission bits.
	ExeOwner(pid uint32) (uid uint32, mode fs.FileMode, ok bool)
	// OldestChildStart is when the process's oldest living child started (a reload
	// replaces every worker); ok is false without children.
	OldestChildStart(pid uint32) (time.Time, bool)
}

// Instance is one proxy and how to read its configuration.
type Instance struct {
	model.ProxyInstance
	// PIDs are the master and every holder, for the connection filter.
	PIDs []uint32
	// Root is "/" for a proxy in the agent's mount namespace, /proc/<pid>/root otherwise.
	Root string
	// Cgroup is the master's cgroup v2 path.
	Cgroup string
	// Trusted: the master runs as root and its executable is root-owned and writable by
	// root only. Only a trusted proxy's config is read and only a trusted proxy gets the
	// connect hook; Untrusted says why not.
	Trusted   bool
	Untrusted string
	// One of these says how to load the config, by Kind.
	NginxConf   string
	Apache      apache.Options
	HAProxyFile []string
}

// Find groups the proxy processes holding listeners into instances, sorted by ID.
// enrich fills a master that holds no listener itself (exe, unit, container).
func Find(listeners []state.Listener, p Procs, selfMountNS uint64, enrich func(model.Process) model.Process) []Instance {
	type group struct {
		inst    *Instance
		holders map[uint32]model.Process
	}
	masters := make(map[uint32]uint32) // holder -> master, cached per call
	groups := make(map[uint32]*group)
	var order []uint32
	for _, l := range listeners {
		for _, proc := range l.Procs {
			kind := KindOf(proc.Exe, proc.Comm)
			if kind == "" || proc.PID == 0 {
				continue
			}
			if kind == KindApache && !isApache(proc, p) {
				continue
			}
			m, ok := masters[proc.PID]
			if !ok {
				m = masterOf(proc.PID, proc.Exe, p)
				masters[proc.PID] = m
			}
			g := groups[m]
			if g == nil {
				g = &group{inst: &Instance{}, holders: make(map[uint32]model.Process)}
				g.inst.Kind, g.inst.NetNS = kind, l.Key.NetNS
				groups[m] = g
				order = append(order, m)
			}
			g.holders[proc.PID] = proc
			if !slices.Contains(g.inst.Listeners, l.Key) {
				g.inst.Listeners = append(g.inst.Listeners, l.Key)
			}
		}
	}
	var out []Instance
	for _, m := range order {
		g := groups[m]
		inst := g.inst
		master, ok := g.holders[m]
		if !ok {
			master = model.Process{PID: m, Exe: p.Exe(m), Cmdline: p.Cmdline(m)}
			if enrich != nil {
				master = enrich(master)
			}
		}
		inst.Procs = []model.Process{master}
		inst.PIDs = []uint32{m}
		var others []uint32
		for pid := range g.holders {
			if pid != m {
				others = append(others, pid)
			}
		}
		slices.Sort(others)
		for _, pid := range others {
			inst.Procs = append(inst.Procs, g.holders[pid])
			inst.PIDs = append(inst.PIDs, pid)
		}
		slices.SortFunc(inst.Listeners, func(a, b model.ListenerKey) int { return strings.Compare(a.String(), b.String()) })
		inst.Root = "/"
		if ns, ok := p.MountNS(m); !ok || ns != selfMountNS {
			inst.Root = "/proc/" + strconv.FormatUint(uint64(m), 10) + "/root"
		}
		inst.Cgroup = p.Cgroup(m)
		inst.Trusted, inst.Untrusted = trust(m, p)
		locate(inst, master, p)
		inst.ID = inst.Kind + "/" + strconv.FormatUint(uint64(inst.NetNS), 10) + "/" + idPath(inst, master)
		out = append(out, *inst)
	}
	slices.SortFunc(out, func(a, b Instance) int { return strings.Compare(a.ID, b.ID) })
	// Two instances of one config in one netns (one is shutting down, or a stray
	// test run): the later masters get "#<pid>" so every ID stays unique.
	used := make(map[string]bool, len(out))
	for i := range out {
		if used[out[i].ID] {
			out[i].ID += "#" + strconv.FormatUint(uint64(out[i].Master().PID), 10)
		}
		used[out[i].ID] = true
	}
	return out
}

func idPath(inst *Instance, master model.Process) string {
	id := inst.ConfigPath
	if id == "" {
		id = master.Exe
	}
	if inst.Root != "/" && master.Container.ID != "" {
		id += "@" + master.Container.ID
	}
	return id
}

// trust decides whether a proxy's own files may speak for it: a look-alike started by
// an unprivileged user (any binary named nginx) must not get its config published.
func trust(master uint32, p Procs) (bool, string) {
	uid, ok := p.EUID(master)
	switch {
	case !ok:
		return false, "master uid unreadable"
	case uid != 0:
		return false, fmt.Sprintf("master runs as uid %d", uid)
	}
	owner, mode, ok := p.ExeOwner(master)
	switch {
	case !ok:
		return false, "executable unreadable"
	case owner != 0:
		return false, fmt.Sprintf("executable owned by uid %d", owner)
	case mode&0o022 != 0:
		return false, fmt.Sprintf("executable writable by group or others (%v)", mode)
	}
	return true, ""
}

// isApache tells Apache httpd from other programs called httpd (BusyBox's applet, for
// one): an "httpd" binary must carry Apache's compiled-in HTTPD_ROOT setting. apache2
// is Debian's name for Apache only.
func isApache(proc model.Process, p Procs) bool {
	if path.Base(proc.Exe) == "apache2" {
		return true
	}
	_, ok := p.ExeString(proc.PID, httpdRoot, `"`)
	return ok
}

// masterOf climbs the parent chain while the parent runs the same executable.
func masterOf(pid uint32, exe string, p Procs) uint32 {
	cur := pid
	for range 64 {
		parent, ok := p.PPID(cur)
		if !ok || parent <= 1 {
			return cur
		}
		if pe := p.Exe(parent); pe == "" || pe != exe {
			return cur
		}
		cur = parent
	}
	return cur
}

// locate fills the config location of inst from the master's command line, environment
// and executable.
func locate(inst *Instance, master model.Process, p Procs) {
	args := master.Cmdline
	if len(args) == 0 {
		args = p.Cmdline(master.PID)
	}
	compiled := func(prefix, stop string) string {
		v, _ := p.ExeString(master.PID, prefix, stop)
		return v
	}
	switch inst.Kind {
	case KindNginx:
		inst.NginxConf = nginxConf(args, compiled)
		inst.ConfigPath = inst.NginxConf
	case KindApache:
		inst.Apache = apacheOptions(args, master.Exe, p.Environ(master.PID), compiled)
		inst.ConfigPath = inst.Apache.MainFile()
	case KindHAProxy:
		inst.HAProxyFile = haproxyFiles(args)
		inst.ConfigPath = strings.Join(inst.HAProxyFile, ",")
	}
}

// nginxArgs undoes nginx's argv rewrite: the master's command line is one string,
// "nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf".
func nginxArgs(cmdline []string) []string {
	if len(cmdline) == 1 {
		if rest, ok := strings.CutPrefix(cmdline[0], "nginx: master process "); ok {
			return strings.Fields(rest)
		}
	}
	return cmdline
}

// compiledFunc returns what follows prefix in the binary, up to a byte of stop ("" when
// absent).
type compiledFunc func(prefix, stop string) string

// nginx's configure arguments end at a space (or the string's end).
const configureStop = " \x00\n"

// upstreamPrefix is nginx's built-in --prefix.
const upstreamPrefix = "/usr/local/nginx/"

// nginxConf finds the running nginx's main config as nginx does: -c, else the compiled
// --conf-path, else conf/nginx.conf; a relative path is under the prefix (-p, else the
// compiled --prefix, else /usr/local/nginx/). Only a binary with no configure arguments
// at all (nothing to go on) falls back to /etc/nginx/nginx.conf.
func nginxConf(cmdline []string, compiled compiledFunc) string {
	args := nginxArgs(cmdline)
	conf, prefix := flagValue(args, "-c"), flagValue(args, "-p")
	cPrefix, cConf := compiled(" --prefix=", configureStop), compiled(" --conf-path=", configureStop)
	configured := cPrefix != "" || cConf != ""
	for _, opt := range []string{" --with", " --without", " --add-", " --sbin-path="} {
		configured = configured || compiled(opt, configureStop) != ""
	}
	if prefix == "" {
		prefix = cPrefix
	}
	if prefix == "" {
		prefix = upstreamPrefix
	}
	switch {
	case conf != "":
	case cConf != "":
		conf = cConf
	case !configured:
		return nginx.DefaultConfPath
	default:
		conf = "conf/nginx.conf"
	}
	if !path.IsAbs(conf) {
		conf = path.Join(prefix, conf)
	}
	return path.Clean(conf)
}

// httpd's -V strings, compiled into the binary.
const (
	httpdRoot       = ` -D HTTPD_ROOT="`
	httpdConfigFile = ` -D SERVER_CONFIG_FILE="`
)

func apacheOptions(cmdline []string, exe string, env map[string]string, compiled compiledFunc) apache.Options {
	o := apache.Options{Env: env}
	args := cmdline
	if len(args) > 0 {
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() string {
			if len(a) > 2 {
				return a[2:]
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case strings.HasPrefix(a, "-d"):
			o.ServerRoot = val()
		case strings.HasPrefix(a, "-f"):
			o.ConfigFile = val()
		case strings.HasPrefix(a, "-D"):
			o.Defines = append(o.Defines, val())
		case a == "-k" || a == "-C" || a == "-c" || a == "-E" || a == "-e":
			i++ // takes a value
		}
	}
	if o.ServerRoot == "" {
		o.ServerRoot = compiled(httpdRoot, `"`)
	}
	if o.ConfigFile == "" {
		o.ConfigFile = compiled(httpdConfigFile, `"`)
	}
	rhel := path.Base(exe) != "apache2"
	if o.ServerRoot == "" {
		o.ServerRoot = apache.DebianRoot
		if rhel {
			o.ServerRoot = apache.RHELRoot
		}
	}
	if o.ConfigFile == "" {
		o.ConfigFile = apache.DebianConfig
		if rhel {
			o.ConfigFile = apache.RHELConfig
		}
	}
	return o
}

func haproxyFiles(cmdline []string) []string {
	var out []string
	args := cmdline
	if len(args) > 0 {
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--":
			out = append(out, args[i+1:]...)
			i = len(args)
		case a == "-f" && i+1 < len(args):
			i++
			out = append(out, args[i])
		case strings.HasPrefix(a, "-f") && len(a) > 2:
			out = append(out, a[2:])
		}
	}
	if len(out) == 0 {
		out = []string{haproxy.DefaultConfig}
	}
	return out
}

func flagValue(args []string, flag string) string {
	v := ""
	for i, a := range args {
		switch {
		case a == flag && i+1 < len(args):
			v = args[i+1]
		case strings.HasPrefix(a, flag) && len(a) > len(flag):
			v = a[len(flag):]
		}
	}
	return v
}
