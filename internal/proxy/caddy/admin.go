package caddy

import (
	"encoding/json"
	"path"
	"strconv"
	"strings"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// DefaultAdmin is Caddy's admin address when nothing sets one.
const DefaultAdmin = "localhost:2019"

// Admin is where a running Caddy's admin API is, as far as the agent can tell without
// asking it.
type Admin struct {
	// Network is "tcp" or "unix"; Addr is host:port or a path. Empty when Off.
	Network, Addr string
	// Origin says where the address came from: the config file and line, CADDY_ADMIN, or
	// "default".
	Origin string
	// Off: the config disables the admin API.
	Off bool
}

// AdminAddress finds the admin address of a Caddy started with args and env, as Caddy
// picks it: the config file's admin setting (JSON "admin.listen"/"admin.disabled", or
// the Caddyfile's global "admin" option), else CADDY_ADMIN, else localhost:2019. The
// config file is read through fsys (the proxy's root) within conf's limits; one that
// cannot be read leaves the environment and the default to decide.
func AdminAddress(fsys conf.FS, args []string, env map[string]string) Admin {
	a := Admin{Origin: "default"}
	addr := DefaultAdmin
	if v := strings.TrimSpace(env["CADDY_ADMIN"]); v != "" {
		addr, a.Origin = v, "CADDY_ADMIN"
	}
	if file, adapter := configFlag(args); file != "" && fsys != nil {
		if b, err := fsys.ReadFile(file); err == nil && len(b) <= conf.MaxTotalBytes {
			switch {
			case adapter == "json" || (adapter == "" && path.Ext(file) == ".json"):
				if v, off, ok := jsonAdmin(b); ok {
					if off {
						return Admin{Off: true, Origin: file}
					}
					addr, a.Origin = v, file
				}
			case adapter == "caddyfile" || (adapter == "" && strings.HasPrefix(path.Base(file), "Caddyfile")):
				if v, line, ok := caddyfileAdmin(string(b)); ok {
					if v == "off" {
						return Admin{Off: true, Origin: file + ":" + itoa(line)}
					}
					addr, a.Origin = v, file+":"+itoa(line)
				}
			}
		}
	}
	a.Network, a.Addr = splitNetwork(addr)
	return a
}

func itoa(n int) string { return strconv.Itoa(n) }

// configFlag returns --config and --adapter from a "caddy run"/"caddy start" command line.
func configFlag(args []string) (file, adapter string) {
	for i := 0; i < len(args); i++ {
		a := strings.TrimPrefix(args[i], "-") // -config and --config both work (Go flags)
		a = strings.TrimPrefix(a, "-")
		name, val, hasVal := strings.Cut(a, "=")
		if name != "config" && name != "adapter" {
			continue
		}
		if !hasVal && i+1 < len(args) {
			i++
			val = args[i]
		}
		if name == "config" {
			file = val
		} else {
			adapter = val
		}
	}
	return file, adapter
}

func jsonAdmin(b []byte) (listen string, off, ok bool) {
	var c struct {
		Admin *struct {
			Disabled bool   `json:"disabled"`
			Listen   string `json:"listen"`
		} `json:"admin"`
	}
	if json.Unmarshal(b, &c) != nil || c.Admin == nil {
		return "", false, false
	}
	if c.Admin.Disabled {
		return "", true, true
	}
	if c.Admin.Listen == "" {
		return "", false, false
	}
	return c.Admin.Listen, false, true
}

// caddyfileAdmin finds "admin <addr>" (or "admin off") in a Caddyfile's global options
// block: the "{ … }" block the file starts with.
func caddyfileAdmin(src string) (addr string, line int, ok bool) {
	depth, started := 0, false
	for i, raw := range strings.Split(src, "\n") {
		text, _, _ := strings.Cut(raw, "#")
		f := strings.Fields(text)
		if len(f) == 0 {
			continue
		}
		if !started {
			if f[0] != "{" {
				return "", 0, false // no global options block
			}
			started = true
		}
		if depth == 1 && f[0] == "admin" {
			if len(f) > 1 && f[1] != "{" {
				return strings.Trim(f[1], `"`), i + 1, true
			}
			return "", 0, false // "admin { … }" keeps the default address
		}
		for _, w := range f {
			switch {
			case strings.HasSuffix(w, "{"):
				depth++
			case w == "}":
				depth--
			}
		}
		if started && depth <= 0 {
			return "", 0, false
		}
	}
	return "", 0, false
}

// splitNetwork turns Caddy's network address syntax into a network and address:
// "unix//run/x.sock" is a Unix socket, "tcp/host:port" and "host:port" are TCP.
func splitNetwork(addr string) (network, rest string) {
	if n, r, ok := strings.Cut(addr, "/"); ok && !strings.Contains(n, ":") {
		if strings.HasPrefix(n, "unix") {
			return "unix", r
		}
		return "tcp", r
	}
	return "tcp", addr
}
