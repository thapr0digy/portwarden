package caddy

import (
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

func TestAdminAddress(t *testing.T) {
	fsys := conf.MemFS{
		"/etc/caddy/Caddyfile": []byte("# comment\n{\n\temail a@b\n\tadmin 127.0.0.1:2020 # moved\n}\n\nexample.com {\n\tadmin nope\n}\n"),
		"/etc/caddy/Off":       []byte("{\n  admin off\n}\n"),
		"/etc/caddy/Block":     []byte("{\n  admin {\n    origins x\n  }\n}\n"),
		"/etc/caddy/NoGlobal":  []byte("example.com {\n  admin 127.0.0.1:1\n}\n"),
		"/etc/caddy/c.json":    []byte(`{"admin":{"listen":"unix//run/caddy/admin.sock"}}`),
		"/etc/caddy/off.json":  []byte(`{"admin":{"disabled":true}}`),
		"/etc/caddy/bad.json":  []byte(`{`),
	}
	cases := []struct {
		args []string
		env  map[string]string
		want Admin
	}{
		{[]string{"caddy", "run"}, nil, Admin{Network: "tcp", Addr: "localhost:2019", Origin: "default"}},
		{[]string{"caddy", "run"}, map[string]string{"CADDY_ADMIN": "0.0.0.0:2019"}, Admin{Network: "tcp", Addr: "0.0.0.0:2019", Origin: "CADDY_ADMIN"}},
		{[]string{"caddy", "run", "--environ", "--config", "/etc/caddy/Caddyfile"}, map[string]string{"CADDY_ADMIN": ":1"}, Admin{Network: "tcp", Addr: "127.0.0.1:2020", Origin: "/etc/caddy/Caddyfile:4"}},
		{[]string{"caddy", "run", "--config=/etc/caddy/Off", "--adapter", "caddyfile"}, nil, Admin{Off: true, Origin: "/etc/caddy/Off:2"}},
		{[]string{"caddy", "run", "-config", "/etc/caddy/Block", "-adapter=caddyfile"}, nil, Admin{Network: "tcp", Addr: "localhost:2019", Origin: "default"}},
		{[]string{"caddy", "run", "--config", "/etc/caddy/NoGlobal", "--adapter", "caddyfile"}, nil, Admin{Network: "tcp", Addr: "localhost:2019", Origin: "default"}},
		{[]string{"caddy", "run", "--config", "/etc/caddy/c.json"}, nil, Admin{Network: "unix", Addr: "/run/caddy/admin.sock", Origin: "/etc/caddy/c.json"}},
		{[]string{"caddy", "run", "--config", "/etc/caddy/off.json"}, nil, Admin{Off: true, Origin: "/etc/caddy/off.json"}},
		{[]string{"caddy", "run", "--config", "/etc/caddy/bad.json"}, nil, Admin{Network: "tcp", Addr: "localhost:2019", Origin: "default"}},
		{[]string{"caddy", "run", "--config", "/missing.json"}, map[string]string{"CADDY_ADMIN": "tcp/localhost:3000"}, Admin{Network: "tcp", Addr: "localhost:3000", Origin: "CADDY_ADMIN"}},
	}
	for _, c := range cases {
		if got := AdminAddress(fsys, c.args, c.env); got != c.want {
			t.Errorf("%v %v: got %+v, want %+v", c.args, c.env, got, c.want)
		}
	}
}
