package main

import (
	"testing"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

func TestFormatProxyRoutes(t *testing.T) {
	ev := &asmv1.ProxyRoutes{
		HostId: hostID, RunId: "r1", Seq: 7, ObservedAt: at, Trigger: "traffic",
		Proxy: &asmv1.Proxy{Kind: "nginx", Processes: []*asmv1.Process{{Pid: 812, Exe: "/usr/sbin/nginx"}, {Pid: 813}}},
		Routes: []*asmv1.ProxyRoute{
			{Listen: []string{"*:8080"}, ServerNames: []string{"api.example.com"}, Path: "/", Kind: "proxy", Backends: []*asmv1.ProxyBackend{
				{Address: "127.0.0.1:8000", Listener: &asmv1.Listener{Port: 8000}, Processes: []*asmv1.Process{{Pid: 1033, Exe: "/usr/bin/python3"}}, Config: true, Seen: true},
				{Address: "unix:/run/php.sock", Config: true},
			}},
			{Listen: []string{"*:8080"}, Path: "/s", Kind: "static", Root: "/var/www"},
			{Kind: "proxy", Inferred: true, Backends: []*asmv1.ProxyBackend{{Address: "10.0.0.9:5432", Seen: true, Note: "no listener"}}},
		},
	}
	got, err := formatEvent("asm."+hostID+".proxy.routes", mustMarshal(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-30T14:02:11.418Z 01234567 seq=7 PROXY nginx pid=812 /usr/sbin/nginx trigger=traffic routes=3" +
		" | *:8080 names=api.example.com / proxy -> 127.0.0.1:8000 pid=1033 /usr/bin/python3 [config,seen], unix:/run/php.sock [config]" +
		" | *:8080 /s static -> /var/www" +
		" | * - proxy -> 10.0.0.9:5432 [inferred,seen] (no listener)"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	ev.Removed, ev.Trigger, ev.Routes = true, "stopped", nil
	got, _ = formatEvent("asm."+hostID+".proxy.routes", mustMarshal(t, ev))
	if want := "2026-10-30T14:02:11.418Z 01234567 seq=7 PROXY nginx pid=812 /usr/sbin/nginx trigger=stopped REMOVED"; got != want {
		t.Fatalf("removed: %q", got)
	}
}

func TestFormatBehindProxy(t *testing.T) {
	ev := openedEvent("r1", 1)
	ev.BehindProxy = []*asmv1.ProxyRef{{Kind: "nginx", Proxy: &asmv1.Process{Pid: 812}, Path: "/api", Config: true, Seen: true}}
	got, _ := formatEvent("asm."+hostID+".listener.opened", mustMarshal(t, ev))
	want := "2026-10-30T14:02:11.418Z 01234567 seq=1 OPENED tcp 0.0.0.0:8443 pid=4410 /opt/app/bin/server behind=nginx:812:/api[config,seen]"
	if got != want {
		t.Fatalf("got %q", got)
	}
}
