//go:build linux && integration

package sdsocket

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDBusListsSocketUnit(t *testing.T) {
	const dir = "/run/systemd/system"
	files := map[string]string{
		"pw-test.socket":  "[Socket]\nListenStream=127.0.0.1:9419\nAccept=no\n\n[Install]\nWantedBy=sockets.target\n",
		"pw-test.service": "[Service]\nExecStart=/bin/true\n",
	}
	systemctl := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			t.Fatalf("systemctl %v: %v\n%s", args, err, out)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("systemctl", "stop", "pw-test.socket", "pw-test.service").Run()
		for name := range files {
			_ = os.Remove(filepath.Join(dir, name))
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
	})
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	systemctl("daemon-reload")
	systemctl("start", "pw-test.socket")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	units, err := NewDBusLister().SocketUnits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range units {
		if u.Name != "pw-test.socket" {
			continue
		}
		if u.Service != "pw-test.service" {
			t.Fatalf("Service = %q", u.Service)
		}
		for _, l := range u.Listens {
			if l.Type == "Stream" && l.Address == "127.0.0.1:9419" {
				return
			}
		}
		t.Fatalf("listens = %+v, want Stream 127.0.0.1:9419", u.Listens)
	}
	t.Fatalf("pw-test.socket not in %+v", units)
}
