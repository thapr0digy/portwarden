//go:build integration && linux

package publish_test

import (
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/flows"
	"github.com/thapr0digy/portwarden/internal/probes"
	"github.com/thapr0digy/portwarden/internal/procinfo"
)

// In the dev VM (make itest; README "Connection flows"): the agent's flow probes and reader
// see curl call a local HTTPS server by name and an HTTP server by Host, and Signal's
// reference door stores the window: curl's two outbound rows named by SNI and Host, and the
// servers' inbound rows. Run it under the unit's capabilities only (README) to see that no
// new privilege is needed.
func TestHostFlowsOfThisHostAreStoredBySignal(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skipf("no curl: %v", err)
	}
	fp, err := probes.StartFlows()
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	t.Logf("running as uid %d", os.Geteuid())

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	tlsSrv := httptest.NewTLSServer(ok) // its certificate names example.com
	defer tlsSrv.Close()
	plain := httptest.NewServer(ok)
	defer plain.Close()
	tlsPort := tlsSrv.Listener.Addr().(*net.TCPAddr).Port
	plainPort := plain.Listener.Addr().(*net.TCPAddr).Port
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}), 0o644); err != nil { //nolint:gosec // a public test certificate
		t.Fatal(err)
	}

	resolver := procinfo.NewResolver("/proc", "/sys/fs/cgroup", 0)
	cfg := flows.Config{Drops: fp.Drops, Identify: func(tgid uint32, cg uint64) flows.Process {
		exe, unit := resolver.Identity(tgid, cg)
		return flows.Process{Exe: exe, Unit: unit}
	}}
	ref, pub, sent := signalDoor(t, e2eHost)
	runFlows(t, cfg, fp.Events(), pub, func() {
		for _, args := range [][]string{
			{"--cacert", ca, "--resolve", fmt.Sprintf("example.com:%d:127.0.0.1", tlsPort), fmt.Sprintf("https://example.com:%d/v1/ledger?token=secret", tlsPort)},
			{"-H", "Host: billing.internal.example", "-H", "Authorization: Bearer secret", fmt.Sprintf("http://127.0.0.1:%d/private/path", plainPort)},
		} {
			if out, err := exec.Command(curl, append([]string{"-sS", "--max-time", "5"}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("curl %v: %v: %s", args, err, out)
			}
		}
		time.Sleep(500 * time.Millisecond) // the reader drains the ring
	})

	f := storedFlows(t, ref)
	for _, r := range f.GetFlows() {
		t.Logf("%s %s exe=%s unit=%s local=%d remote=%s:%d %s %q x%d", r.GetDirection(), r.GetComm(), r.GetExe(), r.GetUnit(),
			r.GetLocalPort(), r.GetRemoteAddr(), r.GetRemotePort(), r.GetAppProto(), r.GetServiceName(), r.GetCount())
	}
	if r := flowRow(f, "out", uint32(tlsPort)); r == nil || r.GetComm() != "curl" || r.GetExe() != curl ||
		r.GetAppProto() != "tls" || r.GetServiceName() != "example.com" || r.GetRemoteAddr() != "127.0.0.1" {
		t.Errorf("curl's TLS row %v", r)
	}
	if r := flowRow(f, "out", uint32(plainPort)); r == nil || r.GetComm() != "curl" || r.GetAppProto() != "http" || r.GetServiceName() != "billing.internal.example" {
		t.Errorf("curl's HTTP row %v", r)
	}
	self, _ := os.Executable()
	if r := flowRow(f, "in", uint32(tlsPort)); r == nil || r.GetExe() != self || r.GetRemoteAddr() != "127.0.0.1" || r.GetServiceName() != "" {
		t.Errorf("the TLS server's inbound row %v", r)
	}
	recordSignalFixtures(t, "host-flows-curl", sent)
}
