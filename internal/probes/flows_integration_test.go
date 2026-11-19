//go:build linux && integration

package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/flows"
)

// collectFlows reads f's events until want reports it has what it needs, or fails after 5 s.
func collectFlows(t *testing.T, f *Flows, want func([]flows.Event) bool) []flows.Event {
	t.Helper()
	var got []flows.Event
	deadline := time.After(5 * time.Second)
	for !want(got) {
		select {
		case e, ok := <-f.Events():
			if !ok {
				t.Fatalf("events closed: %v", f.Err())
			}
			got = append(got, e)
		case <-deadline:
			t.Fatalf("timed out; got %+v", got)
		}
	}
	return got
}

func startFlows(t *testing.T) *Flows {
	t.Helper()
	f, err := StartFlows()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

// The programs load and attach on this kernel, and a TLS connection this process makes is
// reported once each way: made (with the server name its ClientHello carried, joined by
// cookie) and accepted, both attributed to this process.
func TestFlowsTLSConnection(t *testing.T) {
	f := startFlows(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)

	// The test certificate does not name ledger.internal.example, so the handshake fails
	// after the ClientHello; only the ClientHello matters here.
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	if c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "ledger.internal.example", RootCAs: roots}); err == nil {
		_ = c.Close()
	}

	var out, in *flows.Event
	got := collectFlows(t, f, func(es []flows.Event) bool {
		for i := range es {
			e := &es[i]
			switch {
			case e.Kind == flows.KindOut && e.Remote.Port() == port && e.TGID == uint32(os.Getpid()):
				out = e
			case e.Kind == flows.KindIn && e.LocalPort == port && e.TGID == uint32(os.Getpid()):
				in = e
			}
		}
		if out == nil || in == nil {
			return false
		}
		for _, e := range es {
			if e.Kind == flows.KindHead && e.Cookie == out.Cookie {
				return true
			}
		}
		return false
	})
	if out.Cookie == 0 || !out.Remote.Addr().IsLoopback() || out.Comm == "" {
		t.Errorf("made = %+v", *out)
	}
	if in.Remote.Port() == 0 || !in.Remote.Addr().IsLoopback() {
		t.Errorf("accepted = %+v", *in)
	}
	for _, e := range got {
		if e.Kind == flows.KindHead && e.Cookie == out.Cookie && (e.App != flows.AppTLS || e.Service != "ledger.internal.example") {
			t.Errorf("first bytes named %q %q", e.App, e.Service)
		}
	}
}

// A plaintext HTTP request is named by its Host; a client that sends nothing (a
// server-first protocol) is reported made, with no first bytes.
func TestFlowsHTTPAndSilentClient(t *testing.T) {
	f := startFlows(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/secret/path?token=x", nil)
	req.Host = "billing.internal.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	silent, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	var made []flows.Event
	var named *flows.Event
	collectFlows(t, f, func(es []flows.Event) bool {
		made = made[:0]
		for i := range es {
			if es[i].Kind == flows.KindOut && es[i].Remote.Port() == port {
				made = append(made, es[i])
			}
		}
		for i := range es {
			for _, m := range made {
				if es[i].Kind == flows.KindHead && es[i].Cookie == m.Cookie {
					named = &es[i]
				}
			}
		}
		return len(made) == 2 && named != nil
	})
	if named.App != flows.AppHTTP || named.Service != "billing.internal.example" {
		t.Errorf("first bytes named %q %q", named.App, named.Service)
	}
}
