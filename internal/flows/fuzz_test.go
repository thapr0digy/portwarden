package flows

import (
	"bytes"
	"testing"
)

// FuzzSniff feeds Sniff untrusted first bytes (anything a process on the host sends). It
// must not panic, must read nothing past its input, and may only return a service name that
// is a valid one taken from the input itself.
func FuzzSniff(f *testing.F) {
	f.Add(handBuiltHello(sniExt("a.example")))
	f.Add(handBuiltHello(ext(0x0033, make([]byte, 64)), sniExt("b.example")))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a.example:80\r\n\r\n"))
	f.Add([]byte("POST /x HTTP/1.0\r\nhost:b.example\r\n"))
	f.Add([]byte{tlsHandshake, 3, 3, 0xff, 0xff, 1, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		in := bytes.Clone(b)
		app, service := Sniff(b)
		if !bytes.Equal(in, b) {
			t.Fatal("Sniff changed its input")
		}
		switch app {
		case "", AppTLS, AppHTTP:
		default:
			t.Fatalf("app %q", app)
		}
		if service == "" {
			return
		}
		if app == "" {
			t.Fatalf("service %q without an app", service)
		}
		if serviceName(service) != service {
			t.Fatalf("service %q is not a valid name", service)
		}
		if !bytes.Contains(bytes.ToLower(b), []byte(service)) {
			t.Fatalf("service %q is not in the input", service)
		}
	})
}
