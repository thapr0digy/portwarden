package flows

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHello returns the first bytes Go's TLS client sends for serverName: a real
// ClientHello, captured off a pipe.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		// The handshake never completes: only the ClientHello is read off the pipe.
		c := tls.Client(client, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
		_ = c.HandshakeContext(ctx)
	}()
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	return buf[:n]
}

// handBuiltHello is a ClientHello whose extensions are the given ones, in order.
func handBuiltHello(exts ...[]byte) []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32)) // random
	body.WriteByte(0)            // no session id
	body.Write([]byte{0, 2, 0x13, 0x01})
	body.Write([]byte{1, 0})
	all := bytes.Join(exts, nil)
	_ = binary.Write(&body, binary.BigEndian, uint16(len(all)))
	body.Write(all)
	hs := append([]byte{tlsClientHello, 0, byte(body.Len() >> 8), byte(body.Len())}, body.Bytes()...)
	return append([]byte{tlsHandshake, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func ext(typ uint16, data []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

func sniExt(name string) []byte {
	entry := append([]byte{serverNameHost}, binary.BigEndian.AppendUint16(nil, uint16(len(name)))...)
	entry = append(entry, name...)
	return ext(extServerName, append(binary.BigEndian.AppendUint16(nil, uint16(len(entry))), entry...))
}

func TestSniffGoClientHello(t *testing.T) {
	for _, name := range []string{"ledger.internal.example", "API.Example.COM"} {
		app, service := Sniff(clientHello(t, name))
		if app != AppTLS || service != strings.ToLower(name) {
			t.Errorf("Sniff(Go ClientHello for %q) = %q, %q", name, app, service)
		}
	}
}

func TestSniffTLS(t *testing.T) {
	keyShare := ext(0x0033, make([]byte, 1220)) // an X25519MLKEM768 share, before the SNI
	for _, tc := range []struct {
		name        string
		in          []byte
		app, service string
	}{
		{"sni first", handBuiltHello(sniExt("a.example"), ext(0x000a, []byte{0, 2, 0, 0x1d})), AppTLS, "a.example"},
		{"sni behind a big key share", handBuiltHello(keyShare, sniExt("b.example")), AppTLS, "b.example"},
		{"no sni", handBuiltHello(ext(0x000a, []byte{0, 2, 0, 0x1d})), AppTLS, ""},
		{"sni an IP literal", handBuiltHello(sniExt("10.0.0.9")), AppTLS, ""},
		{"sni a wildcard", handBuiltHello(sniExt("*.example.com")), AppTLS, ""},
		{"sni with a control byte", handBuiltHello(sniExt("a\x00.example")), AppTLS, ""},
		{"sni with a trailing dot", handBuiltHello(sniExt("c.example.")), AppTLS, "c.example"},
		{"cut inside the sni", handBuiltHello(sniExt("d.example"))[:60], AppTLS, ""},
		{"not a ClientHello", []byte{tlsHandshake, 3, 3, 0, 4, 0x02, 0, 0, 0}, "", ""},
		{"application data", []byte{0x17, 3, 3, 0, 1, 0}, "", ""},
		{"empty", nil, "", ""},
	} {
		if app, service := Sniff(tc.in); app != tc.app || service != tc.service {
			t.Errorf("%s: Sniff = %q, %q, want %q, %q", tc.name, app, service, tc.app, tc.service)
		}
	}
}

// A ClientHello's length fields may lie; nothing past the bytes captured is read.
func TestSniffTLSLyingLengths(t *testing.T) {
	h := handBuiltHello(sniExt("a.example"))
	for _, at := range []int{3, 6, 7, 8} { // record, handshake and extension lengths
		lie := bytes.Clone(h)
		lie[at] = 0xff
		Sniff(lie) // must not panic
	}
}

func TestSniffHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, in, app, service string
	}{
		{"curl", "GET /v1/ledger?token=secret HTTP/1.1\r\nHost: Ledger.Internal.Example:8080\r\nUser-Agent: curl/8.5.0\r\n\r\n", AppHTTP, "ledger.internal.example"},
		{"host after a cookie", "POST /login HTTP/1.1\r\nCookie: session=abc\r\nAuthorization: Bearer x\r\nhost: a.example\r\n\r\n", AppHTTP, "a.example"},
		{"no host", "GET / HTTP/1.0\r\nAccept: */*\r\n\r\n", AppHTTP, ""},
		{"cut before the host", "GET / HTTP/1.1\r\nAccept: */*\r\nHo", AppHTTP, ""},
		{"host an IPv4 literal", "GET / HTTP/1.1\r\nHost: 10.0.0.9:80\r\n\r\n", AppHTTP, ""},
		{"host an IPv6 literal", "GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", AppHTTP, ""},
		{"host with a path", "GET / HTTP/1.1\r\nHost: a.example/x\r\n\r\n", AppHTTP, ""},
		{"connect", "CONNECT db.example:5432 HTTP/1.1\r\nHost: db.example:5432\r\n\r\n", AppHTTP, "db.example"},
		{"http/2 preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "", ""},
		{"not a method", "HELO mail.example\r\n", "", ""},
		{"no version", "GET /\r\nHost: a.example\r\n\r\n", "", ""},
		{"no line end", "GET / HTTP/1.1", "", ""},
	} {
		if app, service := Sniff([]byte(tc.in)); app != tc.app || service != tc.service {
			t.Errorf("%s: Sniff = %q, %q, want %q, %q", tc.name, app, service, tc.app, tc.service)
		}
	}
}

// The request target never becomes the service name, however much it looks like one.
func TestSniffHTTPNeverTheTarget(t *testing.T) {
	in := []byte("GET http://evil.example/ HTTP/1.1\r\nAccept: */*\r\n\r\n")
	if _, service := Sniff(in); service != "" {
		t.Errorf("Sniff took %q from the request target", service)
	}
}

// The service name is a new string: the capture buffer it came from is reused.
func TestSniffKeepsNothingOfTheInput(t *testing.T) {
	in := []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	_, service := Sniff(in)
	for i := range in {
		in[i] = 'x'
	}
	if service != "a.example" {
		t.Errorf("service changed with its input: %q", service)
	}
}

func TestServiceName(t *testing.T) {
	long := strings.Repeat("a", 63)
	for in, want := range map[string]string{
		"a.example":                         "a.example",
		"_grpc.a.example":                   "_grpc.a.example",
		"-a.example":                        "",
		"a..example":                        "",
		"localhost":                         "localhost",
		"123":                               "",
		strings.Repeat(long+".", 4) + "com": "",
		"ünicode.example":                   "",
	} {
		if got := serviceName(in); got != want {
			t.Errorf("serviceName(%q) = %q, want %q", in, got, want)
		}
	}
}
