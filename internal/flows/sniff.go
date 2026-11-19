// Package flows turns the connections the kernel reports (bpf/flows.bpf.c) into Signal's
// asm.host.flows: per window, connections aggregated by process, direction, peer, port and
// the service name the client asked for (README "Connection flows").
package flows

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// The application protocols Sniff names.
const (
	AppTLS  = "tls"
	AppHTTP = "http"
)

// maxDNSName is the longest DNS name a service name may be (RFC 1035 2.3.4, without the
// trailing dot), as Signal bounds Flow.service_name.
const maxDNSName = 253

// Sniff names the application protocol and the service a client's first bytes ask for: a
// TLS ClientHello's server_name, or a plaintext HTTP/1.x request's Host, lowercase and
// without a port. The name is "" when the bytes hold none, or one that is not a DNS name
// (an IP literal, a wildcard, a malformed name). b may be cut short anywhere; nothing past
// it, or past a length the bytes declare, is read. Nothing of b is kept: the returned
// strings are new.
func Sniff(b []byte) (app, service string) {
	if name, ok := clientHelloSNI(b); ok {
		return AppTLS, name
	}
	if host, ok := httpHost(b); ok {
		return AppHTTP, host
	}
	return "", ""
}

// cursor reads big-endian fields from a byte slice, failing (ok false) at the first read
// past its end; every later read then fails too.
type cursor struct {
	b  []byte
	ok bool
}

func (c *cursor) take(n int) []byte {
	if !c.ok || n < 0 || n > len(c.b) {
		c.ok = false
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() int {
	if v := c.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (c *cursor) u16() int {
	if v := c.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func (c *cursor) u24() int {
	if v := c.take(3); v != nil {
		return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
	}
	return 0
}

// sub takes n bytes as a cursor of their own; when fewer remain it takes what is there
// (the capture may end inside the field), so a truncated ClientHello still yields the
// fields it holds.
func (c *cursor) sub(n int) cursor {
	if !c.ok {
		return cursor{}
	}
	if n > len(c.b) {
		n = len(c.b)
	}
	return cursor{b: c.take(n), ok: true}
}

// TLS constants (RFC 8446 4, RFC 6066 3).
const (
	tlsHandshake      = 0x16
	tlsClientHello    = 0x01
	extServerName     = 0x0000
	serverNameHost    = 0x00
	tlsRecordHeader   = 5
	tlsMajorVersion   = 0x03
	tlsRandomBytes    = 32
	tlsVersionBytes   = 2
	maxSessionIDBytes = 32
)

// clientHelloSNI reports whether b starts with a TLS ClientHello (ok), and its server_name
// host name when it holds a valid one in the bytes captured.
func clientHelloSNI(b []byte) (name string, ok bool) {
	c := cursor{b: b, ok: true}
	if c.u8() != tlsHandshake || c.u8() != tlsMajorVersion {
		return "", false
	}
	c.u8() // the record's minor version: 0 to 4 in the wild
	rec := c.sub(c.u16())
	if !c.ok || rec.u8() != tlsClientHello {
		return "", false
	}
	hello := rec.sub(rec.u24())
	hello.take(tlsVersionBytes + tlsRandomBytes)
	if sid := hello.u8(); sid > maxSessionIDBytes {
		return "", true
	} else {
		hello.take(sid)
	}
	hello.take(hello.u16()) // cipher suites
	hello.take(hello.u8())  // compression methods
	exts := hello.sub(hello.u16())
	if !hello.ok {
		return "", true
	}
	for exts.ok && len(exts.b) >= 4 {
		typ := exts.u16()
		body := exts.sub(exts.u16())
		if typ != extServerName {
			continue
		}
		list := body.sub(body.u16())
		for list.ok && len(list.b) >= 3 {
			kind := list.u8()
			host := list.take(list.u16())
			if list.ok && kind == serverNameHost {
				return serviceName(string(host)), true
			}
		}
		return "", true
	}
	return "", true
}

// The request methods an HTTP/1.x client opens with (RFC 9110 9.3, RFC 5789).
var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true,
	"CONNECT": true, "OPTIONS": true, "TRACE": true, "PATCH": true,
}

// httpHost reports whether b starts with an HTTP/1.x request line (ok), and its Host
// header's name when one is captured. Only the method, the version and the Host header are
// looked at; the request target and every other header are skipped, never returned.
func httpHost(b []byte) (host string, ok bool) {
	line, rest, found := bytes.Cut(b, []byte("\r\n"))
	if !found {
		return "", false
	}
	method, line, _ := bytes.Cut(line, []byte(" "))
	sp := bytes.LastIndexByte(line, ' ')
	if !httpMethods[string(method)] || sp < 0 || !bytes.HasPrefix(line[sp+1:], []byte("HTTP/1.")) {
		return "", false
	}
	for {
		var header []byte
		header, rest, found = bytes.Cut(rest, []byte("\r\n"))
		if !found || len(header) == 0 {
			return "", true // the headers end, or the capture does, without a Host
		}
		name, value, colon := bytes.Cut(header, []byte(":"))
		if colon && strings.EqualFold(string(name), "host") {
			return serviceName(hostWithoutPort(string(bytes.TrimSpace(value)))), true
		}
	}
}

// hostWithoutPort drops a ":port" from a Host value. A bracketed IPv6 literal is returned
// whole and then fails serviceName, as every IP literal does.
func hostWithoutPort(h string) string {
	if strings.HasPrefix(h, "[") {
		return h
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		return h[:i]
	}
	return h
}

// serviceName returns s lowercased, without a trailing dot, when it is a DNS name as Signal
// takes one (labels of letters, digits, hyphens and underscores, 1 to 63 bytes, at most 253
// in all, the last label not all digits, so never an IP address), else "".
func serviceName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > maxDNSName {
		return ""
	}
	labels := strings.Split(s, ".")
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return ""
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for i := range len(label) {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return ""
			}
		}
	}
	return strings.Clone(s)
}
