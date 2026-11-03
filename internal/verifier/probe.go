package verifier

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Results.
const (
	ResultConfirmed   = "confirmed"
	ResultUnreachable = "unreachable"
	ResultNoResponse  = "no_response"
)

// Result is one probe's outcome.
type Result struct {
	Result, Probe, Banner, Detail string
	Target                        Target
	RTT                           time.Duration
}

// Prober runs probes. Everything is bounded: connect and UDP waits by Timeout, banner
// reads by BannerWait and MaxBanner bytes.
type Prober struct {
	Timeout    time.Duration
	BannerWait time.Duration
	MaxBanner  int
	// HTTPPorts get "HEAD / HTTP/1.0" with UserAgent when the service sends nothing
	// first. Only the status line is read; redirects are never followed.
	HTTPPorts map[uint16]bool
	UserAgent string
}

// NewProber returns a prober with defaults (3 s, 2 s, 256 bytes).
func NewProber() *Prober {
	return &Prober{Timeout: 3 * time.Second, BannerWait: 2 * time.Second, MaxBanner: 256, UserAgent: "portwarden-verifier/1"}
}

// Probe probes t.
func (p *Prober) Probe(ctx context.Context, t Target) Result {
	if t.Proto == "udp" {
		return p.udp(ctx, t)
	}
	return p.tcp(ctx, t)
}

func (p *Prober) tcp(ctx context.Context, t Target) Result {
	r := Result{Probe: "tcp-connect", Target: t}
	start := time.Now()
	d := net.Dialer{Timeout: p.Timeout}
	conn, err := d.DialContext(ctx, "tcp", t.String())
	r.RTT = time.Since(start)
	if err != nil {
		r.Result, r.Detail = ResultUnreachable, dialDetail(err, p.Timeout)
		return r
	}
	defer conn.Close()
	r.Result = ResultConfirmed
	buf := make([]byte, p.MaxBanner)
	_ = conn.SetReadDeadline(time.Now().Add(p.BannerWait))
	n, _ := conn.Read(buf)
	if n == 0 && p.HTTPPorts[t.Port] {
		r.Probe = "http-head"
		req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", t.Addr, p.UserAgent)
		_ = conn.SetDeadline(time.Now().Add(p.BannerWait))
		if _, err := conn.Write([]byte(req)); err == nil {
			line, _ := bufio.NewReaderSize(conn, p.MaxBanner).ReadSlice('\n')
			n = copy(buf, line)
		}
	}
	r.Banner = Sanitize(buf[:n])
	return r
}

func dialDetail(err error, timeout time.Duration) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connect: connection refused"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Sprintf("connect: no answer within %s (filtered)", timeout)
	}
	return "connect: " + err.Error()
}

// UDP probes: one fixed request per well-known port; anything else gets an empty
// datagram (which still draws an ICMP port unreachable from a closed port).
var udpProbes = map[uint16]struct {
	name string
	data []byte
}{
	// DNS: query id 0x5057, no recursion, "." NS IN.
	53: {"dns", []byte{0x50, 0x57, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}},
	// NTP: v4 client request (LI 0, VN 4, mode 3), 48 bytes.
	123: {"ntp", append([]byte{0x23}, make([]byte, 47)...)},
	// SNMP: v3 engine-ID discovery (empty user, no auth); agents answer with a report.
	161: {"snmp", []byte{0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69, 0x02, 0x03, 0x00, 0xff, 0xe3,
		0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04,
		0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c, 0x02, 0x02, 0x37, 0xf0, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x30, 0x00}},
	// memcached: UDP frame header (id 0x5057, seq 0, 1 datagram) + "version".
	11211: {"memcached", append([]byte{0x50, 0x57, 0, 0, 0, 1, 0, 0}, []byte("version\r\n")...)},
}

func (p *Prober) udp(ctx context.Context, t Target) Result {
	probe, ok := udpProbes[t.Port]
	if !ok {
		probe.name, probe.data = "udp", []byte{}
	}
	r := Result{Probe: probe.name, Target: t}
	d := net.Dialer{Timeout: p.Timeout}
	conn, err := d.DialContext(ctx, "udp", t.String())
	if err != nil {
		r.Result, r.Detail = ResultUnreachable, "udp: "+err.Error()
		return r
	}
	defer conn.Close()
	start := time.Now()
	_ = conn.SetDeadline(start.Add(p.Timeout))
	if _, err := conn.Write(probe.data); err != nil {
		r.Result, r.Detail = ResultUnreachable, "udp send: "+err.Error()
		return r
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	r.RTT = time.Since(start)
	switch {
	case err == nil:
		r.Result, r.Banner = ResultConfirmed, describeUDP(probe.name, buf[:n], p.MaxBanner)
	case errors.Is(err, syscall.ECONNREFUSED):
		r.Result, r.Detail = ResultUnreachable, "icmp port unreachable"
	default:
		r.Result = ResultNoResponse
		r.Detail = fmt.Sprintf("no answer within %s (open or filtered; UDP silence is not closed)", p.Timeout)
		if probe.name == "udp" {
			r.Detail += "; no protocol probe for this port (e.g. WireGuard never answers unauthenticated packets)"
		}
	}
	return r
}

func describeUDP(name string, b []byte, max int) string {
	switch name {
	case "dns":
		if len(b) >= 12 && b[0] == 0x50 && b[1] == 0x57 && b[2]&0x80 != 0 {
			return fmt.Sprintf("dns: rcode=%d answers=%d", b[3]&0x0f, binary.BigEndian.Uint16(b[6:8])+binary.BigEndian.Uint16(b[8:10]))
		}
	case "ntp":
		if len(b) >= 48 && b[0]&0x07 == 4 {
			return fmt.Sprintf("ntp: version=%d stratum=%d", (b[0]>>3)&0x07, b[1])
		}
	case "memcached":
		if len(b) > 8 {
			return "memcached: " + Sanitize(trimTo([]byte(strings.TrimSpace(string(b[8:]))), max))
		}
	case "snmp":
		if len(b) > 0 && b[0] == 0x30 {
			return fmt.Sprintf("snmp: v3 response (%d bytes)", len(b))
		}
	}
	return Sanitize(trimTo(b, max))
}

func trimTo(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// Sanitize keeps printable ASCII and escapes everything else as \xNN.
func Sanitize(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		switch {
		case c == '\r':
			s.WriteString(`\r`)
		case c == '\n':
			s.WriteString(`\n`)
		case c >= 0x20 && c < 0x7f:
			s.WriteByte(c)
		default:
			fmt.Fprintf(&s, `\x%02x`, c)
		}
	}
	return s.String()
}
