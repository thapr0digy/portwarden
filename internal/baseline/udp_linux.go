//go:build linux

package baseline

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -tags linux -type udp_socket udp ../../bpf/udp.bpf.c -- -I../../bpf

import (
	"fmt"

	"github.com/thapr0digy/portwarden/internal/probes"
)

// udpRecord mirrors struct udp_socket in bpf/udp.bpf.c, padding included
// (TestRecordSizesMatchC checks the size against bpf2go's udpUdpSocket).
type udpRecord struct {
	Cookie uint64
	Family uint16
	Port   uint16
	Addr   [16]uint8
	_      [4]byte
}

// UDPSockets runs the iter/udp program once and returns every UDP socket bound to an
// explicit port in the calling thread's network namespace, kernel sockets (VXLAN,
// WireGuard) included.
func UDPSockets() ([]diagSocket, error) {
	var objs udpObjects
	if err := loadUdpObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load udp iterator: %w", probes.WithVerifierLog(err))
	}
	defer objs.Close()

	raw, err := runIter(objs.UdpSockets)
	if err != nil {
		return nil, fmt.Errorf("udp iterator: %w", err)
	}
	records, err := decodeRecords[udpRecord](raw)
	if err != nil {
		return nil, fmt.Errorf("udp sockets: %w", err)
	}
	socks := make([]diagSocket, 0, len(records))
	for _, r := range records {
		addr, err := recordAddr(r.Family, r.Addr)
		if err != nil {
			return nil, fmt.Errorf("udp socket %#x: %w", r.Cookie, err)
		}
		socks = append(socks, diagSocket{Cookie: r.Cookie, Family: uint8(r.Family), Addr: addr, Port: r.Port})
	}
	return socks, nil
}
