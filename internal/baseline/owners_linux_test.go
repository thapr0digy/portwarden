//go:build linux

package baseline

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// The records are mirrored by hand for binary.Read; bpf2go's types give the C layout.
func TestRecordSizesMatchC(t *testing.T) {
	if got, want := binary.Size(ownerRecord{}), int(unsafe.Sizeof(ownersOwner{})); got != want {
		t.Errorf("ownerRecord is %d bytes, struct owner is %d", got, want)
	}
	if got, want := binary.Size(udpRecord{}), int(unsafe.Sizeof(udpUdpSocket{})); got != want {
		t.Errorf("udpRecord is %d bytes, struct udp_socket is %d", got, want)
	}
}
