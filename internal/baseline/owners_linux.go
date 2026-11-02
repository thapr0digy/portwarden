//go:build linux

package baseline

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -tags linux -type owner owners ../../bpf/owners.bpf.c -- -I../../bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/probes"
)

// ownerRecord mirrors struct owner in bpf/owners.bpf.c, the record the iterator writes
// per socket per process, padding included (TestRecordSizesMatchC checks the size
// against bpf2go's ownersOwner). binary.Read needs fixed-size fields in C order.
type ownerRecord struct {
	Cookie   uint64
	CgroupID uint64
	Tgid     uint32
	Uid      uint32
	NetNS    uint32
	Family   uint16
	Proto    uint8
	_        [1]byte
	Port     uint16
	Addr     [16]uint8
	Comm     [16]int8
	_        [6]byte
}

// Owners runs the task_file iterator once and returns one owner per process holding a
// TCP listening socket or a UDP socket bound to an explicit port, in any netns. Exe
// comes from /proc/<pid>/exe and is empty when that can't be read.
func Owners() ([]owner, error) {
	var objs ownersObjects
	if err := loadOwnersObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load owners iterator: %w", probes.WithVerifierLog(err))
	}
	defer objs.Close()

	raw, err := runIter(objs.Owners)
	if err != nil {
		return nil, fmt.Errorf("owners iterator: %w", err)
	}
	return decodeOwners(raw)
}

// runIter attaches an iterator program, reads its output to EOF and detaches it.
func runIter(prog *ebpf.Program) ([]byte, error) {
	iter, err := link.AttachIter(link.IterOptions{Program: prog})
	if err != nil {
		return nil, fmt.Errorf("attach: %w", err)
	}
	defer iter.Close()

	reader, err := iter.Open()
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer reader.Close()

	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return raw, nil
}

// decodeRecords splits an iterator's output into fixed-size records.
func decodeRecords[T any](raw []byte) ([]T, error) {
	var zero T
	recordSize := binary.Size(zero)
	if len(raw)%recordSize != 0 {
		return nil, fmt.Errorf("iterator output is %d bytes, not a multiple of %d", len(raw), recordSize)
	}
	records := make([]T, len(raw)/recordSize)
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, records); err != nil {
		return nil, fmt.Errorf("decode records: %w", err)
	}
	return records, nil
}

// decodeOwners turns the iterator's records into owners. A process that holds the same
// socket under several descriptors (dup, or inherited across exec) is listed once.
func decodeOwners(raw []byte) ([]owner, error) {
	records, err := decodeRecords[ownerRecord](raw)
	if err != nil {
		return nil, fmt.Errorf("owners: %w", err)
	}

	type holder struct {
		cookie uint64
		pid    uint32
	}
	seen := make(map[holder]bool, len(records))
	exes := make(map[uint32]string)
	owners := make([]owner, 0, len(records))
	for _, r := range records {
		if seen[holder{r.Cookie, r.Tgid}] {
			continue
		}
		seen[holder{r.Cookie, r.Tgid}] = true

		addr, err := recordAddr(r.Family, r.Addr)
		if err != nil {
			return nil, fmt.Errorf("owner record of pid %d: %w", r.Tgid, err)
		}
		proto, err := recordProto(r.Proto)
		if err != nil {
			return nil, fmt.Errorf("owner record of pid %d: %w", r.Tgid, err)
		}
		exe, ok := exes[r.Tgid]
		if !ok {
			exe = probes.ExePath(r.Tgid)
			exes[r.Tgid] = exe
		}
		owners = append(owners, owner{
			Cookie: r.Cookie,
			Key:    model.NewKey(r.NetNS, proto, addr, r.Port),
			Proc: model.Process{
				PID:      r.Tgid,
				UID:      r.Uid,
				Comm:     probes.CommString(r.Comm),
				Exe:      exe,
				CgroupID: r.CgroupID,
			},
		})
	}
	return owners, nil
}

func recordProto(raw uint8) (string, error) {
	switch raw {
	case unix.IPPROTO_TCP:
		return model.ProtoTCP, nil
	case unix.IPPROTO_UDP:
		return model.ProtoUDP, nil
	}
	return "", fmt.Errorf("unknown protocol %d", raw)
}

func recordAddr(family uint16, raw [16]uint8) (netip.Addr, error) {
	switch family {
	case unix.AF_INET:
		return netip.AddrFrom4([4]byte(raw[:4])), nil
	case unix.AF_INET6:
		return netip.AddrFrom16(raw), nil
	}
	return netip.Addr{}, fmt.Errorf("unknown address family %d", family)
}
