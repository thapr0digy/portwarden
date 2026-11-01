//go:build linux

package baseline

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -tags linux owners ../../bpf/owners.bpf.c -- -I../../bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/probes"
)

// ownerRecord mirrors struct owner in bpf/owners.bpf.c, the record the iterator writes
// per listening socket per process. It is written by hand: the C struct is only a local
// variable, so the object carries no BTF for bpf2go to generate it from.
type ownerRecord struct {
	Cookie uint64
	Tgid   uint32
	Uid    uint32
	Comm   [16]int8
}

// Owners runs the task_file iterator once and returns, by socket cookie, the processes
// holding each TCP listening socket. Exe comes from /proc/<pid>/exe and is empty when
// that can't be read.
func Owners() (map[uint64][]model.Process, error) {
	var objs ownersObjects
	if err := loadOwnersObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load owners iterator: %w", probes.WithVerifierLog(err))
	}
	defer objs.Close()

	iter, err := link.AttachIter(link.IterOptions{Program: objs.Owners})
	if err != nil {
		return nil, fmt.Errorf("attach owners iterator: %w", err)
	}
	defer iter.Close()

	reader, err := iter.Open()
	if err != nil {
		return nil, fmt.Errorf("open owners iterator: %w", err)
	}
	defer reader.Close()

	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read owners iterator: %w", err)
	}
	return decodeOwners(raw)
}

// decodeOwners groups the iterator's records by cookie. A process that holds the same
// socket under several descriptors (dup, or inherited across exec) is listed once.
func decodeOwners(raw []byte) (map[uint64][]model.Process, error) {
	recordSize := binary.Size(ownerRecord{})
	if len(raw)%recordSize != 0 {
		return nil, fmt.Errorf("owners iterator output is %d bytes, not a multiple of %d", len(raw), recordSize)
	}
	records := make([]ownerRecord, len(raw)/recordSize)
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, records); err != nil {
		return nil, fmt.Errorf("decode owners records: %w", err)
	}

	type holder struct {
		cookie uint64
		pid    uint32
	}
	seen := make(map[holder]bool, len(records))
	exes := make(map[uint32]string)
	owners := make(map[uint64][]model.Process)
	for _, r := range records {
		if seen[holder{r.Cookie, r.Tgid}] {
			continue
		}
		seen[holder{r.Cookie, r.Tgid}] = true

		exe, ok := exes[r.Tgid]
		if !ok {
			exe = probes.ExePath(r.Tgid)
			exes[r.Tgid] = exe
		}
		owners[r.Cookie] = append(owners[r.Cookie], model.Process{
			PID:  r.Tgid,
			UID:  r.Uid,
			Comm: probes.CommString(r.Comm),
			Exe:  exe,
		})
	}
	return owners, nil
}
