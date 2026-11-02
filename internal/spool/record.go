package spool

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
)

// Msg is one message waiting to be published. Its ID and Seq are fixed when it
// is queued so a resend after a crash is a true duplicate.
type Msg struct {
	Subject, ID string
	Seq         uint64
	Data        []byte
}

const (
	headerLen = 8 // u32 LE length | u32 LE crc32c(payload)
	// payloadMin is the payload of a message with empty subject, id and data.
	payloadMin = 2 + 2 + 8
	// maxPayload bounds a decoded length so a corrupt header cannot ask for gigabytes.
	maxPayload = 64 << 20
)

var (
	castagnoli = crc32.MakeTable(crc32.Castagnoli)

	errTorn    = errors.New("spool: truncated record")
	errCorrupt = errors.New("spool: corrupt record")
	errTooBig  = errors.New("spool: subject or id longer than 65535 bytes")
)

// encodeRecord returns the on-disk form of m:
// u32 LE length | u32 LE crc32c(payload) | payload, where payload is
// u16 len subject | subject | u16 len id | id | u64 seq | data (all LE).
func encodeRecord(m Msg) ([]byte, error) {
	if len(m.Subject) > math.MaxUint16 || len(m.ID) > math.MaxUint16 {
		return nil, errTooBig
	}
	n := payloadMin + len(m.Subject) + len(m.ID) + len(m.Data)
	if n > maxPayload {
		return nil, errTooBig
	}
	rec := make([]byte, headerLen, headerLen+n)
	rec = binary.LittleEndian.AppendUint16(rec, uint16(len(m.Subject)))
	rec = append(rec, m.Subject...)
	rec = binary.LittleEndian.AppendUint16(rec, uint16(len(m.ID)))
	rec = append(rec, m.ID...)
	rec = binary.LittleEndian.AppendUint64(rec, m.Seq)
	rec = append(rec, m.Data...)
	binary.LittleEndian.PutUint32(rec[0:4], uint32(n))
	binary.LittleEndian.PutUint32(rec[4:8], crc32.Checksum(rec[headerLen:], castagnoli))
	return rec, nil
}

// decodeRecord parses the record at the start of buf and returns it with the
// number of bytes it occupies. errTorn means buf ends inside the record;
// errCorrupt means the length or checksum is wrong.
func decodeRecord(buf []byte) (Msg, int, error) {
	if len(buf) < headerLen {
		return Msg{}, 0, errTorn
	}
	n := int(binary.LittleEndian.Uint32(buf[0:4]))
	if n < payloadMin || n > maxPayload {
		return Msg{}, 0, errCorrupt
	}
	if len(buf) < headerLen+n {
		return Msg{}, 0, errTorn
	}
	p := buf[headerLen : headerLen+n]
	if crc32.Checksum(p, castagnoli) != binary.LittleEndian.Uint32(buf[4:8]) {
		return Msg{}, 0, errCorrupt
	}
	sl := int(binary.LittleEndian.Uint16(p))
	if 2+sl+2+8 > n {
		return Msg{}, 0, errCorrupt
	}
	subject := string(p[2 : 2+sl])
	p = p[2+sl:]
	il := int(binary.LittleEndian.Uint16(p))
	if 2+il+8 > len(p) {
		return Msg{}, 0, errCorrupt
	}
	id := string(p[2 : 2+il])
	p = p[2+il:]
	return Msg{
		Subject: subject,
		ID:      id,
		Seq:     binary.LittleEndian.Uint64(p),
		Data:    append([]byte(nil), p[8:]...),
	}, headerLen + n, nil
}
