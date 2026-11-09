package spool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

// recordBudget bounds one decodeRecord: it copies at most one record (maxPayload).
var recordBudget = fuzzcheck.Budget{Time: time.Second, Base: 1 << 20, PerByte: 2}

// openBudget bounds one Open and drain of a fuzzed spool directory (file I/O included).
var openBudget = fuzzcheck.Budget{Time: 5 * time.Second, Base: 8 << 20, PerByte: 16}

func seedRecords(tb testing.TB) [][]byte {
	tb.Helper()
	var out [][]byte
	var all []byte
	for _, m := range []Msg{
		{Subject: "asm.h.listener.opened", ID: "ev-1", Seq: 42, Data: []byte("payload")},
		{Subject: "asm.h.heartbeat", ID: "01JABCDEF", Seq: 1 << 40, Data: bytes.Repeat([]byte{0xA5}, 300)},
		{},
	} {
		rec, err := encodeRecord(m)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, rec)
		all = append(all, rec...)
	}
	badCRC := bytes.Clone(out[0])
	badCRC[len(badCRC)-1] ^= 0xFF
	return append(out, all, out[0][:len(out[0])-1], badCRC)
}

// A spool segment is the agent's own file, but a crash, a full disk or tampering can
// leave anything in it: decoding must not panic, stay within budget, and anything
// that decodes must be exactly the encoding of what it decoded to.
func FuzzDecodeRecord(f *testing.F) {
	for _, s := range seedRecords(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, buf []byte) {
		var m Msg
		var n int
		var err error
		fuzzcheck.Bounded(t, recordBudget, len(buf), func() { m, n, err = decodeRecord(buf) })
		if err != nil {
			return
		}
		rec, err := encodeRecord(m)
		if err != nil {
			t.Fatalf("decoded %+v does not encode: %v", m, err)
		}
		if !bytes.Equal(rec, buf[:n]) {
			t.Fatalf("round trip differs:\n in  %x\n out %x", buf[:n], rec)
		}
	})
}

// Opening a spool whose segment and cursor hold anything must not panic or fail on
// the content; the segment is left holding only whole records, and every message
// Open counts can be read back.
func FuzzOpen(f *testing.F) {
	for _, s := range seedRecords(f) {
		f.Add(s, "0 0")
	}
	f.Add(seedRecords(f)[3], "0 37")
	f.Add(seedRecords(f)[3], "1 0")
	f.Fuzz(func(t *testing.T, seg []byte, cursor string) {
		dir := t.TempDir()
		segFile := filepath.Join(dir, segName(0))
		if err := os.WriteFile(segFile, seg, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, cursorFile), []byte(cursor), 0o600); err != nil {
			t.Fatal(err)
		}
		fuzzcheck.Bounded(t, openBudget, len(seg)+len(cursor), func() {
			s, err := Open(dir, 64<<20, 1<<20)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer s.Close()
			n := s.Len()
			for i := range n {
				m, ok := s.Head()
				if !ok {
					t.Fatalf("Len %d but Head empty after %d", n, i)
				}
				s.Pop(m.ID)
			}
			if s.Len() != 0 {
				t.Fatalf("Len %d after draining %d", s.Len(), n)
			}
		})
		b, err := os.ReadFile(segFile)
		if err != nil {
			return // removed as fully consumed
		}
		for pos := 0; pos < len(b); {
			_, n, err := decodeRecord(b[pos:])
			if err != nil {
				t.Fatalf("segment left with a bad record at %d: %v", pos, err)
			}
			pos += n
		}
	})
}
