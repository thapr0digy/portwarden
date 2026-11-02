package spool

import (
	"bytes"
	"errors"
	"testing"
)

func TestRecordRoundTrip(t *testing.T) {
	for _, m := range []Msg{
		{Subject: "asm.h.listener.opened", ID: "ev-1", Seq: 42, Data: []byte("payload")},
		{},
	} {
		rec, err := encodeRecord(m)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := decodeRecord(append(rec, 0xAA, 0xBB)) // trailing bytes belong to the next record
		if err != nil {
			t.Fatal(err)
		}
		if n != len(rec) {
			t.Fatalf("consumed %d, want %d", n, len(rec))
		}
		if got.Subject != m.Subject || got.ID != m.ID || got.Seq != m.Seq || !bytes.Equal(got.Data, m.Data) {
			t.Fatalf("got %+v, want %+v", got, m)
		}
	}
}

func TestRecordRejectsBadCRC(t *testing.T) {
	rec, _ := encodeRecord(Msg{Subject: "s", ID: "i", Seq: 1, Data: []byte("data")})
	rec[len(rec)-1] ^= 0xFF
	if _, _, err := decodeRecord(rec); !errors.Is(err, errCorrupt) {
		t.Fatalf("err = %v, want errCorrupt", err)
	}
}

func TestRecordTornAndBadLength(t *testing.T) {
	rec, _ := encodeRecord(Msg{Subject: "s", ID: "i", Seq: 1, Data: []byte("data")})
	for _, cut := range []int{0, 3, headerLen, len(rec) - 1} {
		if _, _, err := decodeRecord(rec[:cut]); !errors.Is(err, errTorn) {
			t.Fatalf("cut %d: err = %v, want errTorn", cut, err)
		}
	}
	bad := append([]byte(nil), rec...)
	bad[0], bad[1], bad[2], bad[3] = 0xFF, 0xFF, 0xFF, 0xFF
	if _, _, err := decodeRecord(bad); !errors.Is(err, errCorrupt) {
		t.Fatalf("err = %v, want errCorrupt", err)
	}
}

func TestEncodeRejectsOversizeSubject(t *testing.T) {
	if _, err := encodeRecord(Msg{Subject: string(make([]byte, 70000))}); err == nil {
		t.Fatal("want error")
	}
}
