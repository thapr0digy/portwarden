package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func msg(seq uint64) Msg {
	return Msg{Subject: "asm.h.listener.opened", ID: fmt.Sprintf("ev-%d", seq), Seq: seq, Data: []byte(fmt.Sprintf("data-%d", seq))}
}

func open(t *testing.T, dir string, maxBytes, segBytes int64) *Spool {
	t.Helper()
	s, err := Open(dir, maxBytes, segBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func drain(s *Spool) []uint64 {
	var seqs []uint64
	for {
		m, ok := s.Head()
		if !ok {
			return seqs
		}
		seqs = append(seqs, m.Seq)
		s.Pop(m.Seq)
	}
}

func segFiles(t *testing.T, dir string) []string {
	t.Helper()
	f, err := filepath.Glob(filepath.Join(dir, "*.seg"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFIFOAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, 1<<20, 100) // ~2 records per segment
	for i := uint64(1); i <= 10; i++ {
		s.Push(msg(i))
	}
	if n := len(segFiles(t, dir)); n < 3 {
		t.Fatalf("segments = %d, want several", n)
	}
	got := drain(s)
	if len(got) != 10 {
		t.Fatalf("drained %v", got)
	}
	for i, seq := range got {
		if seq != uint64(i+1) {
			t.Fatalf("order = %v", got)
		}
	}
	if s.Len() != 0 || s.Dropped() != 0 {
		t.Fatalf("Len=%d Dropped=%d", s.Len(), s.Dropped())
	}
	if n := len(segFiles(t, dir)); n > 1 {
		t.Fatalf("consumed segments not deleted: %d left", n)
	}
}

func TestReopenResumesUnsent(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1<<20, 100)
	for i := uint64(1); i <= 5; i++ {
		s.Push(msg(i))
	}
	s.Pop(1)
	s.Pop(2)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, dir, 1<<20, 100)
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if h, _ := s.Head(); h.Seq != 3 || h.ID != "ev-3" || string(h.Data) != "data-3" {
		t.Fatalf("head = %+v", h)
	}
	s.Push(msg(6))
	if got := drain(s); fmt.Sprint(got) != "[3 4 5 6]" {
		t.Fatalf("got %v", got)
	}
}

func TestTornTailIsTruncated(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1<<20, 1<<20)
	s.Push(msg(1))
	s.Push(msg(2))
	_ = s.Close()
	seg := segFiles(t, dir)[0]
	rec, _ := encodeRecord(msg(3))
	f, _ := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.Write(rec[:len(rec)/2])
	_ = f.Close()

	s = open(t, dir, 1<<20, 1<<20)
	if s.Dropped() != 1 {
		t.Fatalf("Dropped = %d, want 1", s.Dropped())
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	s.Push(msg(4)) // appends after the truncation point, not after the garbage
	if got := drain(s); fmt.Sprint(got) != "[1 2 4]" {
		t.Fatalf("got %v", got)
	}
}

func TestBadCRCEndsSegment(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1<<20, 1<<20)
	s.Push(msg(1))
	s.Push(msg(2))
	s.Push(msg(3))
	_ = s.Close()
	seg := segFiles(t, dir)[0]
	b, _ := os.ReadFile(seg)
	rec, _ := encodeRecord(msg(1))
	b[len(rec)+headerLen+3] ^= 0xFF // inside the second record's payload
	_ = os.WriteFile(seg, b, 0o600)

	s = open(t, dir, 1<<20, 1<<20)
	if s.Dropped() < 1 || s.Len() != 1 {
		t.Fatalf("Dropped=%d Len=%d", s.Dropped(), s.Len())
	}
}

func TestOverflowDropsOldestSegment(t *testing.T) {
	dir := t.TempDir()
	rec, _ := encodeRecord(msg(1))
	rs := int64(len(rec))
	// Two records per segment; room for about three segments.
	s := open(t, dir, rs*6+8, rs*2+2)
	for i := uint64(1); i <= 12; i++ {
		s.Push(msg(i))
	}
	if s.Overflowed() == 0 || s.Overflowed() != s.Dropped() {
		t.Fatalf("Overflowed=%d Dropped=%d", s.Overflowed(), s.Dropped())
	}
	got := drain(s)
	if uint64(len(got))+s.Overflowed() != 12 {
		t.Fatalf("kept %v, overflowed %d", got, s.Overflowed())
	}
	if got[len(got)-1] != 12 {
		t.Fatalf("newest lost: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] != got[i-1]+1 {
			t.Fatalf("gap in %v", got)
		}
	}
}

func TestOverflowCountsOnlyUnsent(t *testing.T) {
	dir := t.TempDir()
	rec, _ := encodeRecord(msg(1))
	rs := int64(len(rec))
	s := open(t, dir, rs*4+8, rs*2+2) // two records per segment, room for two segments
	s.Push(msg(1))
	s.Push(msg(2))
	s.Pop(1) // the first segment now holds one unsent record
	s.Push(msg(3))
	s.Push(msg(4))
	s.Push(msg(5)) // third segment pushes the first one out
	if s.Overflowed() != 1 || s.Dropped() != 1 {
		t.Fatalf("Overflowed=%d Dropped=%d, want 1 (only #2 was unsent)", s.Overflowed(), s.Dropped())
	}
	if got := drain(s); fmt.Sprint(got) != "[3 4 5]" {
		t.Fatalf("got %v", got)
	}
}

func TestPopIgnoresStaleSeq(t *testing.T) {
	s := open(t, t.TempDir(), 1<<20, 1<<20)
	s.Push(msg(1))
	s.Push(msg(2))
	s.Pop(2)
	if h, _ := s.Head(); h.Seq != 1 {
		t.Fatalf("head = %d, want 1", h.Seq)
	}
	s.Pop(1)
	s.Pop(1)
	if h, _ := s.Head(); h.Seq != 2 || s.Len() != 1 {
		t.Fatalf("head = %d Len=%d", h.Seq, s.Len())
	}
}

func TestDiscardCountsDropped(t *testing.T) {
	s := open(t, t.TempDir(), 1<<20, 1<<20)
	s.Push(msg(1))
	s.Discard(9)
	s.Discard(1)
	if s.Dropped() != 1 || s.Overflowed() != 0 || s.Len() != 0 {
		t.Fatalf("Dropped=%d Overflowed=%d Len=%d", s.Dropped(), s.Overflowed(), s.Len())
	}
}

func TestPushFallsBackToMemoryWhenDirUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	s := open(t, dir, 1<<20, 1<<20)
	s.Push(msg(1))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700) //nolint:errcheck
	// A fresh segment is needed to fail: force a roll with a tiny segment size.
	s.segBytes = 1
	s.Push(msg(2))
	s.Push(msg(3))
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if h, _ := s.Head(); h.Seq != 1 {
		t.Fatalf("head = %d", h.Seq)
	}
	// Disk comes back: the tail drains to disk ahead of new messages, in order.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.Push(msg(4))
	if got := drain(s); fmt.Sprint(got) != "[1 2 3 4]" {
		t.Fatalf("order = %v", got)
	}
}

func TestPushWithNoDiskSegmentYetFallsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	s := open(t, dir, 1<<20, 1<<20)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700) //nolint:errcheck
	s.Push(msg(1))
	if h, ok := s.Head(); !ok || h.Seq != 1 {
		t.Fatalf("head = %+v %v", h, ok)
	}
}

func TestMemoryOnly(t *testing.T) {
	s := open(t, "", 3<<10, 0)
	for i := uint64(1); i <= 5; i++ {
		s.Push(msg(i))
	}
	if s.Dropped() != 2 || s.Overflowed() != 2 {
		t.Fatalf("Dropped=%d Overflowed=%d", s.Dropped(), s.Overflowed())
	}
	if got := drain(s); fmt.Sprint(got) != "[3 4 5]" {
		t.Fatalf("got %v", got)
	}
}

func TestReadySignalsOnPush(t *testing.T) {
	for _, dir := range []string{"", t.TempDir()} {
		s := open(t, dir, 1<<20, 1<<20)
		select {
		case <-s.Ready():
			t.Fatal("ready before push")
		default:
		}
		s.Push(msg(1))
		s.Push(msg(2)) // second signal must not block
		select {
		case <-s.Ready():
		default:
			t.Fatal("no ready signal")
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	s := open(t, t.TempDir(), 1<<20, 512)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				s.Push(msg(uint64(w*100 + i + 1)))
				if h, ok := s.Head(); ok {
					s.Pop(h.Seq)
				}
				_ = s.Len()
			}
		}(w)
	}
	wg.Wait()
}
