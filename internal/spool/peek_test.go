package spool

import (
	"fmt"
	"os"
	"testing"
)

func seqs(ms []Msg) string {
	out := make([]uint64, len(ms))
	for i, m := range ms {
		out[i] = m.Seq
	}
	return fmt.Sprint(out)
}

// popAll pops what a sender delivered, in order.
func popAll(s *Spool, ms []Msg) {
	for _, m := range ms {
		s.Pop(m.ID)
	}
}

func TestPeekIsDrainOrderAcrossSegmentsAndAPartlyPoppedFirstSegment(t *testing.T) {
	s := open(t, t.TempDir(), 1<<20, 100) // ~2 records per segment
	for i := uint64(1); i <= 9; i++ {
		s.Push(msg(i))
	}
	popAll(s, s.Peek(1, 1<<20)) // segment 0 is now half consumed
	if got := seqs(s.Peek(100, 1<<20)); got != "[2 3 4 5 6 7 8 9]" {
		t.Fatalf("peek = %s", got)
	}
	if s.Len() != 8 {
		t.Fatalf("Peek removed messages: Len = %d", s.Len())
	}
	batch := s.Peek(3, 1<<20)
	if seqs(batch) != "[2 3 4]" {
		t.Fatalf("peek 3 = %s", seqs(batch))
	}
	popAll(s, batch)
	if got := seqs(s.Peek(100, 1<<20)); got != "[5 6 7 8 9]" {
		t.Fatalf("after popping a batch = %s", got)
	}
}

func TestPeekAfterReopenResumesAtTheCursor(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, 1<<20, 100)
	for i := uint64(1); i <= 6; i++ {
		s.Push(msg(i))
	}
	popAll(s, s.Peek(3, 1<<20))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, dir, 1<<20, 100)
	if got := seqs(s.Peek(100, 1<<20)); got != "[4 5 6]" {
		t.Fatalf("peek after reopen = %s", got)
	}
}

func TestPeekBoundsBytesButAlwaysReturnsTheHead(t *testing.T) {
	s := open(t, t.TempDir(), 1<<20, 1<<20)
	for i := uint64(1); i <= 4; i++ {
		s.Push(msg(i)) // Data "data-N": 6 bytes each
	}
	if got := seqs(s.Peek(100, 13)); got != "[1 2]" {
		t.Fatalf("13 bytes = %s, want two 6-byte messages", got)
	}
	if got := seqs(s.Peek(100, 1)); got != "[1]" {
		t.Fatalf("a head larger than the budget = %s, want it alone", got)
	}
	if got := s.Peek(0, 1<<20); got != nil {
		t.Fatalf("n 0 = %s", seqs(got))
	}
}

func TestPeekMemoryOnlyAndEmpty(t *testing.T) {
	s := open(t, "", 1<<20, 1<<20)
	if got := s.Peek(10, 1<<20); got != nil {
		t.Fatalf("empty spool peeked %s", seqs(got))
	}
	for i := uint64(1); i <= 3; i++ {
		s.Push(msg(i))
	}
	if got := seqs(s.Peek(10, 1<<20)); got != "[1 2 3]" {
		t.Fatalf("memory peek = %s", got)
	}
}

func TestPeekCoversDiskThenTheMemoryTail(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	s := open(t, dir, 1<<20, 1<<20)
	s.Push(msg(1))
	s.Push(msg(2))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700) //nolint:errcheck
	s.segBytes = 1 // the next push needs a new segment, which fails: it goes to the tail
	s.Push(msg(3))
	s.Push(msg(4))
	if got := seqs(s.Peek(10, 1<<20)); got != "[1 2 3 4]" {
		t.Fatalf("disk then tail = %s", got)
	}
	if got := seqs(s.Peek(3, 1<<20)); got != "[1 2 3]" {
		t.Fatalf("n stops inside the tail = %s", got)
	}
	popAll(s, s.Peek(2, 1<<20)) // the disk records
	if got := seqs(s.Peek(10, 1<<20)); got != "[3 4]" {
		t.Fatalf("tail only = %s", got)
	}
}
