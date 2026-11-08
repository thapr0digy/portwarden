package fuzzcheck

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// recorder is a testing.TB that keeps its failures instead of failing the test.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

var sink []byte

func TestBoundedFailsAnAllocationOverBudget(t *testing.T) {
	r := &recorder{TB: t}
	Bounded(r, Budget{Time: time.Minute, Base: 1 << 10, PerByte: 1}, 10, func() { sink = make([]byte, 1<<20) })
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "allocated") {
		t.Fatalf("errors = %q, want one allocation failure", r.errs)
	}
}

func TestBoundedFailsASlowCall(t *testing.T) {
	r := &recorder{TB: t}
	Bounded(r, Budget{Time: time.Millisecond, Base: 1 << 30}, 0, func() { time.Sleep(20 * time.Millisecond) })
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "took") {
		t.Fatalf("errors = %q, want one time failure", r.errs)
	}
}

func TestBoundedPassesWithinBudget(t *testing.T) {
	r := &recorder{TB: t}
	s := Bounded(r, Budget{Time: time.Minute, Base: 4 << 20}, 0, func() { sink = make([]byte, 1<<20) })
	if len(r.errs) != 0 {
		t.Fatalf("errors = %q", r.errs)
	}
	if s.Bytes < 1<<20 {
		t.Fatalf("measured %d bytes, want at least the 1 MiB allocated", s.Bytes)
	}
}
