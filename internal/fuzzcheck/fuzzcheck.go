// Package fuzzcheck holds what the fuzz targets share: a guard that fails an input whose
// parse runs too long or allocates too much, and helpers to seed a target from files.
// Only tests import it.
package fuzzcheck

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"testing"
	"time"
)

// Budget is what one parse of one input may spend.
type Budget struct {
	// Time bounds the wall time of the call.
	Time time.Duration
	// Base and PerByte bound the bytes allocated: Base + PerByte*len(input).
	Base, PerByte uint64
}

// Alloc is the allocation bound for an input of n bytes.
func (b Budget) Alloc(n int) uint64 { return b.Base + b.PerByte*uint64(n) }

// Spent is what one call cost.
type Spent struct {
	Time  time.Duration
	Bytes uint64
}

// Measure runs fn once and returns its wall time and the bytes it allocated. The fuzz
// engine runs one input at a time per worker process, so the TotalAlloc delta is fn's.
func Measure(fn func()) Spent {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	fn()
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	return Spent{Time: took, Bytes: after.TotalAlloc - before.TotalAlloc}
}

// PeakHeap runs fn and returns the largest heap (live and not yet collected objects)
// seen while it ran, sampled every 200 µs, and the heap before it started. Sampling can
// miss a short peak, so the result is a lower bound of the true peak.
func PeakHeap(fn func()) (peak, before uint64) {
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	read := func() uint64 { metrics.Read(sample); return sample[0].Value.Uint64() }
	runtime.GC()
	before = read()
	done := make(chan struct{})
	stopped := make(chan struct{})
	var highest uint64
	go func() {
		defer close(stopped)
		t := time.NewTicker(200 * time.Microsecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				highest = max(highest, read())
			}
		}
	}()
	fn()
	close(done)
	<-stopped
	return max(highest, read()), before
}

// Bounded runs fn (the parse of an input of n bytes) and fails t when it exceeds b.
// A panic in fn is left to the fuzz engine, which records the input.
func Bounded(t testing.TB, b Budget, n int, fn func()) Spent {
	t.Helper()
	s := Measure(fn)
	if s.Time > b.Time {
		t.Errorf("parse of %d bytes took %v, budget %v", n, s.Time, b.Time)
	}
	if limit := b.Alloc(n); s.Bytes > limit {
		t.Errorf("parse of %d bytes allocated %d bytes, budget %d", n, s.Bytes, limit)
	}
	if os.Getenv("PORTWARDEN_FUZZ_REPORT") != "" {
		t.Logf("fuzzcheck: %d bytes in, %v (%.1f%% of budget), %d bytes allocated (%.1f%% of budget)",
			n, s.Time, 100*float64(s.Time)/float64(b.Time), s.Bytes, 100*float64(s.Bytes)/float64(b.Alloc(n)))
	}
	return s
}

// Files returns the contents of the files matching each glob pattern, in order; it fails
// t when a pattern matches nothing, so a moved fixture cannot leave a target unseeded.
func Files(t testing.TB, patterns ...string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range patterns {
		names, err := filepath.Glob(p)
		if err != nil || len(names) == 0 {
			t.Fatalf("seed pattern %q matched nothing (%v)", p, err)
		}
		for _, n := range names {
			b, err := os.ReadFile(n)
			if err != nil {
				t.Fatalf("seed %s: %v", n, err)
			}
			out = append(out, b)
		}
	}
	return out
}
