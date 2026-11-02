package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// parseSize reads a positive byte count: a plain integer, or one followed by KiB, MiB
// or GiB (powers of 1024, case-sensitive). Surrounding spaces are ignored.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	num, shift := s, 0
	for _, u := range []struct {
		suffix string
		shift  int
	}{{"KiB", 10}, {"MiB", 20}, {"GiB", 30}} {
		if strings.HasSuffix(s, u.suffix) {
			num, shift = strings.TrimSuffix(s, u.suffix), u.shift
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: want an integer with an optional KiB, MiB or GiB suffix", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("size %q must be positive", s)
	}
	if n > math.MaxInt64>>shift {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return n << shift, nil
}
