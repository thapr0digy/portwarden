package cli

import (
	"errors"
	"flag"
	"fmt"
	"testing"
)

func TestExitCodes(t *testing.T) {
	for _, c := range []struct {
		err      error
		code     int
		reported bool
	}{
		{nil, 0, false},
		{Exit(0), 0, false},
		{Exit(1), 1, true},
		{Exit(2), 2, true},
		{fmt.Errorf("wrapped: %w", Exit(3)), 3, true},
		{errors.New("not reported"), 1, false},
		{FlagExit(flag.ErrHelp), 0, false},
		{FlagExit(errors.New("flag provided but not defined: -x")), 2, true},
	} {
		if got := Code(c.err); got != c.code {
			t.Errorf("Code(%v) = %d, want %d", c.err, got, c.code)
		}
		if got := Reported(c.err); got != c.reported {
			t.Errorf("Reported(%v) = %v, want %v", c.err, got, c.reported)
		}
	}
}
