package leadertest

import (
	"fmt"
	"strings"
	"testing"
)

type recorder struct{ errs []string }

func (r *recorder) Helper()                           {}
func (r *recorder) Errorf(format string, args ...any) { r.errs = append(r.errs, fmt.Sprintf(format, args...)) }
func (r *recorder) Fatal(args ...any)                 { panic(fmt.Sprint(args...)) }
func (r *recorder) Fatalf(format string, args ...any) { panic(fmt.Sprintf(format, args...)) }

func TestUnfencedWrites(t *testing.T) {
	var bad recorder
	UnfencedWrites(&bad, "testdata/bad", "tx")
	all := strings.Join(bad.errs, "\n")
	if len(bad.errs) != 2 || !strings.Contains(all, "SetX calls pool.Exec") || !strings.Contains(all, "Sneaky writes through pool.QueryRow") {
		t.Fatalf("bad: %q", bad.errs)
	}
	var good recorder
	UnfencedWrites(&good, "testdata/good", "tx")
	if len(good.errs) != 0 {
		t.Fatalf("good: %q", good.errs)
	}
}
