package conf

import (
	"fmt"
	"strings"
	"testing"
)

// A hostile include pattern over a wide tree of unreadable entries ends in bounded
// notes, watch list and work, with one cut-off note.
func TestReadBudgetBoundsHostileGlobs(t *testing.T) {
	fsys := MemFS{}
	for i := range 200 {
		for j := range 100 {
			fsys[fmt.Sprintf("/d/%03d/%03d/x", i, j)] = nil // each /d/i/j is a directory: unreadable as a file
		}
	}
	r := NewReader()
	for _, p := range Glob(fsys, r, "/d/*/*") {
		r.Read(fsys, p)
	}
	res := r.Finish(nil)
	if len(res.Notes) > MaxNotes+1 || len(res.Watch) > MaxWatch || r.ops > MaxOps {
		t.Fatalf("notes=%d watch=%d ops=%d", len(res.Notes), len(res.Watch), r.ops)
	}
	all := strings.Join(res.Notes, "\n")
	if !strings.Contains(all, "cut off") || !strings.Contains(res.Notes[len(res.Notes)-1], "more notes") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

func TestEnterRefusesIncludeCycles(t *testing.T) {
	fsys := MemFS{"/a": []byte("x")}
	r := NewReader()
	_, ok, leave := r.Enter(fsys, "/a")
	if !ok {
		t.Fatal("first read")
	}
	if _, ok2, _ := r.Enter(fsys, "/a"); ok2 {
		t.Fatal("a file being read must not be entered again")
	}
	leave()
	if _, ok3 := r.Read(fsys, "/a"); !ok3 {
		t.Fatal("after leaving, the file may be read again")
	}
	if res := r.Finish(nil); !strings.Contains(strings.Join(res.Notes, ","), "include cycle at /a") || len(res.Untrusted) != 0 {
		t.Fatalf("result = %+v", res)
	}
}
