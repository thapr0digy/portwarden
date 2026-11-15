package cejson

import (
	"testing"
	"time"

	"github.com/slidehq/signal/schema/validate"
)

// FuzzDecodeBatch: the CloudEvents JSON decoder reads untrusted bytes; it must never
// panic, and an element without an event always has a Problem.
func FuzzDecodeBatch(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"specversion":"1.0"}]`))
	f.Add([]byte(`[null, 1, "x", {"id": {}}]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		els, err := DecodeBatch(body, validate.Options{Now: func() time.Time { return time.Unix(1762783500, 0) }})
		if err != nil {
			return
		}
		for _, e := range els {
			if e.Event == nil && e.Problem == nil {
				t.Fatalf("element %d has neither event nor problem", e.Index)
			}
		}
	})
}
