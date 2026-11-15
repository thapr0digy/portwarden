package ingest

import (
	"net/http"
	"testing"
	"time"

	"github.com/slidehq/signal/schema/eventsv1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

// answerBudget bounds one parse: the body is at most maxAnswer (1 MiB) when read from the
// door; protobuf and protojson decoding stay linear in it.
var answerBudget = fuzzcheck.Budget{Time: 2 * time.Second, Base: 1 << 20, PerByte: 64}

// FuzzAnswer feeds the door's answer (its body, content type and Retry-After), the only
// input the agent takes from Signal, to the parsers: they must never panic, and a wait
// is never negative or over the cap however the header reads.
func FuzzAnswer(f *testing.F) {
	resp := &eventsv1.IngestResponse{Accepted: 3, Directives: []*eventsv1.Directive{{Kind: eventsv1.Directive_STOP, Reason: "off"}},
		Rejected: []*eventsv1.Rejection{{Index: 1, Code: "invalid_payload"}}, Error: &eventsv1.ErrorInfo{Code: "rate_limited"}}
	bin, _ := proto.Marshal(resp)
	js, _ := protojson.Marshal(resp)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f.Add(contentBinary, bin, "30")
	f.Add(contentJSON+"; charset=utf-8", js, now.Add(time.Minute).Format(http.TimeFormat))
	f.Add("text/html", []byte("<html>"), "-1")
	f.Add(contentBinary, []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f}, "99999999999999999999")
	f.Fuzz(func(t *testing.T, contentType string, raw []byte, retry string) {
		var d time.Duration
		fuzzcheck.Bounded(t, answerBudget, len(raw)+len(retry), func() {
			if a := decodeAnswer(contentType, raw); a != nil {
				_ = (Answer{Resp: a}).Code()
				for _, dir := range a.GetDirectives() {
					_ = dir.GetAfter().AsTime()
				}
			}
			d = retryAfter(retry, now)
		})
		if d < 0 || d > maxRetryAfter {
			t.Fatalf("Retry-After %q = %s", retry, d)
		}
	})
}
