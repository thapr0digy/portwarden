package cejson

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slidehq/signal/schema/validate"
)

// event is a valid JSON event with its attributes and data as given.
func event(extra, data string) string {
	if data == "" {
		data = `{"kind":"EXPOSURE","state":"PRESENT","rule_id":"git-config"}`
	}
	return `{"specversion":"1.0","id":"01JC90AAAA0000000000000F01","type":"asm.finding.reported",` +
		`"source":"urn:asm:scanner:edge-1","subject":"url:https://app.example.com/.git/config",` +
		`"time":"2026-11-10T11:00:00Z"` + extra + `,"data":` + data + `}`
}

func TestDecodeEventHostile(t *testing.T) {
	cases := []struct {
		name string
		body string
		code validate.Code // "" with malformed: ErrMalformed; both empty: valid
		malf bool
	}{
		{"valid", event("", ""), "", false},
		{"valid with camelCase data", event("", `{"kind":"EXPOSURE","ruleId":"git-config"}`), "", false},
		{"invalid UTF-8", strings.Replace(event("", ""), "edge-1", "edge-\xff", 1), "", true},
		{"duplicate attribute", event(`,"id":"01JC90AAAA0000000000000F02"`, ""), validate.CodeInvalidPayload, false},
		{"unknown attribute", event(`,"severity":"high"`, ""), validate.CodeInvalidPayload, false},
		{"unknown data field", event("", `{"rule_id":"x","rule_idd":"y"}`), validate.CodeInvalidPayload, false},
		{"duplicate data field", event("", `{"rule_id":"x","rule_id":"y"}`), validate.CodeInvalidPayload, false},
		{"non-string attribute", event(`,"sequence":5`, ""), validate.CodeInvalidPayload, false},
		{"wrong specversion", strings.Replace(event("", ""), `"1.0"`, `"0.3"`, 1), validate.CodeInvalidPayload, false},
		{"other datacontenttype", event(`,"datacontenttype":"text/xml"`, ""), validate.CodeInvalidPayload, false},
		{"time not RFC 3339", strings.Replace(event("", ""), "2026-11-10T11:00:00Z", "yesterday", 1), validate.CodeBadTime, false},
		{"non-canonical sequence", event(`,"runid":"01JC8Z6X4P9QK2M3N5R7T8V0WA","sequence":"007"`, ""), validate.CodeInvalidPayload, false},
		{"data not an object", event("", `"text"`), validate.CodeInvalidPayload, false},
		// No known field nests this deep, so depth is refused as an unknown field.
		{"data nested deep", event("", `{"location":`+strings.Repeat(`{"a":`, 40)+`1`+strings.Repeat(`}`, 40)+`}`), validate.CodeInvalidPayload, false},
		// encoding/json stops at 10,000 levels; attribute values must be strings.
		{"attribute nested very deep", event(`,"adapter":`+strings.Repeat("[", 20000)+strings.Repeat("]", 20000), ""), validate.CodeInvalidPayload, false},
		{"unknown type", strings.Replace(event("", ""), "asm.finding.reported", "asm.finding.invented", 1), validate.CodeUnknownType, false},
		{"not an object", `[1]`, validate.CodeInvalidPayload, false},
		{"truncated", event("", "")[:40], validate.CodeInvalidPayload, false},
		{"invalid after decoding (validator)", event("", `{"rule_id":"x","confidence":101}`), validate.CodeInvalidPayload, false},
		{"data after the object", event("", "") + "xx", validate.CodeInvalidPayload, false},
		{"a second object", event("", "") + event("", ""), validate.CodeInvalidPayload, false},
		{"null attribute", event(`,"adapter":null`, ""), validate.CodeInvalidPayload, false},
		{"lone surrogate in an attribute", event(`,"adapter":"a\ud800b"`, ""), validate.CodeInvalidPayload, false},
		{"no type, with data", strings.Replace(event("", ""), `"type":"asm.finding.reported",`, "", 1), validate.CodeInvalidPayload, false},
		{"bidi override in the subject", strings.Replace(event("", ""), "app.example.com", `app.example.com\u202e`, 1), validate.CodeInvalidPayload, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeEvent([]byte(c.body), validate.Options{})
			switch {
			case c.malf:
				if !errors.Is(err, validate.ErrMalformed) {
					t.Fatalf("want ErrMalformed, got %v", err)
				}
			case c.code == "":
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
			default:
				var p *validate.Problem
				if !errors.As(err, &p) || p.Code != c.code {
					t.Fatalf("want %s, got %v", c.code, err)
				}
			}
		})
	}
}

func TestDecodeBatchHostile(t *testing.T) {
	ok := event("", "")
	small := validate.Default
	small.MaxBatchEvents = 2
	small.MaxBatchBytes = 4096
	cases := []struct {
		name string
		body string
		want error // nil: decodes
	}{
		{"one event", "[" + ok + "]", nil},
		{"one good, one bad: per element", "[" + ok + `,{"specversion":"1.0"}]`, nil},
		{"not an array", ok, validate.ErrMalformed},
		{"empty array", "[]", validate.ErrMalformed},
		{"trailing data", "[" + ok + "] []", validate.ErrMalformed},
		{"unterminated", "[" + ok, validate.ErrMalformed},
		{"invalid UTF-8", "[" + ok + ",\"\xff\"]", validate.ErrMalformed},
		{"over the event count", "[" + ok + "," + ok + "," + ok + "]", validate.ErrBatchTooLarge},
		{"over the byte cap", "[" + strings.Repeat(" ", 4096) + ok + "]", validate.ErrBatchTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			elems, err := DecodeBatch([]byte(c.body), validate.Options{Limits: &small})
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("want %v, got %v", c.want, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if elems[0].Problem != nil {
				t.Fatalf("first element: %v", elems[0].Problem)
			}
			if len(elems) == 2 && (elems[1].Problem == nil || elems[1].Index != 1 || len(elems[1].Raw) == 0) {
				t.Fatalf("bad element not reported with its index and raw bytes: %+v", elems[1])
			}
		})
	}
}

// The example batch decodes, and its sequenced run is in order.
func TestDecodeBatchExample(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "examples", "batch.request.json"))
	if err != nil {
		t.Fatal(err)
	}
	elems, err := DecodeBatch(body, validate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range elems {
		if e.Problem != nil {
			t.Errorf("element %d: %v", e.Index, e.Problem)
		}
	}
}

// One element that does not decode leaves a hole in its run: the batch still
// decodes, and only that element carries a problem (as in binary).
func TestDecodeBatchHoleInRun(t *testing.T) {
	const run = `,"runid":"01JC8Z6X4P9QK2M3N5R7T8V0WA","sequence":"`
	withID := func(id, seq string) string {
		return strings.Replace(event(run+seq+`"`, ""), "0000000000000F01", "00000000000000"+id, 1)
	}
	body := "[" + withID("A1", "1") + "," + strings.Replace(withID("A2", "2"), `"specversion"`, `"bogus":"x","specversion"`, 1) +
		"," + withID("A3", "3") + "," + withID("A4", "5") + "]"
	_, err := DecodeBatch([]byte(body), validate.Options{})
	if err == nil || !strings.Contains(err.Error(), "events[3]") {
		t.Fatalf("gap at element 3 after a hole: want an error naming events[3], got %v", err)
	}
	body = "[" + withID("A1", "1") + "," + strings.Replace(withID("A2", "2"), `"specversion"`, `"bogus":"x","specversion"`, 1) +
		"," + withID("A3", "3") + "]"
	elems, err := DecodeBatch([]byte(body), validate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if elems[0].Problem != nil || elems[1].Problem == nil || elems[2].Problem != nil {
		t.Fatalf("want only element 1 refused, got %+v", elems)
	}
}

// A producer name may hold slashes; JSON joins name/version and splits at the last.
func TestProducerRoundTrip(t *testing.T) {
	for _, attr := range []string{`"github.com/acme/scan/1.0"`, `"github.com/acme/scan/"`, `"nmap"`, `"nmap/7.95"`} {
		in, err := DecodeEvent([]byte(event(`,"producer":`+attr, "")), validate.Options{})
		if err != nil {
			t.Fatalf("%s: %v", attr, err)
		}
		out, err := EncodeEvent(in)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeEvent(out, validate.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if a, b := in.GetProducer(), again.GetProducer(); a.GetName() != b.GetName() || a.GetVersion() != b.GetVersion() {
			t.Fatalf("%s: %v became %v", attr, a, b)
		}
	}
}
