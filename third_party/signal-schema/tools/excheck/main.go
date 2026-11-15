// Command excheck is the example check: every example under examples/ decodes
// strictly, passes the validators and survives a JSON round trip; every registry
// type has an example; the registry, the Event.data oneof and README.md's registry
// table agree.
//
//	go run ./tools/excheck examples README.md   (from schema/)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/slidehq/signal/schema/cejson"
	"github.com/slidehq/signal/schema/eventsv1"
	"github.com/slidehq/signal/schema/validate"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: excheck <examples dir> <README.md>")
		os.Exit(2)
	}
	failures, files := check(os.Args[1], os.Args[2])
	for _, f := range failures {
		fmt.Println("FAIL", f)
	}
	fmt.Printf("%d files, %d types, %d failures\n", files, len(eventsv1.Registry), len(failures))
	if len(failures) > 0 {
		os.Exit(1)
	}
}

// check returns one line per failure and the number of example files read.
func check(dir, readme string) ([]string, int) {
	var fails []string
	fail := func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }

	for _, f := range registryAgreesWithOneof() {
		fail("%s", f)
	}
	for _, f := range readmeAgrees(readme) {
		fail("%s", f)
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(paths) == 0 {
		fail("no examples in %s", dir)
		return fails, 0
	}
	covered := map[string]bool{}
	for _, p := range paths {
		base := filepath.Base(p)
		body, err := os.ReadFile(p) //nolint:gosec // G304: the examples directory the developer or make names; a dev tool, not a server
		if err != nil {
			fail("%s: %v", base, err)
			continue
		}
		switch base {
		case "batch.response.json":
			var r eventsv1.IngestResponse
			if err := (protojson.UnmarshalOptions{}).Unmarshal(body, &r); err != nil {
				fail("%s: %v", base, err)
			}
		case "batch.request.json":
			elems, err := cejson.DecodeBatch(body, validate.Options{})
			if err != nil {
				fail("%s: %v", base, err)
				continue
			}
			for _, e := range elems {
				if e.Problem != nil {
					fail("%s[%d]: %v", base, e.Index, e.Problem)
					continue
				}
				covered[e.Event.GetType()] = true
				if f := roundTrip(e.Event); f != "" {
					fail("%s[%d]: %s", base, e.Index, f)
				}
			}
		default:
			ev, err := cejson.DecodeEvent(body, validate.Options{})
			if err != nil {
				fail("%s: %v", base, err)
				continue
			}
			if typ := ev.GetType(); base != typ+".json" && !strings.HasPrefix(base, typ+".") {
				fail("%s: holds a %s event; name it %s.json or %s.<variant>.json", base, typ, typ, typ)
			}
			covered[ev.GetType()] = true
			if f := roundTrip(ev); f != "" {
				fail("%s: %s", base, f)
			}
		}
	}
	for _, t := range eventsv1.Registry {
		if !covered[t.Type] {
			fail("no example for %s", t.Type)
		}
	}
	return fails, len(paths)
}

// roundTrip encodes ev and decodes it again; the result must be the same event,
// and the binary form must decode to it too.
func roundTrip(ev *eventsv1.Event) string {
	js, err := cejson.EncodeEvent(ev)
	if err != nil {
		return "encode: " + err.Error()
	}
	back, err := cejson.DecodeEvent(js, validate.Options{})
	if err != nil {
		return "decode of the encoded form: " + err.Error()
	}
	if !proto.Equal(ev, back) {
		return "the JSON round trip changed the event"
	}
	bin, err := proto.Marshal(&eventsv1.Batch{Events: []*eventsv1.Event{ev}})
	if err != nil {
		return "binary encode: " + err.Error()
	}
	d, err := validate.DecodeBinary(bin, validate.Options{})
	if err != nil {
		return "binary decode: " + err.Error()
	}
	if p := d.Elements[0].Problem; p != nil {
		return "binary form invalid: " + p.Error()
	}
	if !proto.Equal(ev, d.Elements[0].Event) {
		return "the binary round trip changed the event"
	}
	return ""
}

// registryAgreesWithOneof: every data case has a registry row naming its message,
// every row names a real case, and no type string repeats.
func registryAgreesWithOneof() []string {
	var out []string
	cases := map[protoreflect.FieldNumber]protoreflect.Name{}
	fields := eventsv1.DataOneof().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		cases[fd.Number()] = fd.Message().Name()
	}
	rows := map[protoreflect.FieldNumber]bool{}
	types := map[string]bool{}
	for _, t := range eventsv1.Registry {
		if types[t.Type] {
			out = append(out, fmt.Sprintf("registry: %s listed twice", t.Type))
		}
		types[t.Type] = true
		msg, ok := cases[t.Case]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("registry: %s names case %d, not a case of Event.data", t.Type, t.Case))
		case msg != t.Message:
			out = append(out, fmt.Sprintf("registry: %s names %s, case %d is %s", t.Type, t.Message, t.Case, msg))
		}
		rows[t.Case] = true
	}
	for n, msg := range cases {
		if !rows[n] {
			out = append(out, fmt.Sprintf("Event.data case %d (%s) has no registry type", n, msg))
		}
	}
	sort.Strings(out)
	return out
}

var readmeRow = regexp.MustCompile("(?m)^\\| `(asm\\.[a-z_.]+)` \\|")

// readmeAgrees: the README's registry table lists exactly the registry's types.
func readmeAgrees(readme string) []string {
	body, err := os.ReadFile(readme) //nolint:gosec // G304: the README path the developer or make names; a dev tool, not a server
	if err != nil {
		return []string{fmt.Sprintf("README: %v", err)}
	}
	listed := map[string]bool{}
	for _, m := range readmeRow.FindAllStringSubmatch(string(body), -1) {
		listed[m[1]] = true
	}
	var out []string
	for _, t := range eventsv1.Registry {
		if !listed[t.Type] {
			out = append(out, fmt.Sprintf("README: registry table lacks %s", t.Type))
		}
		delete(listed, t.Type)
	}
	for t := range listed {
		out = append(out, fmt.Sprintf("README: registry table lists %s, not in the registry", t))
	}
	sort.Strings(out)
	return out
}
