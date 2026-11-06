package pg

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	asmv1 "github.com/thapr0digy/portwarden/gen/asm/v1"
)

// Item 5: an invalid cloud_resource is logged once per distinct value per host (a later,
// different bad value is logged too), never with the value itself, and the hosts
// remembered are bounded.
func TestItem5BadResourceBoundedAndLogsChange(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	badResource = newBadResources(maxBadResourceHosts)
	t.Cleanup(func() { badResource = newBadResources(maxBadResourceHosts) })

	bad := func(v string) *asmv1.HostInfo {
		return &asmv1.HostInfo{Cloud: "gcp", InstanceId: "1", CloudResource: v}
	}
	logs := func() int { return strings.Count(buf.String(), "dropping an invalid cloud_resource") }
	for range 2 {
		if r := checkedResource("h1", bad("projects/x/secret-one")); r != "" {
			t.Fatalf("stored %q", r)
		}
	}
	if logs() != 1 {
		t.Fatalf("same bad value logged %d times:\n%s", logs(), buf.String())
	}
	checkedResource("h1", bad("projects/x/secret-two"))
	if logs() != 2 {
		t.Fatalf("a changed bad value was not logged:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "secret-") {
		t.Fatalf("the value was logged:\n%s", buf.String())
	}
	if ok := checkedResource("h1", &asmv1.HostInfo{Cloud: "gcp", InstanceId: "1",
		CloudResource: "projects/my-project-1/zones/europe-west1-b/instances/1"}); ok == "" {
		t.Fatal("a valid value was dropped")
	}
	for i := range maxBadResourceHosts + 50 {
		checkedResource(fmt.Sprintf("host-%d", i), bad("bad"))
	}
	if n := badResource.len(); n > maxBadResourceHosts {
		t.Fatalf("%d hosts remembered, cap %d", n, maxBadResourceHosts)
	}
}

// The least recently seen host is the one forgotten.
func TestBadResourcesEvictsLeastRecent(t *testing.T) {
	b := newBadResources(2)
	if !b.changed("a", "1") || !b.changed("b", "1") {
		t.Fatal("first values not new")
	}
	if b.changed("a", "1") {
		t.Fatal("repeat reported as new")
	}
	b.changed("c", "1") // evicts b (a was seen more recently)
	if b.changed("a", "1") || !b.changed("b", "1") {
		t.Fatal("wrong host evicted")
	}
}
