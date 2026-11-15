package schema_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The schema module is a contract a producer depends on without Signal: it must import
// nothing from the product, directly or through a dependency.
func TestImportsNothingFromTheProduct(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		if strings.HasPrefix(p, "github.com/slidehq/") && !strings.HasPrefix(p, "github.com/slidehq/signal/schema") {
			t.Errorf("the schema module imports %s", p)
		}
	}
}
