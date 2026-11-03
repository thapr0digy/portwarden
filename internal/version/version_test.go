package version

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintIfRequested(t *testing.T) {
	var b bytes.Buffer
	Version = "1.2.3"
	if !printIfRequested([]string{"/usr/bin/portwarden-agent", "--version"}, &b) || !strings.HasPrefix(b.String(), "portwarden-agent 1.2.3 (go") {
		t.Fatalf("got %q", b.String())
	}
	for _, args := range [][]string{{"x"}, {"x", "--version", "y"}, {"x", "--help"}} {
		if printIfRequested(args, &b) {
			t.Fatalf("%v printed a version", args)
		}
	}
}
