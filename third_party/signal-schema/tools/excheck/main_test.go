package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The example corpus is the conformance check: every example decodes strictly,
// validates and round-trips, every type has one, and the registry, the oneof and
// the README agree.
func TestExamples(t *testing.T) {
	fails, files := check(filepath.Join("..", "..", "examples"), filepath.Join("..", "..", "README.md"))
	if files == 0 {
		t.Fatal("no example files read: the check would prove nothing")
	}
	for _, f := range fails {
		t.Error(f)
	}
}

// The check fails on a broken example, so a green run means something.
func TestExamplesCheckCatchesABadExample(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join("..", "..", "examples", "asm.finding.reported.json")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(body), `"rule_id"`, `"rule_idd"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "asm.finding.reported.json"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	fails, _ := check(dir, filepath.Join("..", "..", "README.md"))
	var decodeFail, missing bool
	for _, f := range fails {
		decodeFail = decodeFail || strings.HasPrefix(f, "asm.finding.reported.json:")
		missing = missing || strings.HasPrefix(f, "no example for asm.agent.started")
	}
	if !decodeFail || !missing {
		t.Fatalf("want a decode failure and a missing example, got %q", fails)
	}
}
