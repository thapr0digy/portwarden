package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMintAndRender(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	for _, args := range [][]string{
		{"mint", "--dir", dir, "--role", "host", "--host", "abc123"},
		{"mint", "--dir", dir, "--role", "inventory"},
		{"render", "--dir", dir, "--out", filepath.Join(dir, "users.conf")},
	} {
		if err := run(args, &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "users.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"asm.abc123.heartbeat"`) || !strings.Contains(string(b), `"_INBOX_inventory.>"`) {
		t.Fatalf("render output:\n%s", b)
	}
	if err := run([]string{"mint", "--dir", dir, "--role", "alerter", "--host", "x"}, &out); err == nil {
		t.Fatal("--host with a service role must be refused")
	}
	if err := run([]string{"bogus"}, &out); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}
