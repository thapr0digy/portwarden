package publish

import (
	"slices"
	"testing"

	"github.com/thapr0digy/portwarden/internal/model"
)

// The published process carries the redacted command line; the model's stays raw (proxy
// discovery and the docker-proxy parser read it in memory).
func TestProcessCmdlineIsRedacted(t *testing.T) {
	raw := []string{"app", "--password", "hunter2", "--port=80", "PGPASSWORD=pw"}
	p := model.Process{PID: 7, Exe: "/usr/bin/app", Cmdline: slices.Clone(raw)}
	got := processToProto(p).GetCmdline()
	want := []string{"app", "--password", "***", "--port=80", "PGPASSWORD=***"}
	if !slices.Equal(got, want) {
		t.Fatalf("published cmdline %q, want %q", got, want)
	}
	if !slices.Equal(p.Cmdline, raw) {
		t.Fatalf("model cmdline changed to %q", p.Cmdline)
	}
}

func TestProcessWithoutCmdlineStaysEmpty(t *testing.T) {
	if got := processToProto(model.Process{PID: 1}).GetCmdline(); got != nil {
		t.Fatalf("cmdline %q, want nil", got)
	}
}
