package access

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeJournalctl writes a script that records its arguments and prints one record, then
// follows (sleeps) or exits with an error as journalctl would.
func fakeJournalctl(t *testing.T, follow bool) (path, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	end := "exec sleep 60"
	if !follow {
		end = "echo 'Failed to seek to cursor: Invalid argument' >&2; exit 1"
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\necho '{\"MESSAGE\":\"x\",\"__CURSOR\":\"c9\"}'\n" + end + "\n"
	path = filepath.Join(dir, "journalctl")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func TestExecJournalFollowsOnlySSHDsUnits(t *testing.T) {
	if err := journalAccess(); err != nil {
		t.Skipf("this user may not read the journal: %v", err)
	}
	path, argsFile := fakeJournalctl(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := ExecJournal(path)(ctx, "s=abc")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	go func() {
		_ = readLines(r, func(l []byte) {
			lines = append(lines, string(l))
			cancel() // stop the follow after the first record
		})
	}()
	<-ctx.Done()
	_ = r.Close()
	args, _ := os.ReadFile(argsFile)
	for _, want := range []string{"--follow", "--output=json", "--after-cursor=s=abc", "_SYSTEMD_UNIT=ssh.service", "_SYSTEMD_UNIT=sshd.service"} {
		if !strings.Contains(string(args), want+"\n") {
			t.Errorf("journalctl args lack %s:\n%s", want, args)
		}
	}
	if strings.Contains(string(args), "--since") {
		t.Errorf("a cursor follow is not bounded by --since: %s", args)
	}
}

func TestExecJournalSaysWhyItEnded(t *testing.T) {
	if err := journalAccess(); err != nil {
		t.Skipf("this user may not read the journal: %v", err)
	}
	path, argsFile := fakeJournalctl(t, false)
	r, err := ExecJournal(path)(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err == nil || !strings.Contains(err.Error(), "Failed to seek to cursor") {
		t.Fatalf("close = %v", err)
	}
	if args, _ := os.ReadFile(argsFile); !strings.Contains(string(args), "--since=-24h\n") {
		t.Fatalf("a first follow starts a day back: %s", args)
	}
}
