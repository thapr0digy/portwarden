package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/backend/testnats"
	"github.com/thapr0digy/portwarden/internal/cmd/alerter"
	"github.com/thapr0digy/portwarden/internal/cmd/cli"
	"github.com/thapr0digy/portwarden/internal/cmd/inventory"
	"github.com/thapr0digy/portwarden/internal/cmd/natsauth"
	"github.com/thapr0digy/portwarden/internal/cmd/verifier"
	"github.com/thapr0digy/portwarden/internal/cmd/watch"
	pwnatsauth "github.com/thapr0digy/portwarden/internal/natsauth"
)

// TestMain doubles as the portwarden binary for the child-process tests: with
// PW_DISPATCH_HELPER set it is main, so a symlink to the test binary runs exactly what an
// installed symlink to /usr/bin/portwarden runs.
func TestMain(m *testing.M) {
	if os.Getenv("PW_DISPATCH_HELPER") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// call records one fake subcommand run.
type call struct {
	cmd  string
	args []string
}

func fakeCommands(calls *[]call) map[string]command {
	cmds := map[string]command{}
	for name := range commands {
		cmds[name] = command{run: func(_ context.Context, args []string, stdout, _ io.Writer) error {
			*calls = append(*calls, call{name, slices.Clone(args)})
			fmt.Fprint(stdout, "ran "+name)
			if slices.Contains(args, "--fail") {
				return cli.Exit(3)
			}
			if slices.Contains(args, "--unreported") {
				return errors.New("boom")
			}
			return nil
		}, summary: "fake " + name}
	}
	return cmds
}

// argv[0] picks the command: only "portwarden" (any directory) takes it from argv[1], only
// portwarden-<command> runs that command; nothing else runs anything.
func TestDispatch(t *testing.T) {
	for _, c := range []struct {
		argv      []string
		want      []call
		code      int
		stdout    string
		stderrHas string
	}{
		{argv: []string{"/usr/bin/portwarden", "alerter", "--config", "a.json"}, want: []call{{"alerter", []string{"--config", "a.json"}}}, stdout: "ran alerter"},
		{argv: []string{"portwarden", "inventory", "forget-host", "h1"}, want: []call{{"inventory", []string{"forget-host", "h1"}}}, stdout: "ran inventory"},
		{argv: []string{"/usr/bin/portwarden-alerter", "--config", "a.json"}, want: []call{{"alerter", []string{"--config", "a.json"}}}, stdout: "ran alerter"},
		{argv: []string{"/usr/bin/portwarden-inventory"}, want: []call{{"inventory", []string{}}}, stdout: "ran inventory"},
		{argv: []string{"./portwarden-verifier", "--config", "v.json"}, want: []call{{"verifier", []string{"--config", "v.json"}}}, stdout: "ran verifier"},
		{argv: []string{"portwarden-natsauth", "mint", "--dir", "d", "--role", "admin"}, want: []call{{"natsauth", []string{"mint", "--dir", "d", "--role", "admin"}}}, stdout: "ran natsauth"},
		{argv: []string{"portwarden-watch", "--since", "0s"}, want: []call{{"watch", []string{"--since", "0s"}}}, stdout: "ran watch"},
		// A compatibility name passes its arguments as they are: no second dispatch.
		{argv: []string{"portwarden-alerter", "verifier"}, want: []call{{"alerter", []string{"verifier"}}}, stdout: "ran alerter"},
		{argv: []string{"portwarden", "alerter", "--fail"}, want: []call{{"alerter", []string{"--fail"}}}, code: 3, stdout: "ran alerter"},
		{argv: []string{"portwarden", "watch", "--unreported"}, want: []call{{"watch", []string{"--unreported"}}}, code: 1, stdout: "ran watch", stderrHas: "portwarden: boom"},
		{argv: []string{"portwarden", "help", "verifier"}, want: []call{{"verifier", []string{"--help"}}}, stdout: "ran verifier"},
		{argv: []string{"portwarden", "help"}, stdout: "usage: portwarden <command>"},
		{argv: []string{"portwarden", "--help"}, stdout: "usage: portwarden <command>"},
		{argv: []string{"portwarden", "version"}, stdout: "portwarden dev ("},
		{argv: []string{"portwarden", "--version"}, stdout: "portwarden dev ("},
		// Everything below runs nothing, prints the usage on stderr and exits 2.
		{argv: nil, code: 2, stderrHas: "no program name"},
		{argv: []string{"portwarden"}, code: 2, stderrHas: "usage: portwarden"},
		{argv: []string{"portwarden", "agent"}, code: 2, stderrHas: `unknown command "agent"`},
		{argv: []string{"portwarden", "portwarden-alerter"}, code: 2, stderrHas: `unknown command "portwarden-alerter"`},
		{argv: []string{"portwarden", "Alerter"}, code: 2, stderrHas: `unknown command "Alerter"`},
		{argv: []string{"portwarden", "help", "agent"}, code: 2, stderrHas: `unknown command "agent"`},
		{argv: []string{"portwarden", "help", "alerter", "x"}, code: 2, stderrHas: "usage: portwarden"},
		{argv: []string{"portwarden", "version", "x"}, code: 2, stderrHas: "usage: portwarden"},
		{argv: []string{"/usr/bin/portwarden-agent"}, code: 2, stderrHas: `unknown command name "portwarden-agent"`},
		{argv: []string{"portwarden-help"}, code: 2, stderrHas: `unknown command name "portwarden-help"`},
		{argv: []string{"portwarden-version"}, code: 2, stderrHas: `unknown command name "portwarden-version"`},
		{argv: []string{"portwarden-"}, code: 2, stderrHas: `unknown command name "portwarden-"`},
		{argv: []string{"alerter", "--config", "a.json"}, code: 2, stderrHas: `unknown command name "alerter"`},
		{argv: []string{"/tmp/pw", "alerter"}, code: 2, stderrHas: `unknown command name "pw"`},
		{argv: []string{"portwarden-alerter.old"}, code: 2, stderrHas: `unknown command name "portwarden-alerter.old"`},
		{argv: []string{"xportwarden-alerter"}, code: 2, stderrHas: `unknown command name "xportwarden-alerter"`},
		{argv: []string{"portwarden.test", "alerter"}, code: 2, stderrHas: `unknown command name "portwarden.test"`},
		{argv: []string{""}, code: 2, stderrHas: "unknown command name"},
	} {
		var calls []call
		var stdout, stderr bytes.Buffer
		code := dispatch(context.Background(), fakeCommands(&calls), c.argv, &stdout, &stderr)
		if code != c.code {
			t.Errorf("%q: exit %d, want %d (stderr %q)", c.argv, code, c.code, stderr.String())
		}
		if !reflect.DeepEqual(calls, c.want) {
			t.Errorf("%q: ran %v, want %v", c.argv, calls, c.want)
		}
		if !strings.HasPrefix(stdout.String(), c.stdout) || (c.stdout == "" && stdout.Len() != 0) {
			t.Errorf("%q: stdout %q, want it to start with %q", c.argv, stdout.String(), c.stdout)
		}
		if !strings.Contains(stderr.String(), c.stderrHas) || (c.stderrHas == "" && stderr.Len() != 0) {
			t.Errorf("%q: stderr %q, want %q", c.argv, stderr.String(), c.stderrHas)
		}
	}
}

// The real table: exactly the five former binaries, each its own package's Run.
func TestCommandTable(t *testing.T) {
	want := map[string]runFunc{
		"inventory": inventory.Run, "alerter": alerter.Run, "verifier": verifier.Run,
		"natsauth": natsauth.Run, "watch": watch.Run,
	}
	if len(commands) != len(want) {
		t.Fatalf("commands %v, want %v", slices.Sorted(maps.Keys(commands)), slices.Sorted(maps.Keys(want)))
	}
	for name, run := range want {
		c, ok := commands[name]
		if !ok {
			t.Fatalf("no command %q", name)
		}
		if reflect.ValueOf(c.run).Pointer() != reflect.ValueOf(run).Pointer() {
			t.Errorf("%s runs the wrong function", name)
		}
	}
}

// installed makes a bin directory like the backend .deb's: portwarden and a
// portwarden-<command> symlink per command, here all pointing at this test binary.
func installed(t *testing.T, extra ...string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	names := []string{program}
	for name := range commands {
		names = append(names, namePrefix+name)
	}
	for _, n := range append(names, extra...) {
		if err := os.Symlink(self, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type result struct {
	code           int
	stdout, stderr string
}

func runBin(t *testing.T, path string, args ...string) result {
	t.Helper()
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "PW_DISPATCH_HELPER=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	return result{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()}
}

// logTime is the one field that differs between two runs of the same JSON log.
var logTime = regexp.MustCompile(`"time":"[^"]*"`)

// A command started through its compatibility symlink behaves like the subcommand: the
// same stdout, stderr and exit status for help, version, a bad flag, a missing config and
// a bad argument, and each has the status its former binary had.
func TestCompatNameIsTheSubcommand(t *testing.T) {
	bin := installed(t)
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, c := range []struct {
		cmd    string
		args   []string
		code   int
		output string // in stdout or stderr
	}{
		{"inventory", []string{"--help"}, 0, "Usage of portwarden-inventory:\n  -config string\n    \tconfig file (JSON) (default \"/etc/portwarden/inventory.json\")"},
		{"alerter", []string{"--help"}, 0, "Usage of portwarden-alerter:\n  -config string\n    \tconfig file (JSON) (default \"/etc/portwarden/alerter.json\")"},
		{"verifier", []string{"-h"}, 0, "Usage of portwarden-verifier:\n  -config string\n    \tconfig file (JSON) (default \"/etc/portwarden/verifier.json\")"},
		{"watch", []string{"--help"}, 0, "Usage of portwarden-watch:\n  -host string"},
		{"natsauth", []string{"--help"}, 2, "portwarden-natsauth: usage: portwarden-natsauth mint --dir D --role host|inventory|alerter|verifier|admin [--host ID]"},
		{"natsauth", []string{"mint", "--help"}, 0, "Usage of portwarden-natsauth mint:"},
		{"inventory", []string{"forget-host", "--bogus"}, 1, "portwarden-inventory forget-host: flag provided but not defined: -bogus\nusage: portwarden-inventory forget-host"},
		{"inventory", []string{"--version"}, 0, "portwarden-inventory dev ("},
		{"alerter", []string{"-version"}, 0, "portwarden-alerter dev ("},
		{"verifier", []string{"--version"}, 0, "portwarden-verifier dev ("},
		{"natsauth", []string{"--version"}, 0, "portwarden-natsauth dev ("},
		{"watch", []string{"--version"}, 0, "portwarden-watch dev ("},
		{"inventory", []string{"--bogus"}, 2, "flag provided but not defined: -bogus\nUsage of portwarden-inventory:"},
		{"alerter", []string{"--bogus"}, 2, "flag provided but not defined: -bogus\nUsage of portwarden-alerter:"},
		{"verifier", []string{"--bogus"}, 2, "flag provided but not defined: -bogus\nUsage of portwarden-verifier:"},
		{"watch", []string{"--since", "-1s"}, 2, "portwarden-watch: --since must not be negative"},
		{"natsauth", []string{"bogus"}, 2, "portwarden-natsauth: usage:"},
		{"inventory", []string{"--config", missing}, 1, `"msg":"portwarden-inventory","err":"`},
		{"alerter", []string{"--config", missing}, 1, `"msg":"portwarden-alerter","err":"`},
		{"verifier", []string{"--config", missing}, 1, `"msg":"portwarden-verifier","err":"`},
		{"watch", []string{"--nats-url", "nats://127.0.0.1:1"}, 1, "portwarden-watch: connect nats://127.0.0.1:1"},
	} {
		sub := runBin(t, filepath.Join(bin, program), append([]string{c.cmd}, c.args...)...)
		compat := runBin(t, filepath.Join(bin, namePrefix+c.cmd), c.args...)
		sub.stderr, compat.stderr = logTime.ReplaceAllString(sub.stderr, ""), logTime.ReplaceAllString(compat.stderr, "")
		if sub != compat {
			t.Errorf("%s %q: the subcommand gave %+v, the symlink %+v", c.cmd, c.args, sub, compat)
		}
		if sub.code != c.code || !strings.Contains(sub.stdout+sub.stderr, c.output) {
			t.Errorf("%s %q: exit %d, output %q; want exit %d and %q", c.cmd, c.args, sub.code, sub.stdout+sub.stderr, c.code, c.output)
		}
	}
}

// Through an unexpected name the binary runs nothing: usage on stderr, exit 2.
func TestUnknownNameRunsNothing(t *testing.T) {
	bin := installed(t, "portwarden-agent", "portwarden-help", "pw", "alerter")
	for _, name := range []string{"portwarden-agent", "portwarden-help", "pw", "alerter"} {
		r := runBin(t, filepath.Join(bin, name), "--version")
		if r.code != 2 || r.stdout != "" || !strings.Contains(r.stderr, "unknown command name") || !strings.Contains(r.stderr, "usage: portwarden") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// natsauth mint through either name writes the seed 0600 and refuses to overwrite it.
func TestNatsauthMintThroughEitherName(t *testing.T) {
	bin := installed(t)
	dir := filepath.Join(t.TempDir(), "users")
	r := runBin(t, filepath.Join(bin, "portwarden-natsauth"), "mint", "--dir", dir, "--role", "alerter")
	if r.code != 0 || !strings.Contains(r.stdout, "minted alerter") {
		t.Fatalf("mint: %+v", r)
	}
	seed := filepath.Join(dir, "alerter.nk")
	fi, err := os.Stat(seed)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("seed mode %v, want 0600", fi.Mode().Perm())
	}
	before, err := os.ReadFile(seed)
	if err != nil {
		t.Fatal(err)
	}
	r = runBin(t, filepath.Join(bin, program), "natsauth", "mint", "--dir", dir, "--role", "alerter")
	if r.code != 2 || !strings.HasPrefix(r.stderr, "portwarden-natsauth: ") {
		t.Fatalf("second mint: %+v", r)
	}
	after, err := os.ReadFile(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the second mint overwrote the seed")
	}
	r = runBin(t, filepath.Join(bin, program), "natsauth", "render", "--dir", dir)
	if r.code != 0 || !strings.Contains(r.stdout, `"_INBOX_alerter.>"`) {
		t.Fatalf("render: %+v", r)
	}
}

// A service started through its symlink and through the subcommand runs the same: the
// verifier connects with its own nkey, logs the same lines, and stops cleanly (exit 0) on
// SIGTERM and SIGINT, as its unit's ExecStart starts it.
func TestServiceThroughEitherName(t *testing.T) {
	ts := testnats.Start(t)
	ts.CreateStream(t)
	cfg := filepath.Join(t.TempDir(), "verifier.json")
	body := fmt.Sprintf(`{"nats": {"url": %q, "nkey_file": %q}, "checker": "pw-test", "allow_cidrs": ["127.0.0.0/8"]}`,
		ts.URL, ts.Seeds[pwnatsauth.RoleVerifier])
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := installed(t)
	var logs []string
	for _, c := range []struct {
		argv []string
		sig  syscall.Signal
	}{
		{[]string{filepath.Join(bin, namePrefix+"verifier"), "--config", cfg}, syscall.SIGTERM},
		{[]string{filepath.Join(bin, program), "verifier", "--config", cfg}, syscall.SIGTERM},
		{[]string{filepath.Join(bin, namePrefix+"verifier"), "--config", cfg}, syscall.SIGINT},
	} {
		cmd := exec.Command(c.argv[0], c.argv[1:]...)
		cmd.Env = append(os.Environ(), "PW_DISPATCH_HELPER=1")
		stderr, err := cmd.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		lines := make(chan string, 64)
		go func() {
			defer close(lines)
			sc := bufio.NewScanner(stderr)
			for sc.Scan() {
				lines <- sc.Text()
			}
		}()
		var got []string
		deadline := time.After(10 * time.Second)
	wait:
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("%q exited before running: %q", c.argv, got)
				}
				got = append(got, logTime.ReplaceAllString(l, ""))
				if strings.Contains(l, `"msg":"verifier running"`) {
					break wait
				}
			case <-deadline:
				_ = cmd.Process.Kill()
				t.Fatalf("%q never ran: %q", c.argv, got)
			}
		}
		if err := cmd.Process.Signal(c.sig); err != nil {
			t.Fatal(err)
		}
		for l := range lines {
			got = append(got, logTime.ReplaceAllString(l, ""))
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("%q after %v: %v (%q)", c.argv, c.sig, err, got)
		}
		logs = append(logs, strings.Join(got, "\n"))
	}
	for i := 1; i < len(logs); i++ {
		if logs[i] != logs[0] {
			t.Errorf("run %d logged\n%s\nrun 0 logged\n%s", i, logs[i], logs[0])
		}
	}
}
