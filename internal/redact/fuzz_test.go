package redact

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
)

// redactBudget bounds one Cmdline. Linux caps an argv at a few MiB; a fuzz input is far
// smaller, so this bounds the rule matching itself. The seeds allocate at most 40 KiB.
var redactBudget = fuzzcheck.Budget{Time: 2 * time.Second, Base: 4 << 20, PerByte: 256}

// seedCmdlines cover every rule family of the package doc, in the shapes the unit tests
// use; each is an argv joined by NUL, as /proc/<pid>/cmdline holds it.
var seedCmdlines = [][]string{
	{"app", "--password", "hunter2"},
	{"app", "--password=hunter2", "--port", "80"},
	{"app", "-password", "x", "--password-file", "/run/pw"},
	{"redis-server", "--requirepass", "r", "--masterauth", "m"},
	{"mysql", "-uroot", "-psecret", "db"},
	{"sudo", "env", "A=1", "redis-cli", "-a", "pw"},
	{"sshpass", "-p", "pw", "ssh", "host"},
	{"curl", "-u", "user:pw", "--proxy-user", "a:b", "-H", "Authorization: Bearer tok"},
	{"curl", "-H", "Proxy-Authorization: Basic abc", "https://u:p@example.com/x?token=t&a=1"},
	{"sh", "-c", "mysql -p'x y' && curl -H 'Authorization: Token z' http://h"},
	{"psql", "host=db user=u password=p sslmode=require"},
	{"java", "-Ddb.password=x", "-Dlog.file=/var/log/a", "-jar", "app.jar"},
	{"helm", "--set", "a=1,b.password=x,c.passwordFile=/f"},
	{"docker", "run", "--env=DB_PASSWORD=x", "-e", "MYSQL_PWD=y", "img"},
	{"app", `{"apiKey": "k", "user": "u"}`},
	{"app", "jdbc:postgresql://h/db;user=u;password=p", "ODBC=PWD=x;UID=u"},
	{"app", "--aws-secret-access-key", "a", "--client-secret", "c"},
	{"app", ""},
	{},
}

// Anyone who can start a process shapes the command line the agent publishes: any argv
// must redact without a panic, within budget, keeping its argument count, leaving its
// input alone, and redacting a value that is already redacted to itself.
func FuzzCmdline(f *testing.F) {
	for _, s := range seedCmdlines {
		f.Add(strings.Join(s, "\x00"))
	}
	for _, s := range fuzzcheck.Files(f, "../exposure/testdata/docker-proxy-cmdlines.txt") {
		for line := range strings.SplitSeq(string(s), "\n") {
			f.Add(strings.ReplaceAll(line, " ", "\x00"))
		}
	}
	f.Fuzz(func(t *testing.T, cmdline string) {
		args := strings.Split(cmdline, "\x00")
		orig := slices.Clone(args)
		var out []string
		fuzzcheck.Bounded(t, redactBudget, len(cmdline), func() { out = Cmdline(args) })
		if len(out) != len(args) {
			t.Fatalf("Cmdline(%q) has %d args, want %d", args, len(out), len(args))
		}
		if !slices.Equal(args, orig) {
			t.Fatalf("Cmdline modified its input: %q, was %q", args, orig)
		}
		if again := Cmdline(out); !slices.Equal(again, out) {
			t.Errorf("not idempotent: Cmdline(%q) = %q", out, again)
		}
	})
}
