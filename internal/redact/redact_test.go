package redact

import (
	"slices"
	"strings"
	"testing"
)

func check(t *testing.T, in, want []string) {
	t.Helper()
	orig := slices.Clone(in)
	got := Cmdline(in)
	if !slices.Equal(got, want) {
		t.Errorf("Cmdline(%q)\n got %q\nwant %q", in, got, want)
	}
	if !slices.Equal(in, orig) {
		t.Errorf("Cmdline modified its input: %q", in)
	}
}

func TestSecretFlags(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"app", "--password", "hunter2"}, []string{"app", "--password", "***"}},
		{[]string{"app", "--password=hunter2"}, []string{"app", "--password=***"}},
		{[]string{"app", "-password", "hunter2"}, []string{"app", "-password", "***"}},
		{[]string{"app", "--passwd=x"}, []string{"app", "--passwd=***"}},
		{[]string{"app", "--token", "abc", "--port", "80"}, []string{"app", "--token", "***", "--port", "80"}},
		{[]string{"app", "--secret=s"}, []string{"app", "--secret=***"}},
		{[]string{"app", "--api-key", "k"}, []string{"app", "--api-key", "***"}},
		{[]string{"app", "--api_key=k"}, []string{"app", "--api_key=***"}},
		{[]string{"app", "--apikey=k"}, []string{"app", "--apikey=***"}},
		{[]string{"app", "--API-KEY=k"}, []string{"app", "--API-KEY=***"}},
		// Suffix match: a prefixed name is still a secret.
		{[]string{"app", "--db-password", "p"}, []string{"app", "--db-password", "***"}},
		{[]string{"app", "--auth-token=t"}, []string{"app", "--auth-token=***"}},
		{[]string{"app", "--client-secret", "c"}, []string{"app", "--client-secret", "***"}},
		{[]string{"app", "--aws-secret-access-key", "a"}, []string{"app", "--aws-secret-access-key", "***"}},
		{[]string{"app", "--access-key=a"}, []string{"app", "--access-key=***"}},
		{[]string{"app", "--private-key=a"}, []string{"app", "--private-key=***"}},
		{[]string{"redis-server", "--requirepass", "r"}, []string{"redis-server", "--requirepass", "***"}},
		{[]string{"redis-server", "--masterauth", "r"}, []string{"redis-server", "--masterauth", "***"}},
		// A value that looks like a flag is not consumed.
		{[]string{"mysql", "--password", "--verbose"}, []string{"mysql", "--password", "--verbose"}},
		// Flag at the end, empty value.
		{[]string{"app", "--token"}, []string{"app", "--token"}},
		{[]string{"app", "--token="}, []string{"app", "--token="}},
	} {
		check(t, tc.in, tc.want)
	}
}

func TestSecretFlagFalsePositives(t *testing.T) {
	for _, in := range [][]string{
		{"app", "--password-file", "/run/secrets/pw"},
		{"app", "--password-file=/run/secrets/pw"},
		{"app", "--token-path", "/var/lib/token"},
		{"app", "--secret-dir=/etc/app"},
		{"app", "--tokens-limit", "5"},
		{"app", "--keyfile", "/etc/ssl/key.pem"},
		{"app", "--passive", "1"},
		{"app", "--secrets-mount", "/s"},
		{"nginx", "-g", "daemon off;"},
		{"sshd", "-D", "-p", "22"},
		{"app", "--port", "8080", "--bind=0.0.0.0"},
		{"app", "-p8080"},
	} {
		check(t, in, in)
	}
}

func TestMySQLShortPassword(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"mysql", "-uroot", "-phunter2", "db"}, []string{"mysql", "-uroot", "-p***", "db"}},
		{[]string{"/usr/bin/mysqldump", "-psecret"}, []string{"/usr/bin/mysqldump", "-p***"}},
		{[]string{"mariadb", "-pX"}, []string{"mariadb", "-p***"}},
		{[]string{"mysqladmin", "-pX", "status"}, []string{"mysqladmin", "-p***", "status"}},
		// -p alone prompts: nothing to mask; -P is the port.
		{[]string{"mysql", "-p", "db"}, []string{"mysql", "-p", "db"}},
		{[]string{"mysql", "-P3306"}, []string{"mysql", "-P3306"}},
		// Other programs: -p<n> is a port or a pid.
		{[]string{"redis-server", "-p6379"}, []string{"redis-server", "-p6379"}},
		{[]string{"python3", "-phunter2"}, []string{"python3", "-phunter2"}},
	} {
		check(t, tc.in, tc.want)
	}
}

func TestKeyValueWords(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"env", "PGPASSWORD=pw", "psql"}, []string{"env", "PGPASSWORD=***", "psql"}},
		{[]string{"env", "MYSQL_PWD=pw"}, []string{"env", "MYSQL_PWD=***"}},
		{[]string{"env", "GITHUB_TOKEN=ghp_x"}, []string{"env", "GITHUB_TOKEN=***"}},
		{[]string{"env", "AWS_SECRET_ACCESS_KEY=a"}, []string{"env", "AWS_SECRET_ACCESS_KEY=***"}},
		{[]string{"env", "STRIPE_API_KEY=k"}, []string{"env", "STRIPE_API_KEY=***"}},
		{[]string{"env", "APIKEY=k"}, []string{"env", "APIKEY=***"}},
		{[]string{"env", "db_password=p"}, []string{"env", "db_password=***"}},
		// Inside one argument: a shell command and a libpq conninfo.
		{[]string{"sh", "-c", "PGPASSWORD=pw psql -h db"}, []string{"sh", "-c", "PGPASSWORD=*** psql -h db"}},
		{[]string{"app", "host=db user=app password=pw dbname=x"}, []string{"app", "host=db user=app password=*** dbname=x"}},
		// Java system properties.
		{[]string{"java", "-Djavax.net.ssl.keyStorePassword=ks", "-jar", "a.jar"}, []string{"java", "-Djavax.net.ssl.keyStorePassword=***", "-jar", "a.jar"}},
		{[]string{"java", "-Ddb.password=p"}, []string{"java", "-Ddb.password=***"}},
	} {
		check(t, tc.in, tc.want)
	}
}

func TestKeyValueFalsePositives(t *testing.T) {
	for _, in := range [][]string{
		{"env", "PWD=/home/u"},
		{"env", "PASSWORD_FILE=/run/secrets/pw"},
		{"env", "TOKEN_PATH=/var/token"},
		{"env", "SECRET_DIR=/etc/s"},
		{"env", "TOKENIZER=bert"},
		{"env", "PATH=/usr/bin", "HOME=/root"},
		{"java", "-Dfile.encoding=UTF-8", "-Xmx1g"},
		{"java", "-Dapp.token.ttl=5m"},
		{"app", "a=b"},
		{"app", "=value"},
	} {
		check(t, in, in)
	}
}

func TestURLUserinfo(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"app", "postgres://app:pw@db:5432/x"}, []string{"app", "postgres://app:***@db:5432/x"}},
		{[]string{"app", "--dsn=mysql://root:pw@localhost/db"}, []string{"app", "--dsn=mysql://root:***@localhost/db"}},
		{[]string{"git", "clone", "https://ghp_token@github.com/a/b"}, []string{"git", "clone", "https://***@github.com/a/b"}},
		{[]string{"app", "redis://:pw@cache:6379"}, []string{"app", "redis://:***@cache:6379"}},
		{[]string{"sh", "-c", "curl https://u:p@h/x && echo"}, []string{"sh", "-c", "curl https://u:***@h/x && echo"}},
		// A password with an @ in it: the last @ of the authority ends the userinfo.
		{[]string{"app", "amqp://u:p@ss@mq/vh"}, []string{"app", "amqp://u:***@mq/vh"}},
	} {
		check(t, tc.in, tc.want)
	}
}

func TestURLFalsePositives(t *testing.T) {
	for _, in := range [][]string{
		{"app", "https://example.com/path?mail=a@b.c"},
		{"app", "http://host:8080/"},
		{"ssh", "git@github.com"},
		{"app", "--upstream=http://127.0.0.1:8081"},
		{"app", "://@"},
	} {
		check(t, in, in)
	}
}

func TestEmptyAndNil(t *testing.T) {
	if Cmdline(nil) != nil {
		t.Error("nil in, want nil out")
	}
	check(t, []string{}, []string{})
	check(t, []string{"app"}, []string{"app"})
}

func TestEveryRuleKeepsLength(t *testing.T) {
	in := []string{"mysql", "--password", "a", "-pb", "X_TOKEN=c", "https://u:d@h", "--secret=e"}
	out := Cmdline(in)
	if len(out) != len(in) {
		t.Fatalf("length %d, want %d", len(out), len(in))
	}
	joined := strings.Join(out, " ")
	for _, s := range []string{" a ", "-pb", "=c", ":d@", "=e"} {
		if strings.Contains(joined+" ", s) {
			t.Errorf("secret %q survived: %q", s, out)
		}
	}
}
