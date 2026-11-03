package redact

import "testing"

// Fix-wave bypasses (review of PR #8): each must be masked.
func TestFixWaveBypasses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in, want []string
	}{
		// Whitespace other than one space, separators kept.
		{"tab in a script", []string{"sh", "-c", "psql\tPGPASSWORD=pw"}, []string{"sh", "-c", "psql\tPGPASSWORD=***"}},
		{"double space before the value", []string{"sh", "-c", "app --password  hunter2"}, []string{"sh", "-c", "app --password  ***"}},
		{"newline in a script", []string{"sh", "-c", "export TOKEN=t\nrun"}, []string{"sh", "-c", "export TOKEN=***\nrun"}},
		// Quoted values.
		{"quoted value in a script", []string{"sh", "-c", `app --password="a b" --x`}, []string{"sh", "-c", `app --password="***" --x`}},
		{"single-quoted next word", []string{"sh", "-c", "app --token 'a b'"}, []string{"sh", "-c", "app --token '***'"}},
		{"argv value with a space", []string{"app", "--password=a b"}, []string{"app", "--password=***"}},
		{"argv next value with a space", []string{"app", "--password", "a b"}, []string{"app", "--password", "***"}},
		{"quoted KEY=value", []string{"sh", "-c", `PGPASSWORD="a b" psql`}, []string{"sh", "-c", `PGPASSWORD="***" psql`}},
		// KEY=value inside a flag's value.
		{"docker --env", []string{"docker", "run", "--env=DB_PASSWORD=x", "img"}, []string{"docker", "run", "--env=DB_PASSWORD=***", "img"}},
		{"docker -e", []string{"docker", "run", "-e", "DB_PASSWORD=x"}, []string{"docker", "run", "-e", "DB_PASSWORD=***"}},
		{"kubectl --from-literal", []string{"kubectl", "create", "secret", "generic", "s", "--from-literal=password=x"},
			[]string{"kubectl", "create", "secret", "generic", "s", "--from-literal=password=***"}},
		{"helm --set", []string{"helm", "install", "--set", "db.password=x,replicas=2"}, []string{"helm", "install", "--set", "db.password=***,replicas=2"}},
		{"helm --set camelCase", []string{"helm", "--set=auth.rootPassword=x"}, []string{"helm", "--set=auth.rootPassword=***"}},
		// Secret query parameters.
		{"url token", []string{"curl", "https://h/x?user=a&token=t"}, []string{"curl", "https://h/x?user=a&token=***"}},
		{"url first param", []string{"curl", "https://h/x?password=p"}, []string{"curl", "https://h/x?password=***"}},
		{"url access_token", []string{"app", "--url=https://h/?access_token=t&x=1"}, []string{"app", "--url=https://h/?access_token=***&x=1"}},
		{"url api_key and key", []string{"app", "https://h/?api_key=a&key=k&pwd=p&secret=s"}, []string{"app", "https://h/?api_key=***&key=***&pwd=***&secret=***"}},
		{"jdbc mysql", []string{"java", "-jar", "a.jar", "jdbc:mysql://db/x?user=a&password=p"}, []string{"java", "-jar", "a.jar", "jdbc:mysql://db/x?user=a&password=***"}},
		{"jdbc sqlserver", []string{"app", "jdbc:sqlserver://db;user=a;password=p;db=x"}, []string{"app", "jdbc:sqlserver://db;user=a;password=***;db=x"}},
		// ; and & lists.
		{"odbc", []string{"app", "Driver={X};Server=db;Uid=u;Pwd=p;"}, []string{"app", "Driver={X};Server=db;Uid=u;Pwd=***;"}},
		{"ampersand list", []string{"app", "user=a&password=p"}, []string{"app", "user=a&password=***"}},
		// mysql -p anywhere in a script.
		{"mysql after cd", []string{"sh", "-c", "cd /tmp && mysql -uroot -phunter2 db"}, []string{"sh", "-c", "cd /tmp && mysql -uroot -p*** db"}},
		{"mysqldump in a pipe", []string{"bash", "-c", "mysqldump -pX db | gzip > f"}, []string{"bash", "-c", "mysqldump -p*** db | gzip > f"}},
		{"sudo mysql", []string{"sh", "-c", "sudo mysql -pX"}, []string{"sh", "-c", "sudo mysql -p***"}},
		// Per-program rules.
		{"redis-cli -a", []string{"redis-cli", "-h", "r", "-a", "pw", "ping"}, []string{"redis-cli", "-h", "r", "-a", "***", "ping"}},
		{"sshpass -p", []string{"sshpass", "-p", "pw", "ssh", "h"}, []string{"sshpass", "-p", "***", "ssh", "h"}},
		{"sshpass -ppw", []string{"sshpass", "-ppw", "ssh", "h"}, []string{"sshpass", "-p***", "ssh", "h"}},
		{"curl -u", []string{"curl", "-u", "user:pw", "https://h"}, []string{"curl", "-u", "user:***", "https://h"}},
		{"curl -uuser:pw", []string{"curl", "-uuser:pw", "https://h"}, []string{"curl", "-uuser:***", "https://h"}},
		{"curl --user=", []string{"curl", "--user=user:pw"}, []string{"curl", "--user=user:***"}},
		{"curl in a script", []string{"sh", "-c", "curl -s -u admin:pw https://h"}, []string{"sh", "-c", "curl -s -u admin:*** https://h"}},
		// Authorization headers.
		{"bearer header", []string{"curl", "-H", "Authorization: Bearer abc", "https://h"}, []string{"curl", "-H", "Authorization: Bearer ***", "https://h"}},
		{"basic header", []string{"curl", "--header=Authorization: Basic dXNlcjpwdw=="}, []string{"curl", "--header=Authorization: Basic ***"}},
		{"raw header token", []string{"curl", "-H", "authorization: abc123"}, []string{"curl", "-H", "authorization: ***"}},
		{"header in a script", []string{"sh", "-c", `curl -H "Authorization: Bearer abc" https://h`}, []string{"sh", "-c", `curl -H "Authorization: Bearer ***" https://h`}},
		// JSON.
		{"json body", []string{"curl", "-d", `{"user":"a","password":"p w"}`}, []string{"curl", "-d", `{"user":"a","password":"***"}`}},
		{"json spaced", []string{"app", `{"api_key": "k", "n": 1}`}, []string{"app", `{"api_key": "***", "n": 1}`}},
		{"json unquoted value", []string{"app", `{"token":12345}`}, []string{"app", `{"token":"***"}`}},
		// Bare PASS= and PASSWD=.
		{"bare PASS", []string{"env", "PASS=p"}, []string{"env", "PASS=***"}},
		{"bare PASSWD", []string{"env", "PASSWD=p"}, []string{"env", "PASSWD=***"}},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.in, tc.want) })
	}
}

func TestFixWaveFalsePositives(t *testing.T) {
	for _, in := range [][]string{
		{"env", "PWD=/home/u"},
		{"docker", "run", "-e", "PASSWORD_FILE=/run/s"},
		{"curl", "-u", "user", "https://h"}, // curl prompts for the password
		{"redis-server", "-a", "x"},         // -a is redis-cli's
		{"app", "-p", "8080"},               // -p is sshpass's only
		{"curl", "-H", "Accept: application/json"},
		{"app", "https://h/?page=2&sort=name"},
		{"app", `{"user":"a","n":1}`},
		{"sh", "-c", "echo a  b\tc"},
		{"helm", "--set", "replicas=2,image.tag=v1"},
	} {
		check(t, in, in)
	}
}
