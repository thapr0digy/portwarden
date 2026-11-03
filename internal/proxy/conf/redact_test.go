package conf

import "testing"

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"http://user:secret@127.0.0.1:81/x?token=abc":  "http://***@127.0.0.1:81/x",
		"https://b/?key=K":                             "https://b/",
		"user:pw@10.0.0.1:5432":                        "***@10.0.0.1:5432",
		"unix@/run/static.sock":                        "unix@/run/static.sock",
		"ipv4@127.0.0.1:5433":                          "ipv4@127.0.0.1:5433",
		"unix:/run/app.sock|http://localhost/":         "unix:/run/app.sock|http://localhost/",
		"unresolved: hostname a:b@db (no DNS lookups)": "unresolved: hostname ***@db (no DNS lookups)",
		"http://${API_USER}:${API_PASS}@b/":            "http://***@b/",
		"fcgi://127.0.0.1:9001/var/www/app/$1":         "fcgi://127.0.0.1:9001/var/www/app/$1",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}
