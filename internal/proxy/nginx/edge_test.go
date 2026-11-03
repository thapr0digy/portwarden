package nginx

import (
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

func TestLexQuotesCommentsAndVariables(t *testing.T) {
	toks, _ := lex("a \"b;{c}#d\" 'e\\'f' ${host}x g\\;h # comment {\n}")
	var words []string
	for _, tk := range toks {
		words = append(words, tk.text)
	}
	want := []string{"a", "b;{c}#d", "e'f", "${host}x", `g\;h`, "}"}
	if !slices.Equal(words, want) {
		t.Fatalf("tokens = %q, want %q", words, want)
	}
	if toks[len(toks)-1].line != 2 {
		t.Fatalf("line of } = %d", toks[len(toks)-1].line)
	}
}

func TestEdgeCases(t *testing.T) {
	fsys := conf.MemFS{
		"/etc/hosts": []byte("10.1.2.3 app.internal\n"),
		"/etc/nginx/nginx.conf": []byte(`events {}
http {
	include missing.conf;
	include /etc/nginx/none/*.conf;
	server {
		location / { proxy_pass http://app.internal:9000; }
		location /x { proxy_pass https://example.com; }
		location /y { return 301 https://example.com$request_uri; }
	}
	server {
		listen 10.0.0.1;
		return 444;
	}
	server {
		listen unix:/run/nginx.sock;
	}
	server {
		location / { proxy_pass http://$var$var2; }
	}
`),
	}
	res := Load(fsys, "/etc/nginx/nginx.conf")
	got := conf.Render(res)
	for _, want := range []string{
		"*:80 names= path=\"/\" proxy \"http://app.internal:9000\"\n    -> app.internal:9000 10.1.2.3:9000\n",
		"-> example.com (unresolved: hostname example.com (no DNS lookups))",
		"path=\"/y\" return \"301\"",
		"10.0.0.1:80 names= path=\"\" return \"444\"",
		"unix:/run/nginx.sock names= path=\"/\" static \"html\" root=html",
		"-> $var$var2 (unresolved: variable $var)",
		"config note: unreadable /etc/nginx/missing.conf: file does not exist",
		"config note: unexpected end of file, expecting } in /etc/nginx/nginx.conf",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !slices.Contains(res.Watch, "/etc/nginx/missing.conf") || !slices.Contains(res.Watch, "/etc/nginx/none") {
		t.Errorf("watch = %v (a missing include and a globbed dir must be watched)", res.Watch)
	}
}

func TestParseDumpKeepsFileBoundaries(t *testing.T) {
	main, files, order, err := ParseDump([]byte("# configuration file /a.conf:\nx;\n\n# configuration file /b.conf:\ny;\n"))
	if err != nil || main != "/a.conf" || !slices.Equal(order, []string{"/a.conf", "/b.conf"}) ||
		string(files["/a.conf"]) != "x;\n" || string(files["/b.conf"]) != "y;" {
		t.Fatalf("ParseDump = %q %q %v %v", main, files, order, err)
	}
	if _, _, _, err := ParseDump([]byte("nothing")); err == nil {
		t.Fatal("a dump without headers must fail")
	}
}

func TestSelfIncludeIsACycleNotARunaway(t *testing.T) {
	fsys := conf.MemFS{"/etc/nginx/nginx.conf": []byte("include /etc/nginx/nginx.conf;\nhttp { server { listen 81; } }\n")}
	res := Load(fsys, "/etc/nginx/nginx.conf")
	if len(res.Routes) != 1 || !strings.Contains(strings.Join(res.Notes, ","), "include cycle") {
		t.Fatalf("routes=%d notes=%v", len(res.Routes), res.Notes)
	}
}
