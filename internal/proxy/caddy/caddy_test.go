package caddy

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

var update = flag.Bool("update", false, "rewrite the routes.txt golden files")

// Every recorded /config/ answer (dev/proxy-fixtures.sh records the VM's Caddy; the
// handwritten case covers what a Caddyfile adapter does not emit) parses to the reviewed
// golden routes.
func TestCaddyParseGolden(t *testing.T) {
	cases, _ := filepath.Glob("testdata/*/config.json")
	if len(cases) < 2 {
		t.Fatalf("fixtures = %v, want the handwritten and at least one recorded case", cases)
	}
	for _, f := range cases {
		dir := filepath.Dir(f)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			res, err := Parse(b, "127.0.0.1:2019", conf.LoadNames(nil))
			if err != nil {
				t.Fatal(err)
			}
			got := conf.Render(res)
			golden := filepath.Join(dir, "routes.txt")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("routes differ from %s (go test -update to rewrite after review):\n%s", golden, got)
			}
		})
	}
}

func TestCaddyParseShapes(t *testing.T) {
	b, err := os.ReadFile("testdata/handwritten/config.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(b, "127.0.0.1:2019", conf.LoadNames(conf.MemFS{"/etc/hosts": []byte("10.0.0.7 backend.internal\n")}))
	if err != nil {
		t.Fatal(err)
	}
	got := conf.Render(res)
	for _, want := range []string{
		// Hosts from the outer route, paths from the subroute.
		"*:443,127.0.0.1:8443,udp/*:443 names=app.example.com,www.app.example.com path=\"/api/*\" proxy \"localhost:9000 [::1]:9001\"\n    -> localhost:9000 127.0.0.1:9000 [::1]:9000\n    -> [::1]:9001 [::1]:9001\n    @ 127.0.0.1:2019/config/apps/http/servers/srv0/routes/0/handle/0/routes/0/handle/0",
		"path=\"*.php\" fastcgi \"unix//run/php/php-fpm.sock\"\n    -> unix//run/php/php-fpm.sock unix=/run/php/php-fpm.sock",
		// The vars handler's root reaches the file_server after it.
		"path=\"\" static \"/srv/www\" root=/srv/www",
		"names=dyn.example.com path=\"\" proxy \"(dynamic upstreams)\"\n    -> (dynamic) (unresolved: dynamic upstreams)\n    note: matcher header\n    note: matcher remote_ip\n    note: unresolved: dynamic upstreams",
		"-> {http.request.host}:8080 (unresolved: placeholder in {http.request.host}:8080)",
		"-> backend.internal:8080 10.0.0.7:8080",
		"-> 127.0.0.1 (unresolved: no port)",
		"*:443,127.0.0.1:8443,udp/*:443 names= path=\"\" return \"404\"",
		"unix:/run/caddy/app.sock names= path=\"\" proxy \"unix//run/app.sock\"",
		"config note: app layer4 not read",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "secret body") || strings.Contains(got, "Caddyfile") {
		t.Errorf("fields that are not routes were published:\n%s", got)
	}
}

func TestCaddyParseEdges(t *testing.T) {
	for _, empty := range []string{"", "null", " \n"} {
		res, err := Parse([]byte(empty), "x", conf.LoadNames(nil))
		if err != nil || len(res.Routes) != 0 || len(res.Notes) != 1 {
			t.Errorf("%q: %+v, %v", empty, res, err)
		}
	}
	for _, bad := range []string{"{", `{"apps":{"http":{"servers":[]}}}`, `[]`} {
		if _, err := Parse([]byte(bad), "x", conf.LoadNames(nil)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	// Subroutes nested past MaxDepth stop with a note.
	inner := `{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:1"}]}`
	for i := 0; i < MaxDepth+3; i++ {
		inner = `{"handler":"subroute","routes":[{"handle":[` + inner + `]}]}`
	}
	res, err := Parse([]byte(`{"apps":{"http":{"servers":{"s":{"listen":[":80"],"routes":[{"handle":[`+inner+`]}]}}}}}`), "x", conf.LoadNames(nil))
	if err != nil || len(res.Routes) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "nested over") {
		t.Errorf("deep subroutes: %+v, %v", res, err)
	}
}
