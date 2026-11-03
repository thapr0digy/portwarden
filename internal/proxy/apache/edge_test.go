package apache

import (
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

func TestApacheEdgeCases(t *testing.T) {
	fsys := conf.MemFS{
		"/etc/httpd/conf/httpd.conf": []byte(`ServerRoot /etc/httpd
Listen 8080
Include conf.d
Include missing.conf
<IfModule mod_version.c>
ProxyPass /v http://127.0.0.1:1000/
</IfModule>
<IfModule mod_proxy.c>
Include never/*.conf
</IfModule>
<Macro VHost $name>
ProxyPass /m http://$name/
</Macro>
<VirtualHost *>
RewriteRule ^/(.*)$ http://%{HTTP_HOST}:81/$1 [L,P]
ProxyPass /b balancer://nobody/
<If "%{HTTP_HOST} == 'x'">
ProxyPass /if http://127.0.0.1:1001/
</If>
</VirtualHost>
`),
		"/etc/httpd/conf.d/a.conf":     []byte("ProxyPass /a http://127.0.0.1:2000/\n"),
		"/etc/httpd/conf.d/sub/b.conf": []byte("ProxyPass /b fcgi://127.0.0.1/\n"),
		"/etc/httpd/conf.d/.dot.conf":  []byte("ProxyPass /dot http://127.0.0.1:2002/\n"),
	}
	res := Load(fsys, Options{ServerRoot: RHELRoot, ConfigFile: RHELConfig})
	got := conf.Render(res)
	for _, want := range []string{
		`path="/v" proxy`, // mod_version.c is static
		`path="/a" proxy "http://127.0.0.1:2000/"`,
		"-> 127.0.0.1 127.0.0.1:8000", // fcgi's default port
		`path="/dot"`,                 // a directory Include reads dotfiles too
		"*:* names= path=\"~ ^/(.*)$\" proxy \"http://%{HTTP_HOST}:81/$1\"\n    -> %{HTTP_HOST}:81 (unresolved: variable in %{HTTP_HOST}:81)",
		"unresolved: balancer://nobody has no members",
		"conditional: <if %{HTTP_HOST} == 'x'>",
		"config note: unreadable /etc/httpd/missing.conf: file does not exist",
		"config note: <Macro> at /etc/httpd/conf/httpd.conf:11 not expanded",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "never") || strings.Contains(got, "/m ") {
		t.Errorf("skipped sections leaked:\n%s", got)
	}
	if !slices.Equal(res.Files, []string{"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/.dot.conf", "/etc/httpd/conf.d/a.conf", "/etc/httpd/conf.d/sub/b.conf"}) {
		t.Errorf("files = %v", res.Files)
	}
}
