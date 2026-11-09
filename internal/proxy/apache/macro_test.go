package apache

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

func loadMain(t *testing.T, main string, env map[string]string) (string, conf.Result) {
	t.Helper()
	fsys := conf.MemFS{"/etc/apache2/apache2.conf": []byte(main)}
	res := Load(fsys, Options{ServerRoot: DebianRoot, ConfigFile: DebianConfig, Env: env})
	return conf.Render(res), res
}

// A macro defines virtual hosts; each Use expands to one, read as if written in place,
// with the longest parameter replaced first ($host inside $hostname is not touched).
func TestApacheMacroExpand(t *testing.T) {
	got, res := loadMain(t, `LoadModule proxy_module mod_proxy.so
<Macro App $hostname $host $port>
<VirtualHost *:80>
  ServerName $hostname
  ProxyPass / http://$host:$port/
</VirtualHost>
</Macro>
Use App a.example 127.0.0.1 9001
use app b.example "127.0.0.2" 9002
UndefMacro App
Use App c.example 127.0.0.3 9003
`, nil)
	for _, want := range []string{
		"*:80 names=a.example path=\"/\" proxy \"http://127.0.0.1:9001/\"\n    -> 127.0.0.1:9001 127.0.0.1:9001\n    note: from macro App (Use at /etc/apache2/apache2.conf:8)\n    @ /etc/apache2/apache2.conf:5",
		"*:80 names=b.example path=\"/\" proxy \"http://127.0.0.2:9002/\"",
		"config note: Use of undefined macro App at /etc/apache2/apache2.conf:11",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "c.example") || strings.Contains(got, "$host") {
		t.Errorf("an undefined or unexpanded macro leaked:\n%s", got)
	}
	_, vhosts := load(conf.MemFS{"/etc/apache2/apache2.conf": []byte("<Macro V $n>\n<VirtualHost *:80>\nServerName $n\n</VirtualHost>\n</Macro>\nUse V x\nUse V y\n")},
		Options{ServerRoot: DebianRoot, ConfigFile: DebianConfig})
	if len(vhosts) != 2 || vhosts[0].source != "/etc/apache2/apache2.conf:2" {
		t.Errorf("vhosts = %+v, want two at the macro's <VirtualHost> line", vhosts)
	}
	if len(res.Files) != 1 {
		t.Errorf("files = %v", res.Files)
	}
}

// mod_macro refuses a macro that uses itself; the loader notes it and stops there.
func TestApacheMacroRecursion(t *testing.T) {
	got, _ := loadMain(t, "<Macro Loop $x>\nProxyPass /$x http://127.0.0.1:1/\nUse Loop $x\n</Macro>\nUse Loop a\n", nil)
	if !strings.Contains(got, "recursive Use of macro Loop at /etc/apache2/apache2.conf:3; not expanded") {
		t.Errorf("no recursion note:\n%s", got)
	}
	if n := strings.Count(got, `path="/a"`); n != 1 {
		t.Errorf("%d expansions, want 1:\n%s", n, got)
	}
}

// Nested macros stop at MaxMacroDepth, and a fan-out (each level using the next twice)
// stops at the load's byte budget instead of growing 2^depth.
func TestApacheMacroBounds(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxMacroDepth+2; i++ {
		fmt.Fprintf(&b, "<Macro M%d $v>\nProxyPass /m%d/$v http://127.0.0.1:1/\nUse M%d $v\n</Macro>\n", i, i, i+1)
	}
	b.WriteString("Use M0 x\n")
	got, _ := loadMain(t, b.String(), nil)
	if !strings.Contains(got, fmt.Sprintf("macro nesting over %d", MaxMacroDepth)) {
		t.Errorf("no depth note:\n%s", got)
	}
	if strings.Contains(got, fmt.Sprintf("/m%d/", MaxMacroDepth)) {
		t.Errorf("expanded past the depth limit:\n%s", got)
	}

	b.Reset()
	pad := strings.Repeat("x", 4096)
	for i := 0; i < MaxMacroDepth; i++ {
		fmt.Fprintf(&b, "<Macro F%d $v>\nServerAdmin %s\nUse F%d $v\nUse F%d $v\n</Macro>\n", i, pad, i+1, i+1)
	}
	fmt.Fprintf(&b, "<Macro F%d $v>\nServerAdmin %s\n</Macro>\n", MaxMacroDepth, pad)
	main := b.String() + strings.Repeat("Use F0 x\n", 8)
	_, res := loadMain(t, main, nil)
	if !strings.Contains(strings.Join(res.Notes, "\n"), fmt.Sprintf("more than %d bytes", conf.MaxTotalBytes)) {
		t.Errorf("a fan-out was not cut at the byte budget; notes = %q", res.Notes)
	}
}

// A Use with the wrong number of arguments is not expanded (Apache refuses to start).
func TestApacheMacroArgumentCount(t *testing.T) {
	got, _ := loadMain(t, "<Macro Two $a $b>\nProxyPass /$a http://$b/\n</Macro>\nUse Two only\n", nil)
	if !strings.Contains(got, "Use Two at /etc/apache2/apache2.conf:4: 1 arguments, the macro takes 2; not expanded") || strings.Contains(got, "path=") {
		t.Errorf("got:\n%s", got)
	}
}

// A Use argument naming an environment variable resolves through it, but only the
// ${VAR} form is published, as for any other directive.
func TestApacheMacroEnvSecretsNotPublished(t *testing.T) {
	got, _ := loadMain(t, "Listen 80\n<Macro P $u>\nProxyPass / $u\n</Macro>\nUse P http://${API_PASS}@127.0.0.1:9000/\n",
		map[string]string{"API_PASS": "hunter2"})
	if strings.Contains(got, "hunter2") || !strings.Contains(got, `"http://${API_PASS}@127.0.0.1:9000/"`) || !strings.Contains(got, "-> 127.0.0.1:9000 127.0.0.1:9000") {
		t.Errorf("got:\n%s", got)
	}
}
