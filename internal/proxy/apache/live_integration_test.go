//go:build linux && integration

package apache

import (
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/proxy/rootfs"
)

// The loader, reading the host's /etc/apache2 through openat2(RESOLVE_IN_ROOT), reads the
// files `apache2 -t -D DUMP_INCLUDES` lists, in its order.
func TestLoaderMatchesLiveApacheIncludes(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/apache2"); err != nil {
		t.Skip("apache2 not installed")
	}
	env := map[string]string{}
	envvars, err := exec.Command("bash", "-c", "set -a; . /etc/apache2/envvars; env").Output()
	if err != nil {
		t.Fatal(err)
	}
	var environ []string
	for _, kv := range strings.Split(string(envvars), "\n") {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "APACHE_") {
			env[k] = v
			environ = append(environ, kv)
		}
	}
	cmd := exec.Command("/usr/sbin/apache2", "-t", "-D", "DUMP_INCLUDES")
	cmd.Env = append(os.Environ(), environ...)
	out, _ := cmd.CombinedOutput()
	var want []string
	for _, m := range regexp.MustCompile(`(?m)^\s*\((?:\*|\d+)\) (/\S+)$`).FindAllStringSubmatch(string(out), -1) {
		if !slices.Contains(want, m[1]) {
			want = append(want, m[1])
		}
	}
	if len(want) == 0 {
		t.Fatalf("no includes in:\n%s", out)
	}
	fsys, err := rootfs.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	res := Load(fsys, Options{ServerRoot: DebianRoot, ConfigFile: DebianConfig, Env: env})
	if !slices.Equal(res.Files, want) {
		t.Fatalf("files = %v\nDUMP_INCLUDES = %v", res.Files, want)
	}
}
