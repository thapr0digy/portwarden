package apache

import (
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// A container's Apache config is the image author's: a short config that includes one
// dense file over and over reads up to conf.MaxTotalBytes, within every limit. That load
// must fit fuzzcheck.ProxyBudget and the agent's memory (fuzzcheck.ProxyHeapLimit).
func TestLoadAtTheReadLimitFitsBudgetAndMemory(t *testing.T) {
	vhost := "<VirtualHost *:80>\nServerName a.example\nProxyPass / http://127.0.0.1:9000/\n</VirtualHost>\n"
	big := strings.Repeat(vhost, (1<<20)/len(vhost))
	main := "LoadModule proxy_module mod_proxy.so\nLoadModule proxy_http_module mod_proxy_http.so\n" +
		strings.Repeat("Include /etc/apache2/big.conf\n", 2*conf.MaxTotalBytes/len(big))
	fsys := conf.MemFS{"/etc/apache2/apache2.conf": []byte(main), "/etc/apache2/big.conf": []byte(big)}
	o := Options{ServerRoot: DebianRoot, ConfigFile: DebianConfig, Env: ubuntuEnv}
	fuzzcheck.AtReadLimit(t, func() conf.Result { return Load(fsys, o) })
}
