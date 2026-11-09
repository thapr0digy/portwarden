package nginx

import (
	"strings"
	"testing"

	"github.com/thapr0digy/portwarden/internal/fuzzcheck"
	"github.com/thapr0digy/portwarden/internal/proxy/conf"
)

// A container's nginx config is the image author's: a short config that includes one
// dense file over and over reads up to conf.MaxTotalBytes, within every limit. That load
// must fit fuzzcheck.ProxyBudget (so a FuzzLoad budget failure means a blow-up, not a
// large allowed load) and the agent's memory (fuzzcheck.ProxyHeapLimit).
func TestLoadAtTheReadLimitFitsBudgetAndMemory(t *testing.T) {
	server := "server { listen 8080; server_name a.example; location / { proxy_pass http://127.0.0.1:9000; } }\n"
	big := strings.Repeat(server, (1<<20)/len(server))
	main := "http {\n" + strings.Repeat("include /etc/nginx/big.conf;\n", 2*conf.MaxTotalBytes/len(big)) + "}\n"
	fsys := conf.MemFS{"/etc/nginx/nginx.conf": []byte(main), "/etc/nginx/big.conf": []byte(big)}
	fuzzcheck.AtReadLimit(t, func() conf.Result { return Load(fsys, "/etc/nginx/nginx.conf") })
}
