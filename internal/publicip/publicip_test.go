package publicip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/model"
	"github.com/thapr0digy/portwarden/internal/netif"
)

func dmi(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetect(t *testing.T) {
	cases := []struct {
		files map[string]string
		want  string
	}{
		{map[string]string{"sys_vendor": "Amazon EC2", "product_name": "m6i.large"}, AWS},
		{map[string]string{"sys_vendor": "Xen", "bios_version": "4.11.amazon"}, AWS},
		{map[string]string{"sys_vendor": "Google", "product_name": "Google Compute Engine"}, GCP},
		{map[string]string{"sys_vendor": "Microsoft Corporation", "chassis_asset_tag": azureAssetTag}, Azure},
		{map[string]string{"sys_vendor": "Microsoft Corporation", "chassis_asset_tag": "none"}, ""}, // Hyper-V, not Azure
		{map[string]string{"sys_vendor": "Apple Inc.", "product_name": "Apple Virtualization Generic Platform"}, ""},
		{map[string]string{"sys_vendor": "QEMU"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := Detect(dmi(t, c.files)); got != c.want {
			t.Errorf("%v: got %q, want %q", c.files, got, c.want)
		}
	}
	if Detect("/nonexistent") != "" {
		t.Error("missing DMI must detect nothing")
	}
}

// fakeIMDS serves canned metadata and records request headers.
func fakeIMDS(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return NewClient(s.URL, time.Second)
}

func TestAWSIMDSv2(t *testing.T) {
	c := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/api/token" {
			if r.Method != http.MethodPut || r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				http.Error(w, "bad token request", http.StatusBadRequest)
				return
			}
			w.Write([]byte("TOKEN"))
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "TOKEN" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/latest/meta-data/instance-id":
			w.Write([]byte("i-0abc123"))
		case "/latest/meta-data/public-ipv4":
			w.Write([]byte("34.120.1.7"))
		default:
			http.NotFound(w, r) // no ipv6
		}
	})
	info, err := c.Fetch(context.Background(), AWS)
	if err != nil {
		t.Fatal(err)
	}
	if info.Cloud != AWS || info.InstanceID != "i-0abc123" || !slices.Equal(info.PublicIPs, []netip.Addr{netip.MustParseAddr("34.120.1.7")}) {
		t.Fatalf("info = %+v", info)
	}
}

func TestAWSWithoutPublicIP(t *testing.T) {
	c := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			w.Write([]byte("T"))
		case "/latest/meta-data/instance-id":
			w.Write([]byte("i-1"))
		default:
			http.NotFound(w, r)
		}
	})
	info, err := c.Fetch(context.Background(), AWS)
	if err != nil || len(info.PublicIPs) != 0 || info.InstanceID != "i-1" {
		t.Fatalf("info %+v err %v", info, err)
	}
}

func TestGCP(t *testing.T) {
	c := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing flavor", http.StatusForbidden)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		switch r.URL.Path {
		case "/computeMetadata/v1/instance/id":
			w.Write([]byte("4419012345678"))
		case "/computeMetadata/v1/instance/network-interfaces/":
			if r.URL.Query().Get("recursive") != "true" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(`[{"ip":"10.128.0.2","accessConfigs":[{"externalIp":"35.200.1.2","type":"ONE_TO_ONE_NAT"}],"ipv6AccessConfigs":[{"externalIpv6":"2600:1900:4000::1"}]}]`))
		default:
			http.NotFound(w, r)
		}
	})
	info, err := c.Fetch(context.Background(), GCP)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("35.200.1.2"), netip.MustParseAddr("2600:1900:4000::1")}
	if info.InstanceID != "4419012345678" || !slices.Equal(info.PublicIPs, want) {
		t.Fatalf("info = %+v", info)
	}
}

func TestGCPRejectsAnswerWithoutFlavor(t *testing.T) {
	c := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) })
	if _, err := c.Fetch(context.Background(), GCP); err == nil {
		t.Fatal("an endpoint that is not GCP's metadata server must be refused")
	}
}

func TestAzure(t *testing.T) {
	c := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" || r.URL.Query().Get("api-version") == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{"compute":{"vmId":"02aab8a4-74ef-476e-8182-f6d2ba4166a6"},"network":{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.0.4","publicIpAddress":"20.40.1.2"},{"privateIpAddress":"10.0.0.5","publicIpAddress":""}]},"ipv6":{"ipAddress":[]}}]}}`))
	})
	info, err := c.Fetch(context.Background(), Azure)
	if err != nil {
		t.Fatal(err)
	}
	if info.InstanceID != "02aab8a4-74ef-476e-8182-f6d2ba4166a6" || !slices.Equal(info.PublicIPs, []netip.Addr{netip.MustParseAddr("20.40.1.2")}) {
		t.Fatalf("info = %+v", info)
	}
}

func TestTimeoutAndErrors(t *testing.T) {
	block := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	t.Cleanup(s.Close)
	// Cleanups run last-first: the handler is released before the server waits for it.
	t.Cleanup(func() { close(block) })
	c := NewClient(s.URL, 100*time.Millisecond)
	start := time.Now()
	if _, err := c.Fetch(context.Background(), AWS); err == nil {
		t.Fatal("a hanging endpoint must fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout not applied: %s", time.Since(start))
	}
	c = fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) })
	if _, err := c.Fetch(context.Background(), Azure); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("got %v", err)
	}
	if _, err := c.Fetch(context.Background(), "ibm"); err == nil {
		t.Fatal("unknown provider")
	}
}

func TestRunIMDSRetriesThenRefreshes(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	c := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			http.Error(w, "not yet", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"compute":{"vmId":"vm-1"},"network":{"interface":[]}}`))
	})
	got := make(chan Info, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunIMDS(ctx, c, Azure, 20*time.Millisecond, 10*time.Millisecond, func(i Info) { got <- i })
	}()
	for range 2 {
		select {
		case i := <-got:
			if i.InstanceID != "vm-1" {
				t.Fatalf("info %+v", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no metadata delivered")
		}
	}
	cancel()
	<-done
}

func TestCollector(t *testing.T) {
	var got []model.HostInfo
	c := NewCollector(func(h model.HostInfo) { got = append(got, h) })
	ifs := []netif.Interface{
		{Name: "lo", Up: true, Loopback: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.5.15/24"), netip.MustParsePrefix("2600:1f18::15/64"), netip.MustParsePrefix("fe80::1/64")}},
		{Name: "eth1", Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("34.120.1.7/24")}},
		{Name: "eth2", Up: false, Prefixes: []netip.Prefix{netip.MustParsePrefix("34.120.9.9/24")}},
	}
	c.SetInterfaces(ifs)
	c.SetInterfaces(ifs) // unchanged: no publish
	c.SetIngestLocal(netip.MustParseAddr("192.168.5.15"))
	c.SetCloud(Info{Cloud: AWS, InstanceID: "i-1", PublicIPs: []netip.Addr{netip.MustParseAddr("54.1.2.3")}})
	c.SetIngestLocal(netip.MustParseAddr("34.120.1.7"))
	if len(got) != 3 {
		t.Fatalf("published %d times: %+v", len(got), got)
	}
	want := []model.PublicIP{
		{IP: netip.MustParseAddr("54.1.2.3"), Via: model.ViaIMDS, Dir: model.DirIn},
		{IP: netip.MustParseAddr("2600:1f18::15"), Via: model.ViaNetlink, Dir: model.DirIn, Iface: "eth0"},
		{IP: netip.MustParseAddr("34.120.1.7"), Via: model.ViaNetlink, Dir: model.DirIn, Iface: "eth1"},
		{IP: netip.MustParseAddr("34.120.1.7"), Via: model.ViaIngestLocal, Dir: model.DirOut},
	}
	last := got[len(got)-1]
	if last.Cloud != AWS || last.InstanceID != "i-1" || !slices.Equal(last.PublicIPs, want) {
		t.Fatalf("host = %+v", last)
	}
	if !c.Host().Equal(last) {
		t.Fatal("Host() differs from the last published block")
	}
}

func TestCollectorConditions(t *testing.T) {
	var got []model.HostInfo
	c := NewCollector(func(h model.HostInfo) { got = append(got, h) })
	c.SetConditions(nil)
	c.SetConditions([]string{"fw:unreadable iptables-save: Permission denied"})
	c.SetConditions([]string{"fw:unreadable iptables-save: Permission denied"})
	c.SetConditions(nil)
	if len(got) != 3 || len(got[1].Conditions) != 1 || len(got[2].Conditions) != 0 {
		t.Fatalf("published %+v", got)
	}
}
