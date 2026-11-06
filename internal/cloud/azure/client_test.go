package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/cloud"
)

const (
	tenant   = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	clientID = "a1b2c3d4-e5f6-4789-8abc-def012345678"
	resource = rgPath + "Microsoft.Compute/virtualMachines/web1"
	secret   = "s3cr3t-Value~with.chars"
)

// fakeARM serves Entra ID's token endpoint, IMDS and the ARM reads from testdata.
type fakeARM struct {
	t *testing.T

	mu         sync.Mutex
	paths      []string
	forms      []map[string]string
	status     map[string]int    // path suffix → status
	bodies     map[string]string // path suffix → body override
	tokenCalls atomic.Int32
	tagCalls   atomic.Int32
	srv        *httptest.Server
}

func newFake(t *testing.T) *fakeARM {
	f := &fakeARM{t: t, status: map[string]int{}, bodies: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeARM) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	path := r.URL.EscapedPath()
	switch {
	case strings.HasSuffix(path, "/oauth2/v2.0/token"):
		f.tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		form := map[string]string{"path": path}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		f.mu.Lock()
		f.forms = append(f.forms, form)
		f.mu.Unlock()
		if code := f.status["token"]; code != 0 {
			w.WriteHeader(code)
			w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. secret=` + form["client_secret"] + `","error_codes":[7000215]}`))
			return
		}
		w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"arm-token"}`))
		return
	case path == "/metadata/identity/oauth2/token":
		f.tokenCalls.Add(1)
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, `{"error":"invalid_request"}`, 400)
			return
		}
		f.mu.Lock()
		f.forms = append(f.forms, map[string]string{"client_id": r.URL.Query().Get("client_id"), "resource": r.URL.Query().Get("resource"), "api-version": r.URL.Query().Get("api-version")})
		f.mu.Unlock()
		w.Write([]byte(`{"access_token":"mi-token","expires_in":"86399","expires_on":"1506484173","resource":"https://management.azure.com/","token_type":"Bearer"}`))
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer arm-token" && got != "Bearer mi-token" {
		http.Error(w, `{"error":{"code":"AuthenticationFailed","message":"no token"}}`, 401)
		return
	}
	if strings.HasSuffix(path, "/serviceTags") {
		f.tagCalls.Add(1)
	}
	for suffix, code := range f.status {
		if suffix != "token" && strings.HasSuffix(path, suffix) {
			w.WriteHeader(code)
			w.Write([]byte(`{"error":{"code":"AuthorizationFailed","message":"The client 'x' with object id 'y' does not have authorization to perform action 'Microsoft.Network/networkSecurityGroups/read'."}}`))
			return
		}
	}
	for suffix, body := range f.bodies {
		if strings.HasSuffix(path, suffix) {
			w.Write([]byte(body))
			return
		}
	}
	file := ""
	switch {
	case strings.HasSuffix(path, "/virtualMachines/web1"):
		f.want(r, computeAPI)
		file = "vm.json"
	case strings.HasSuffix(path, "/networkInterfaces/web-nic"):
		file = "nic.json"
	case strings.HasSuffix(path, "/publicIPAddresses/web-ip"):
		file = "publicip.json"
	case strings.HasSuffix(path, "/virtualNetworks/vnet1/subnets/web"):
		file = "subnet.json"
	case strings.HasSuffix(path, "/networkSecurityGroups/subnet-nsg"):
		file = "nsg-subnet.json"
	case strings.HasSuffix(path, "/networkSecurityGroups/nic-nsg"):
		file = "nsg-nic.json"
	case strings.HasSuffix(path, "/locations/westeurope/serviceTags"):
		if r.URL.Query().Get("page") == "2" {
			file = "servicetags-2.json"
			break
		}
		b := f.read("servicetags-1.json")
		w.Write([]byte(strings.Replace(b, `"NEXT"`, `"`+f.srv.URL+path+`?api-version=`+networkAPI+`&page=2"`, 1)))
		return
	default:
		http.Error(w, `{"error":{"code":"ResourceNotFound","message":"not found"}}`, 404)
		return
	}
	if file != "vm.json" && !strings.HasSuffix(path, "/serviceTags") {
		f.want(r, networkAPI)
	}
	w.Write([]byte(f.read(file)))
}

func (f *fakeARM) want(r *http.Request, apiVersion string) {
	if got := r.URL.Query().Get("api-version"); got != apiVersion {
		f.t.Errorf("%s: api-version %q, want %q", r.URL.Path, got, apiVersion)
	}
}

func (f *fakeARM) read(name string) string {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *fakeARM) requested(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.paths {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fakeARM) provider(t *testing.T, mod func(*Options)) *Provider {
	t.Helper()
	o := Options{TenantID: tenant, ClientID: clientID, ClientSecretFile: writeFile(t, secret+"\n"), Subscriptions: []string{strings.ToUpper(sub)},
		BaseURL: f.srv.URL, LoginURL: f.srv.URL, IMDSURL: f.srv.URL + "/metadata/identity/oauth2/token", HTTP: f.srv.Client()}
	if mod != nil {
		mod(&o)
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var host = cloud.Host{ID: "web1", Cloud: "azure", InstanceID: vmID, Region: "westeurope", Resource: resource}

func TestEvaluateEndToEnd(t *testing.T) {
	f := newFake(t)
	p := f.provider(t, nil)
	https := cloud.Port{Key: "tcp/0.0.0.0:443", Proto: "tcp", Addr: "0.0.0.0", Port: 443, AgentLevel: cloud.LevelHostFirewallOpen}
	smtp := cloud.Port{Key: "tcp/0.0.0.0:25", Proto: "tcp", Addr: "0.0.0.0", Port: 25, AgentLevel: cloud.LevelHostFirewallOpen}
	vs, err := p.Evaluate(context.Background(), host, []cloud.Port{ssh, https, smtp})
	if err != nil {
		t.Fatal(err)
	}
	if !vs[0].Open || !strings.Contains(strings.Join(vs[0].Evidence, "\n"), "(service tag AzureFrontDoor.Backend) allows tcp/22 from 147.243.0.0/16") {
		t.Fatalf("ssh: %+v", vs[0])
	}
	if !vs[1].Open || !strings.Contains(strings.Join(vs[1].Evidence, "\n"), "reachable from 0.0.0.0/0") {
		t.Fatalf("https: %+v", vs[1])
	}
	if vs[2].Open || !vs[2].Complete {
		t.Fatalf("smtp: %+v", vs[2])
	}
	for _, want := range []string{
		"GET /subscriptions/" + sub + "/resourceGroups/web-rg/providers/Microsoft.Compute/virtualMachines/web1?api-version=" + computeAPI,
		"GET /subscriptions/" + sub + "/resourceGroups/web-rg/providers/Microsoft.Network/networkInterfaces/web-nic?api-version=" + networkAPI,
		"/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/web?",
		"/networkSecurityGroups/subnet-nsg?", "/networkSecurityGroups/nic-nsg?", "/publicIPAddresses/web-ip?",
		"GET /subscriptions/" + sub + "/providers/Microsoft.Network/locations/westeurope/serviceTags?api-version=" + networkAPI,
		"page=2",
	} {
		if !f.requested(want) {
			t.Errorf("no request %q; got %v", want, f.paths)
		}
	}
	form := f.forms[0]
	if form["path"] != "/"+tenant+"/oauth2/v2.0/token" || form["grant_type"] != "client_credentials" || form["client_id"] != clientID ||
		form["client_secret"] != secret || form["scope"] != "https://management.azure.com/.default" {
		t.Fatalf("token form %v", form)
	}
	// A second look-up uses the cached token and the cached service tags.
	if _, err := p.Evaluate(context.Background(), host, []cloud.Port{ssh}); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls.Load() != 1 || f.tagCalls.Load() != 2 {
		t.Fatalf("token calls %d (want 1), tag page reads %d (want 2)", f.tokenCalls.Load(), f.tagCalls.Load())
	}
}

func TestResourceChecks(t *testing.T) {
	other := "11111111-2222-4333-8444-555555555555"
	cases := []struct {
		name string
		h    func(cloud.Host) cloud.Host
		want string
		vm   bool // the VM read happens
	}{
		{"no resource", func(h cloud.Host) cloud.Host { h.Resource = ""; return h }, "no cloud_resource", false},
		{"bad shape", func(h cloud.Host) cloud.Host {
			h.Resource = "/subscriptions/" + sub + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/ss/virtualMachines/3"
			return h
		}, "cloud_resource is not", false},
		{"subscription not allowed", func(h cloud.Host) cloud.Host {
			h.Resource = strings.Replace(resource, sub, other, 1)
			return h
		}, "not in cloud.azure.subscriptions", false},
		{"instance id not a UUID", func(h cloud.Host) cloud.Host { h.InstanceID = "web1"; return h }, "not a vmId", false},
		{"vmId mismatch", func(h cloud.Host) cloud.Host { h.InstanceID = other; return h }, "whose vmId is", true},
		{"location mismatch", func(h cloud.Host) cloud.Host { h.Region = "eastus"; return h }, "not the host's region", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider(t, nil)
			_, err := p.Evaluate(context.Background(), c.h(host), []cloud.Port{ssh})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if f.requested("/virtualMachines/") != c.vm {
				t.Fatalf("VM read %v, want %v (%v)", !c.vm, c.vm, f.paths)
			}
			if f.requested("/networkInterfaces/") {
				t.Fatalf("NIC read after a failed check: %v", f.paths)
			}
		})
	}
}

func TestFollowedIDs(t *testing.T) {
	other := "11111111-2222-4333-8444-555555555555"
	cases := []struct{ name, nsgID, want string }{
		{"another subscription", strings.Replace(nnsgID, sub, other, 1), "subscription " + other + " is not in"},
		{"not a Network type", rgPath + "Microsoft.Storage/storageAccounts/x", "is not a networkSecurityGroups id"},
		{"wrong Network type", rgPath + "Microsoft.Network/publicIPAddresses/web-ip", "is not a networkSecurityGroups id"},
		{"dots", rgPath + "Microsoft.Network/networkSecurityGroups/..", "dots"},
		{"escaped slash", rgPath + "Microsoft.Network/networkSecurityGroups/a%2Fb", "is not a networkSecurityGroups id"},
		{"query", rgPath + "Microsoft.Network/networkSecurityGroups/a?x=1", "is not a networkSecurityGroups id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			nic := strings.Replace(f.read("nic.json"), nnsgID, c.nsgID, 1)
			f.bodies["/networkInterfaces/web-nic"] = nic
			p := f.provider(t, func(o *Options) { o.Subscriptions = append(o.Subscriptions, "22222222-2222-4333-8444-555555555555") })
			vs, err := p.Evaluate(context.Background(), host, []cloud.Port{ssh})
			if err != nil {
				t.Fatal(err)
			}
			ev := strings.Join(vs[0].Evidence, "\n")
			if vs[0].Complete || !strings.Contains(ev, c.want) {
				t.Fatalf("verdict %+v, want undetermined naming %q", vs[0], c.want)
			}
			if f.requested(other) || f.requested("storageAccounts") || f.requested("a%2Fb") || f.requested("/..") {
				t.Fatalf("a refused id was requested: %v", f.paths)
			}
		})
	}
	t.Run("names are escaped", func(t *testing.T) {
		a, err := parseID(rgPath+"Microsoft.Network/networkSecurityGroups/web.nsg_1-a", kindNSG)
		if err != nil {
			t.Fatal(err)
		}
		if a.path() != "/subscriptions/"+sub+"/resourceGroups/web-rg/providers/Microsoft.Network/networkSecurityGroups/web.nsg_1-a" {
			t.Fatal(a.path())
		}
		g, err := parseID("/subscriptions/"+sub+"/resourceGroups/grüppe(1)/providers/Microsoft.Network/networkSecurityGroups/n", kindNSG)
		if err != nil || !strings.Contains(g.path(), "/resourceGroups/gr%C3%BCppe%281%29/") {
			t.Fatalf("%v %q", err, g.path())
		}
	})
}

func TestARMErrors(t *testing.T) {
	t.Run("NSG 403 makes the layer undetermined", func(t *testing.T) {
		f := newFake(t)
		f.status["/networkSecurityGroups/nic-nsg"] = 403
		vs, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh})
		if err != nil {
			t.Fatal(err)
		}
		ev := strings.Join(vs[0].Evidence, "\n")
		if vs[0].Complete || !strings.Contains(ev, "AuthorizationFailed") || !strings.Contains(ev, "deploy/azure-role.json") {
			t.Fatalf("%+v", vs[0])
		}
	})
	t.Run("VM 404 is a host error", func(t *testing.T) {
		f := newFake(t)
		f.status["/virtualMachines/web1"] = 404
		if _, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh}); err == nil || !strings.Contains(err.Error(), "virtualMachines/get") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("429 on the public IP", func(t *testing.T) {
		f := newFake(t)
		f.status["/publicIPAddresses/web-ip"] = 429
		vs, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh})
		if err != nil || vs[0].Complete || !strings.Contains(strings.Join(vs[0].Evidence, "\n"), "429") {
			t.Fatalf("%v %+v", err, vs)
		}
	})
	t.Run("body that is not JSON", func(t *testing.T) {
		f := newFake(t)
		f.bodies["/networkSecurityGroups/subnet-nsg"] = "<html>"
		vs, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh})
		if err != nil || vs[0].Complete || !strings.Contains(strings.Join(vs[0].Evidence, "\n"), "not the expected JSON") {
			t.Fatalf("%v %+v", err, vs)
		}
	})
}

func TestBodyCaps(t *testing.T) {
	f := newFake(t)
	f.bodies["/networkSecurityGroups/nic-nsg"] = `{"name":"` + strings.Repeat("x", maxNSGBody) + `"}`
	vs, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh})
	if err != nil || vs[0].Complete || !strings.Contains(strings.Join(vs[0].Evidence, "\n"), "response over") {
		t.Fatalf("%v %+v", err, vs)
	}
}

func TestServiceTagCache(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	f := newFake(t)
	p := f.provider(t, func(o *Options) { o.Now = clock })
	eval := func() cloud.Verdict {
		t.Helper()
		vs, err := p.Evaluate(context.Background(), host, []cloud.Port{ssh})
		if err != nil {
			t.Fatal(err)
		}
		return vs[0]
	}
	eval()
	eval()
	if n := f.tagCalls.Load(); n != 2 { // one read of two pages
		t.Fatalf("tag page reads %d, want 2", n)
	}
	advance(23 * time.Hour)
	eval()
	if n := f.tagCalls.Load(); n != 2 {
		t.Fatalf("read again before 24 h: %d", n)
	}
	advance(2 * time.Hour)
	f.status["/serviceTags"] = 403 // a failed refresh keeps the last good list
	if v := eval(); !v.Open {
		t.Fatalf("a failed refresh dropped the good list: %+v", v)
	}
	if n := f.tagCalls.Load(); n != 3 {
		t.Fatalf("tag reads %d, want 3", n)
	}
	eval()
	if n := f.tagCalls.Load(); n != 3 {
		t.Fatalf("failure not cached: %d", n)
	}
	advance(11 * time.Minute)
	delete(f.status, "/serviceTags")
	eval()
	if n := f.tagCalls.Load(); n != 5 {
		t.Fatalf("not retried after 10 min: %d", n)
	}

	t.Run("failure without a good list is cached and undetermined", func(t *testing.T) {
		f := newFake(t)
		f.status["/serviceTags"] = 403
		p := f.provider(t, func(o *Options) { o.Now = clock })
		for range 2 {
			vs, err := p.Evaluate(context.Background(), host, []cloud.Port{ssh})
			if err != nil || vs[0].Complete || !strings.Contains(strings.Join(vs[0].Evidence, "\n"), "service tags not read: service tags: 403") {
				t.Fatalf("%v %+v", err, vs)
			}
		}
		if n := f.tagCalls.Load(); n != 1 {
			t.Fatalf("tag reads %d, want 1", n)
		}
	})
	t.Run("nextLink to another host is refused", func(t *testing.T) {
		f := newFake(t)
		f.bodies["/serviceTags"] = strings.Replace(f.read("servicetags-1.json"), `"NEXT"`, `"https://evil.example/x"`, 1)
		vs, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh})
		if err != nil || vs[0].Complete || !strings.Contains(strings.Join(vs[0].Evidence, "\n"), "is not on") {
			t.Fatalf("%v %+v", err, vs)
		}
	})
	t.Run("not read when no rule names a tag", func(t *testing.T) {
		f := newFake(t)
		f.bodies["/networkSecurityGroups/subnet-nsg"] = strings.Replace(f.read("nsg-subnet.json"), "AzureFrontDoor.Backend", "Internet", 1)
		if _, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh}); err != nil {
			t.Fatal(err)
		}
		if f.tagCalls.Load() != 0 {
			t.Fatal("service tags read without need")
		}
	})
}

// A3 (REST "Service Tags - List"): the list is paged with nextLink and tag names match
// case-insensitively; a regional tag is its own entry.
func TestAssumptionA3ServiceTagPaging(t *testing.T) {
	f := newFake(t)
	p := f.provider(t, nil)
	tags, err := p.readTags(context.Background(), sub, "westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tags.lookup("azurefrontdoor.BACKEND"); !ok {
		t.Fatalf("second page's tag missing: %v", tags)
	}
	if _, ok := tags.lookup("AzureCloud"); !ok {
		t.Fatal("first page's tag missing")
	}
}

func TestTokens(t *testing.T) {
	t.Run("client secret", func(t *testing.T) {
		f := newFake(t)
		p := f.provider(t, nil)
		if p.Credential != "client secret (app "+clientID+")" {
			t.Fatal(p.Credential)
		}
		if _, err := p.tokens.token(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("federated token re-read per exchange", func(t *testing.T) {
		f := newFake(t)
		file := writeFile(t, "assertion-1\n")
		now := time.Now()
		p := f.provider(t, func(o *Options) {
			o.ClientSecretFile, o.FederatedTokenFile = "", file
			o.Now = func() time.Time { return now }
		})
		if _, err := p.tokens.token(context.Background()); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(file, []byte("assertion-2"), 0o600)
		now = now.Add(2 * time.Hour)
		if _, err := p.tokens.token(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.forms[0]["client_assertion"] != "assertion-1" || f.forms[1]["client_assertion"] != "assertion-2" ||
			f.forms[1]["client_assertion_type"] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || f.forms[1]["client_secret"] != "" {
			t.Fatalf("forms %v", f.forms)
		}
	})
	t.Run("managed identity", func(t *testing.T) {
		f := newFake(t)
		p := f.provider(t, func(o *Options) { o.ClientSecretFile, o.TenantID = "", "" })
		if p.Credential != "managed identity (user-assigned "+clientID+")" {
			t.Fatal(p.Credential)
		}
		vs, err := p.Evaluate(context.Background(), host, []cloud.Port{ssh})
		if err != nil || !vs[0].Open {
			t.Fatalf("%v %+v", err, vs)
		}
		got := f.forms[0]
		if got["client_id"] != clientID || got["resource"] != "https://management.azure.com/" || got["api-version"] != "2018-02-01" {
			t.Fatalf("IMDS query %v", got)
		}
	})
	t.Run("expires_in as string or number", func(t *testing.T) {
		for _, in := range []string{`"3599"`, `3599`} {
			var s seconds
			if err := s.UnmarshalJSON([]byte(in)); err != nil || s != 3599 {
				t.Fatalf("%s: %v %d", in, err, s)
			}
		}
		var s seconds
		if s.UnmarshalJSON([]byte(`"soon"`)) == nil {
			t.Fatal("accepted a non-number")
		}
	})
	t.Run("error never carries the secret", func(t *testing.T) {
		f := newFake(t)
		f.status["token"] = 401
		_, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh})
		if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "invalid_client (AADSTS7000215)") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("tenant is escaped in the path", func(t *testing.T) {
		if got := tokenEndpoint("https://login.microsoftonline.com", "contoso.onmicrosoft.com"); got != "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token" {
			t.Fatal(got)
		}
	})
}

func TestNewErrors(t *testing.T) {
	file := writeFile(t, "x")
	empty := writeFile(t, " \n")
	cases := []struct {
		name string
		o    Options
		want string
	}{
		{"no subscriptions", Options{}, "subscriptions is required"},
		{"bad subscription", Options{Subscriptions: []string{"prod"}}, "not a subscription id"},
		{"secret and federated", Options{Subscriptions: []string{sub}, ClientSecretFile: file, FederatedTokenFile: file}, "not both"},
		{"secret without tenant", Options{Subscriptions: []string{sub}, ClientID: clientID, ClientSecretFile: file}, "tenant_id is required"},
		{"bad tenant", Options{Subscriptions: []string{sub}, TenantID: "a/b", ClientID: clientID, ClientSecretFile: file}, "tenant_id is required"},
		{"secret without client", Options{Subscriptions: []string{sub}, TenantID: tenant, ClientSecretFile: file}, "client_id is required"},
		{"bad client id", Options{Subscriptions: []string{sub}, ClientID: "app"}, "client_id is not"},
		{"missing secret file", Options{Subscriptions: []string{sub}, TenantID: tenant, ClientID: clientID, ClientSecretFile: "/nonexistent/x"}, "client secret file"},
		{"empty secret file", Options{Subscriptions: []string{sub}, TenantID: tenant, ClientID: clientID, ClientSecretFile: empty}, "empty"},
		{"missing federated file", Options{Subscriptions: []string{sub}, TenantID: tenant, ClientID: clientID, FederatedTokenFile: "/nonexistent/x"}, "federated token file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
	p, err := New(Options{Subscriptions: []string{sub}})
	if err != nil || p.Credential != "managed identity" {
		t.Fatalf("%v %v", err, p)
	}
}

// Review m579 minor: a rule whose direction is not understood is judged (as maybe), so the
// service tags it names are read and its reason names the direction, not "tags not read".
func TestTagsReadForUnknownDirection(t *testing.T) {
	f := newFake(t)
	nsg := strings.Replace(f.read("nsg-subnet.json"), `"priority": 310, "direction": "Inbound"`, `"priority": 310, "direction": "Both"`, 1)
	f.bodies["/networkSecurityGroups/subnet-nsg"] = nsg
	vs, err := f.provider(t, nil).Evaluate(context.Background(), host, []cloud.Port{ssh})
	if err != nil {
		t.Fatal(err)
	}
	ev := strings.Join(vs[0].Evidence, "\n")
	if f.tagCalls.Load() == 0 || vs[0].Complete || !strings.Contains(ev, `direction "Both" not understood`) || strings.Contains(ev, "service tags not read") {
		t.Fatalf("tag reads %d, %+v", f.tagCalls.Load(), vs[0])
	}
}
