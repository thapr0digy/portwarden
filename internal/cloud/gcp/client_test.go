package gcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/thapr0digy/portwarden/internal/cloud"
	"github.com/thapr0digy/portwarden/internal/cloud/reach"
)

const (
	project  = "acme-prod"
	zone     = "us-central1-a"
	instNum  = "4567890123456789012"
	resource = "projects/" + project + "/zones/" + zone + "/instances/" + instNum
	saEmail  = "portwarden@acme-ops.iam.gserviceaccount.com"
)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func writeKey(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "acme-ops", "private_key_id": "kid1",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "client_email": saEmail,
		"token_uri": "https://evil.example/token"})
	p := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeGoogle serves the token endpoint and the two Compute calls from testdata.
type fakeGoogle struct {
	t               *testing.T
	tokenCalls      atomic.Int32
	effectiveStatus int
	instanceStatus  int
	instanceBody    []byte
	effectivePaths  []string
	unexpectedPaths []string
}

func (f *fakeGoogle) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, 400)
			return
		}
		verifyJWT(f.t, r.Form.Get("assertion"))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"ya29.test","expires_in":3599,"token_type":"Bearer"}`))
	})
	mux.HandleFunc("GET /compute/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ya29.test" {
			http.Error(w, `{"error":{"code":401,"message":"no token"}}`, 401)
			return
		}
		base := "/compute/v1/projects/" + project + "/zones/" + zone + "/instances/"
		switch {
		case r.URL.Path == base+instNum:
			if f.instanceStatus != 0 {
				w.WriteHeader(f.instanceStatus)
				w.Write([]byte(`{"error":{"code":404,"message":"The resource 'projects/acme-prod/zones/us-central1-a/instances/4567890123456789012' was not found","status":"NOT_FOUND"}}`))
				return
			}
			body := f.instanceBody
			if body == nil {
				body = mustRead(f.t, "testdata/instance.json")
			}
			w.Write(body)
		case r.URL.Path == base+"web-1/getEffectiveFirewalls":
			f.effectivePaths = append(f.effectivePaths, r.URL.RawQuery)
			if f.effectiveStatus != 0 {
				w.WriteHeader(f.effectiveStatus)
				w.Write([]byte(`{"error":{"code":403,"message":"Required 'compute.instances.getEffectiveFirewalls' permission","status":"PERMISSION_DENIED"}}`))
				return
			}
			w.Write(mustRead(f.t, "testdata/effective-nic0.json"))
		default:
			f.unexpectedPaths = append(f.unexpectedPaths, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	return mux
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Error(err)
	}
	return b
}

func verifyJWT(t *testing.T, a string) {
	t.Helper()
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		t.Errorf("assertion has %d parts", len(parts))
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Error(err)
		return
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Errorf("signature: %v", err)
	}
	var h map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	json.Unmarshal(hb, &h)
	if h["alg"] != "RS256" || h["typ"] != "JWT" || h["kid"] != "kid1" {
		t.Errorf("header %v", h)
	}
	var c map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(cb, &c)
	if c["iss"] != saEmail || c["scope"] != "https://www.googleapis.com/auth/compute.readonly" || c["aud"] != "https://oauth2.googleapis.com/token" {
		t.Errorf("claims %v", c)
	}
	iat, _ := c["iat"].(float64)
	exp, _ := c["exp"].(float64)
	if exp-iat != 3600 {
		t.Errorf("exp-iat = %v", exp-iat)
	}
}

func newTestProvider(t *testing.T, f *fakeGoogle) *Provider {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	p, err := New(Options{KeyFile: writeKey(t), Projects: []string{project}, Policy: reach.NewPolicy(nil),
		BaseURL: srv.URL + "/compute/v1", TokenURL: srv.URL + "/token", HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var host = cloud.Host{ID: "h1", Cloud: "gcp", InstanceID: instNum, Region: "us-central1", Resource: resource}

func ports() []cloud.Port {
	return []cloud.Port{tcp(443), tcp(22), tcp(23)}
}

func TestEvaluateEndToEnd(t *testing.T) {
	f := &fakeGoogle{t: t}
	p := newTestProvider(t, f)
	if p.Credential != "service account "+saEmail {
		t.Errorf("credential %q", p.Credential)
	}
	vs, err := p.Evaluate(context.Background(), host, ports())
	if err != nil {
		t.Fatal(err)
	}
	// 443: allowed by the tagged VPC rule (both families); 22: the VPC allow at 65534
	// comes after the network policy's internet deny only in BEFORE order, so the orders
	// disagree; 23: the organisation policy denies.
	expect(t, vs[0], isOpen, "nic0 (34.68.10.20): firewall allow-https-web (vpc, priority 1000) allows tcp/443 from 0.0.0.0/0")
	expect(t, vs[1], isUndetermined, "disagree")
	expect(t, vs[2], isClosed, "policy org-baseline rule 100 (hierarchy)")
	// Only nic0 has an external address; nic1 is not asked about.
	if len(f.effectivePaths) != 1 || f.effectivePaths[0] != "networkInterface=nic0" {
		t.Errorf("effective firewall calls %v", f.effectivePaths)
	}
	if len(f.unexpectedPaths) > 0 {
		t.Errorf("unexpected paths %v", f.unexpectedPaths)
	}
}

func TestTokenCached(t *testing.T) {
	f := &fakeGoogle{t: t}
	p := newTestProvider(t, f)
	for range 3 {
		if _, err := p.Evaluate(context.Background(), host, ports()); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.tokenCalls.Load(); n != 1 {
		t.Errorf("token fetched %d times", n)
	}
}

func TestResourceChecks(t *testing.T) {
	f := &fakeGoogle{t: t}
	p := newTestProvider(t, f)
	cases := map[string]cloud.Host{
		"no cloud_resource":            {Cloud: "gcp", InstanceID: instNum, Region: "us-central1"},
		"not projects/":                {Cloud: "gcp", InstanceID: instNum, Resource: "projects/acme-prod/zones/us-central1-a/instances/../x"},
		"names instance":               {Cloud: "gcp", InstanceID: "1", Region: "us-central1", Resource: resource},
		"is not in cloud.gcp.projects": {Cloud: "gcp", InstanceID: instNum, Region: "us-central1", Resource: "projects/other-proj/zones/us-central1-a/instances/" + instNum},
		"is not in the host's region":  {Cloud: "gcp", InstanceID: instNum, Region: "europe-west1", Resource: resource},
	}
	for want, h := range cases {
		_, err := p.Evaluate(context.Background(), h, ports())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v", want, err)
		}
	}
	if f.tokenCalls.Load() != 0 || len(f.effectivePaths) != 0 {
		t.Errorf("an invalid host reached Google: %d token calls, %v", f.tokenCalls.Load(), f.effectivePaths)
	}
}

func TestInstanceIDMismatch(t *testing.T) {
	inst := mustRead(t, "testdata/instance.json")
	f := &fakeGoogle{t: t, instanceBody: []byte(strings.Replace(string(inst), instNum, "999", 1))}
	p := newTestProvider(t, f)
	_, err := p.Evaluate(context.Background(), host, ports())
	if err == nil || !strings.Contains(err.Error(), `returned instance "999"`) {
		t.Fatalf("err %v", err)
	}
	if len(f.effectivePaths) != 0 {
		t.Error("effective firewalls read for a mismatched instance")
	}
}

func TestInstanceGetFails(t *testing.T) {
	f := &fakeGoogle{t: t, instanceStatus: 404}
	p := newTestProvider(t, f)
	_, err := p.Evaluate(context.Background(), host, ports())
	if err == nil || !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("err %v", err)
	}
}

func TestEffectiveFirewallsFails(t *testing.T) {
	f := &fakeGoogle{t: t, effectiveStatus: 403}
	p := newTestProvider(t, f)
	vs, err := p.Evaluate(context.Background(), host, ports())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		expect(t, v, isUndetermined, "getEffectiveFirewalls failed: 403 Forbidden", "compute.instances.getEffectiveFirewalls")
	}
}

func TestMalformedEffectiveFirewalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getEffectiveFirewalls") {
			w.Write([]byte(`{"firewalls": "not a list"}`))
			return
		}
		w.Write(mustRead(t, "testdata/instance.json"))
	}))
	defer srv.Close()
	p := metadataProvider(t, srv)
	vs, err := p.Evaluate(context.Background(), host, ports())
	if err != nil {
		t.Fatal(err)
	}
	expect(t, vs[0], isUndetermined, "not the expected JSON")
}

func TestBodyCap(t *testing.T) {
	big := make([]byte, maxInstanceBody+1)
	for i := range big {
		big[i] = ' '
	}
	f := &fakeGoogle{t: t, instanceBody: big}
	p := newTestProvider(t, f)
	_, err := p.Evaluate(context.Background(), host, ports())
	if err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("err %v", err)
	}
}

// metadataProvider uses a stand-in metadata server on srv at /token.
func metadataProvider(t *testing.T, srv *httptest.Server) *Provider {
	t.Helper()
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing header", 403)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		w.Write([]byte(`{"access_token":"ya29.test","expires_in":3599,"token_type":"Bearer"}`))
	}))
	t.Cleanup(md.Close)
	p, err := New(Options{Projects: []string{project}, BaseURL: srv.URL, MetadataURL: md.URL, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if p.Credential != "metadata server" {
		t.Errorf("credential %q", p.Credential)
	}
	return p
}

func TestMetadataToken(t *testing.T) {
	f := &fakeGoogle{t: t}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	p := metadataProvider(t, srv)
	p.base = srv.URL + "/compute/v1"
	if _, err := p.Evaluate(context.Background(), host, ports()); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataWithoutFlavorRefused(t *testing.T) {
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"ya29.spoof","expires_in":3599,"token_type":"Bearer"}`))
	}))
	defer md.Close()
	p, err := New(Options{Projects: []string{project}, MetadataURL: md.URL, HTTP: md.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Evaluate(context.Background(), host, ports())
	if err == nil || !strings.Contains(err.Error(), "Metadata-Flavor") {
		t.Fatalf("err %v", err)
	}
}

func TestTokenEndpointError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`))
	}))
	defer srv.Close()
	p, err := New(Options{KeyFile: writeKey(t), Projects: []string{project}, TokenURL: srv.URL, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Evaluate(context.Background(), host, ports())
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("err %v", err)
	}
}

func TestKeyFileErrors(t *testing.T) {
	dir := t.TempDir()
	ecKey := `{"type":"service_account","client_email":"x@y","private_key":"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n"}`
	for want, content := range map[string]string{
		"not JSON":                "nope",
		"not service_account":     `{"type":"authorized_user"}`,
		"no client_email":         `{"type":"service_account"}`,
		"not PEM":                 `{"type":"service_account","client_email":"x@y","private_key":"abc"}`,
		"neither PKCS#8 nor PKCS": ecKey,
	} {
		p := filepath.Join(dir, "k.json")
		os.WriteFile(p, []byte(content), 0o600)
		_, err := New(Options{KeyFile: p, Projects: []string{project}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v", want, err)
		}
		if err != nil && strings.Contains(err.Error(), "BEGIN PRIVATE KEY") {
			t.Errorf("error quotes the key: %v", err)
		}
	}
	if _, err := New(Options{KeyFile: filepath.Join(dir, "missing.json"), Projects: []string{project}}); err == nil {
		t.Error("missing key file accepted")
	}
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "projects is required") {
		t.Errorf("no projects: %v", err)
	}
}

// Assumption (design): instances.get accepts the instance number in place of its name
// (the reference says "name"). The look-up asks by number once, then uses the returned
// name for getEffectiveFirewalls, so only the first call relies on it: a 404 there is a
// host error naming the call, never a verdict.
func TestAssumptionNumericInstanceID(t *testing.T) {
	f := &fakeGoogle{t: t}
	p := newTestProvider(t, f)
	if _, err := p.Evaluate(context.Background(), host, ports()); err != nil {
		t.Fatal(err)
	}
	if len(f.effectivePaths) != 1 {
		t.Fatalf("getEffectiveFirewalls not called by name: %v (unexpected %v)", f.effectivePaths, f.unexpectedPaths)
	}
	f404 := &fakeGoogle{t: t, instanceStatus: 404}
	_, err := newTestProvider(t, f404).Evaluate(context.Background(), host, ports())
	if err == nil || !strings.Contains(err.Error(), "instances.get "+instNum) {
		t.Fatalf("err %v", err)
	}
}
