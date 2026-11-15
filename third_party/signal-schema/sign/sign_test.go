package sign

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1762783500, 0)

func keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	k := ed25519.NewKeyFromSeed(seed)
	return k.Public().(ed25519.PublicKey), k
}

func signed(t *testing.T, body string, enc string) *http.Request {
	t.Helper()
	_, priv := keys()
	req := httptest.NewRequest("POST", "https://ingest.example:8443/v1/ingest/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-protobuf")
	if enc != "" {
		req.Header.Set("Content-Encoding", enc)
	}
	if err := Sign(req, []byte(body), priv, "ak_test", now); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, _ := keys()
	for _, enc := range []string{"", "gzip"} {
		req := signed(t, "hello", enc)
		p, err := ParseHeaders(req.Header)
		if err != nil {
			t.Fatal(err)
		}
		if p.KeyID != "ak_test" {
			t.Fatalf("keyid = %q", p.KeyID)
		}
		if err := Verify(req, []byte("hello"), p, pub, now.Add(time.Minute), 0); err != nil {
			t.Fatalf("enc %q: %v", enc, err)
		}
	}
}

func TestVerifyFailures(t *testing.T) {
	pub, _ := keys()
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1)).Public().(ed25519.PublicKey)
	cases := []struct {
		name string
		edit func(*http.Request)
		body string
		pub  ed25519.PublicKey
		at   time.Time
		want Code
	}{
		{"wrong body", nil, "hellO", pub, now, CodeBadDigest},
		{"wrong key", nil, "hello", other, now, CodeBadSignature},
		{"old", nil, "hello", pub, now.Add(16 * time.Minute), CodeClockSkew},
		{"future", nil, "hello", pub, now.Add(-16 * time.Minute), CodeClockSkew},
		{"path changed", func(r *http.Request) { r.URL.Path = "/v1/other" }, "hello", pub, now, CodeBadSignature},
		{"method changed", func(r *http.Request) { r.Method = "PUT" }, "hello", pub, now, CodeBadSignature},
		{"host changed", func(r *http.Request) { r.Host = "evil.example" }, "hello", pub, now, CodeBadSignature},
		{"content type changed", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, "hello", pub, now, CodeBadSignature},
	}
	for _, c := range cases {
		req := signed(t, "hello", "")
		if c.edit != nil {
			c.edit(req)
		}
		p, err := ParseHeaders(req.Header)
		if err != nil {
			t.Fatal(err)
		}
		err = Verify(req, []byte(c.body), p, c.pub, c.at, 0)
		if CodeOf(err) != c.want {
			t.Errorf("%s: code = %q (%v), want %q", c.name, CodeOf(err), err, c.want)
		}
	}
}

func TestParseHeadersRefusals(t *testing.T) {
	good := signed(t, "x", "").Header
	mut := func(f func(h http.Header)) http.Header {
		h := good.Clone()
		f(h)
		return h
	}
	in := good.Get("Signature-Input")
	cases := map[string]http.Header{
		"no input":   mut(func(h http.Header) { h.Del("Signature-Input") }),
		"no sig":     mut(func(h http.Header) { h.Del("Signature") }),
		"two inputs": mut(func(h http.Header) { h.Add("Signature-Input", in) }),
		"label":      mut(func(h http.Header) { h.Set("Signature-Input", strings.Replace(in, "asm=", "x=", 1)) }),
		"components": mut(func(h http.Header) { h.Set("Signature-Input", strings.Replace(in, `"content-type" `, "", 1)) }),
		"tag":        mut(func(h http.Header) { h.Set("Signature-Input", strings.Replace(in, Tag, "other", 1)) }),
		"extra":      mut(func(h http.Header) { h.Set("Signature-Input", in+`;nonce="1"`) }),
		"short sig":  mut(func(h http.Header) { h.Set("Signature", "asm=:AAAA:") }),
		"long":       mut(func(h http.Header) { h.Set("Signature-Input", in+strings.Repeat("a", 3000)) }),
	}
	for name, h := range cases {
		if _, err := ParseHeaders(h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	h := mut(func(h http.Header) { h.Set("Signature-Input", strings.Replace(in, `alg="ed25519"`, `alg="rsa"`, 1)) })
	if _, err := ParseHeaders(h); CodeOf(err) != CodeUnsupportedAlg {
		t.Errorf("alg: %v", err)
	}
}

func TestSignRefusesBadInput(t *testing.T) {
	_, priv := keys()
	req := httptest.NewRequest("POST", "https://h/v1/ingest/batch", nil)
	if err := Sign(req, nil, priv, "k", now); err == nil {
		t.Error("signed without Content-Type")
	}
	req.Header.Set("Content-Type", "x")
	if err := Sign(req, nil, priv, `k"`, now); err == nil {
		t.Error("signed with a quote in keyid")
	}
	if err := Sign(req, nil, ed25519.PrivateKey{1}, "k", now); err == nil {
		t.Error("signed with a short key")
	}
}
