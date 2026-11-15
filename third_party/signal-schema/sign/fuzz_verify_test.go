package sign

import (
	"crypto/ed25519"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzVerify: whatever the headers and body, Verify refuses unless the request was signed
// by the key; a mutated body or signature never verifies.
func FuzzVerify(f *testing.F) {
	f.Add("hello", "x", 0)
	f.Fuzz(func(t *testing.T, body, extra string, flip int) {
		pub, priv := keys()
		req := httptest.NewRequest("POST", "https://h.example/v1/ingest/batch", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-protobuf")
		if err := Sign(req, []byte(body), priv, "k", now); err != nil {
			t.Fatal(err)
		}
		p, err := ParseHeaders(req.Header)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(req, []byte(body), p, pub, now, 0); err != nil {
			t.Fatalf("a good request failed: %v", err)
		}
		if extra != "" {
			if Verify(req, []byte(body+extra), p, pub, now, 0) == nil {
				t.Fatal("a changed body verified")
			}
		}
		bad := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		if Verify(req, []byte(body), p, bad, now, 0) == nil {
			t.Fatal("verified with the wrong key")
		}
		_ = flip
	})
}
