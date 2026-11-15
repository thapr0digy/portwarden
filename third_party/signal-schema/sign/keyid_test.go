package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestKeyIDMatchesRFC8037Thumbprint checks the derivation against RFC 8037 Appendix A.3, and
// that the id it gives passes Sign and ParseHeaders (43 characters, nothing the header refuses).
func TestKeyIDMatchesRFC8037Thumbprint(t *testing.T) {
	x, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := KeyID(ed25519.PublicKey(x)), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"; got != want {
		t.Fatalf("KeyID = %q, want %q", got, want)
	}
	pub, priv := keys()
	kid := KeyID(pub)
	req := httptest.NewRequest("POST", "https://ingest.example:8443/v1/ingest/batch", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/x-protobuf")
	if err := Sign(req, []byte("x"), priv, kid, now); err != nil {
		t.Fatal(err)
	}
	p, err := ParseHeaders(req.Header)
	if err != nil {
		t.Fatal(err)
	}
	if p.KeyID != kid || len(kid) != 43 {
		t.Fatalf("keyid %q (%d characters), want %q", p.KeyID, len(kid), kid)
	}
}
