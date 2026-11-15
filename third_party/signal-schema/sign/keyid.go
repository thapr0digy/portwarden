package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
)

// KeyID is the key id a producer signs with: the RFC 7638 JWK thumbprint of its Ed25519
// public key as an RFC 8037 OKP key, base64url without padding (43 characters). A producer
// computes it from its own key; the product derives the same id when the key is registered.
// It names the key and proves nothing: the signature does.
func KeyID(pub ed25519.PublicKey) string {
	// RFC 7638 §3.2: the required members in lexicographic order, no whitespace.
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
