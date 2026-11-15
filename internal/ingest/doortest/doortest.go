// Package doortest serves a handler the way Signal's ingest door is served, for tests: TLS
// 1.3 only, with a self-signed Ed25519 certificate made from a seed (as Signal's
// push.Certificate makes it), so a client pins its key and trusts no CA.
package doortest

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thapr0digy/portwarden/internal/ingest"
)

// Cert is the door certificate of a 32-byte seed and its pin.
func Cert(t testing.TB, seed []byte) (tls.Certificate, string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "signal-ingest"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, ingest.PinOf(c.RawSubjectPublicKeyInfo)
}

// Seed is a fixed test seed made of b.
func Seed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return s
}

// Start serves h over TLS with the certificate of Seed(1) and returns the server and its
// pin: TLS 1.3 only when maxVersion is 0, else TLS 1.2 up to maxVersion (a door that is
// not what Signal runs). The server stops with the test.
func Start(t testing.TB, h http.Handler, maxVersion uint16) (*httptest.Server, string) {
	t.Helper()
	cert, pin := Cert(t, Seed(1))
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if maxVersion != 0 {
		ts.TLS.MinVersion, ts.TLS.MaxVersion = tls.VersionTLS12, maxVersion
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, pin
}
