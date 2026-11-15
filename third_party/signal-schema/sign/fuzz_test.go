package sign

import (
	"net/http"
	"testing"
)

// FuzzParseHeaders: the parser reads untrusted headers before anything is checked; it
// must never panic and must refuse or return a complete Params.
func FuzzParseHeaders(f *testing.F) {
	f.Add(`asm=("@method" "@authority" "@path" "content-type" "content-digest");created=1;keyid="k";alg="ed25519";tag="asm-ingest-v1"`, "asm=:"+string(make([]byte, 0))+":")
	f.Add("", "")
	f.Add(`asm=(`, `asm=::`)
	f.Fuzz(func(t *testing.T, in, sig string) {
		h := http.Header{}
		h.Add("Signature-Input", in)
		h.Add("Signature", sig)
		p, err := ParseHeaders(h)
		if err == nil && (p.KeyID == "" || len(p.Signature) != 64 || p.Created.IsZero()) {
			t.Fatalf("accepted an incomplete %+v", p)
		}
	})
}
