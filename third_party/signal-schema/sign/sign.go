// Package sign signs and verifies ingest requests: an RFC 9421 HTTP message
// signature (Ed25519, one fixed label and tag) over an RFC 9530 Content-Digest.
// It uses only the standard library, so a producer can depend on it freely.
//
// A request carries
//
//	Content-Digest: sha-256=:<base64 sha256 of the body as sent>:
//	Signature-Input: asm=("@method" "@authority" "@path" "content-type" ["content-encoding"] "content-digest");created=N;keyid="K";alg="ed25519";tag="asm-ingest-v1"
//	Signature: asm=:<base64 signature>:
//
// The receiver parses the headers first (ParseHeaders reads no body, so an unknown
// key is refused before the body is read), then reads the body, then calls Verify.
package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Fixed protocol values.
const (
	Label = "asm"
	Tag   = "asm-ingest-v1"
	Alg   = "ed25519"
	// MaxSkew is how far created may be from the receiver's clock.
	MaxSkew = 15 * time.Minute
	// maxHeader bounds the signature headers the parser will look at.
	maxHeader = 2048
	// maxKeyID bounds keyid.
	maxKeyID = 128
)

// Code is a stable failure code (the ingest error.code of a 401).
type Code string

// The failure codes.
const (
	// CodeBadHeader is a signature header that is missing, malformed or not the fixed profile.
	CodeBadHeader Code = "bad_header"
	// CodeBadDigest is a Content-Digest that does not match the body.
	CodeBadDigest Code = "bad_digest"
	// CodeBadSignature is a signature that does not verify.
	CodeBadSignature Code = "bad_signature"
	// CodeClockSkew is a created time outside the allowed window.
	CodeClockSkew Code = "clock_skew"
	// CodeUnsupportedAlg is an algorithm other than ed25519.
	CodeUnsupportedAlg Code = "unsupported_alg"
)

// Error is a signature failure with its code.
type Error struct {
	Code   Code
	Reason string
}

func (e *Error) Error() string { return "sign: " + string(e.Code) + ": " + e.Reason }

func fail(c Code, format string, a ...any) *Error {
	return &Error{Code: c, Reason: fmt.Sprintf(format, a...)}
}

// CodeOf returns the failure code in err, or "" when err is not a sign error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// ContentDigest is the Content-Digest header value for body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// Params are the parsed Signature-Input and Signature of a request.
type Params struct {
	KeyID      string
	Created    time.Time
	Components []string
	// Raw is the signature-params text after "asm=", exactly as sent (the signature base
	// repeats it).
	Raw       string
	Signature []byte
}

var (
	baseComponents     = []string{"@method", "@authority", "@path", "content-type", "content-digest"}
	withEncodingParams = []string{"@method", "@authority", "@path", "content-type", "content-encoding", "content-digest"}
)

// Sign sets Content-Digest, Signature-Input and Signature on req for body. The
// request's Host (or URL host) is the authority; Content-Type must be set.
func Sign(req *http.Request, body []byte, key ed25519.PrivateKey, keyID string, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize {
		return fail(CodeUnsupportedAlg, "key is not an Ed25519 private key")
	}
	if keyID == "" || len(keyID) > maxKeyID || strings.ContainsAny(keyID, "\"\\\r\n") {
		return fail(CodeBadHeader, "keyid is empty, too long or has a forbidden character")
	}
	if req.Header.Get("Content-Type") == "" {
		return fail(CodeBadHeader, "Content-Type is required")
	}
	req.Header.Set("Content-Digest", ContentDigest(body))
	comps := baseComponents
	if req.Header.Get("Content-Encoding") != "" {
		comps = withEncodingParams
	}
	raw := paramsText(comps, now.Unix(), keyID)
	base, err := signatureBase(req, comps, raw)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(key, []byte(base))
	req.Header.Set("Signature-Input", Label+"="+raw)
	req.Header.Set("Signature", Label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

func paramsText(comps []string, created int64, keyID string) string {
	q := make([]string, len(comps))
	for i, c := range comps {
		q[i] = `"` + c + `"`
	}
	return "(" + strings.Join(q, " ") + ");created=" + strconv.FormatInt(created, 10) +
		`;keyid="` + keyID + `";alg="` + Alg + `";tag="` + Tag + `"`
}

func authority(req *http.Request) string {
	if req.Host != "" {
		return strings.ToLower(req.Host)
	}
	if req.URL != nil {
		return strings.ToLower(req.URL.Host)
	}
	return ""
}

func signatureBase(req *http.Request, comps []string, raw string) (string, *Error) {
	var b strings.Builder
	for _, c := range comps {
		var v string
		switch c {
		case "@method":
			v = req.Method
		case "@authority":
			v = authority(req)
		case "@path":
			v = req.URL.EscapedPath()
		default:
			vals := req.Header.Values(c)
			if len(vals) != 1 {
				return "", fail(CodeBadHeader, "%s must appear exactly once", c)
			}
			v = strings.TrimSpace(vals[0])
		}
		if strings.ContainsAny(v, "\r\n") {
			return "", fail(CodeBadHeader, "%s has a line break", c)
		}
		b.WriteString(`"` + c + `": ` + v + "\n")
	}
	b.WriteString(`"@signature-params": ` + raw)
	return b.String(), nil
}

// ParseHeaders reads the signature headers of h. It looks at no body and no
// other header; an error is a 401 before the body is read.
func ParseHeaders(h http.Header) (Params, error) {
	in, sg := h.Values("Signature-Input"), h.Values("Signature")
	if len(in) != 1 || len(sg) != 1 {
		return Params{}, fail(CodeBadHeader, "exactly one Signature-Input and one Signature are required")
	}
	if len(in[0]) > maxHeader || len(sg[0]) > maxHeader {
		return Params{}, fail(CodeBadHeader, "signature header too long")
	}
	raw, ok := strings.CutPrefix(in[0], Label+"=")
	if !ok {
		return Params{}, fail(CodeBadHeader, "signature label must be %q", Label)
	}
	p := Params{Raw: raw}
	rest, ok := strings.CutPrefix(raw, "(")
	if !ok {
		return Params{}, fail(CodeBadHeader, "missing component list")
	}
	list, rest, ok := strings.Cut(rest, ")")
	if !ok {
		return Params{}, fail(CodeBadHeader, "unterminated component list")
	}
	for _, f := range strings.Fields(list) {
		name, ok := strings.CutPrefix(f, `"`)
		if ok {
			name, ok = strings.CutSuffix(name, `"`)
		}
		if !ok || name == "" || strings.ContainsAny(name, `"\`) {
			return Params{}, fail(CodeBadHeader, "malformed component")
		}
		p.Components = append(p.Components, name)
	}
	if !equalList(p.Components, baseComponents) && !equalList(p.Components, withEncodingParams) {
		return Params{}, fail(CodeBadHeader, "covered components are not the fixed set")
	}
	var created, alg, tag, keyid bool
	for _, part := range strings.Split(strings.TrimPrefix(rest, ";"), ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || rest == "" || !strings.HasPrefix(rest, ";") {
			return Params{}, fail(CodeBadHeader, "malformed parameter")
		}
		switch k {
		case "created":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 || created {
				return Params{}, fail(CodeBadHeader, "bad created")
			}
			created, p.Created = true, time.Unix(n, 0)
		case "keyid":
			s, ok := unquote(v)
			if !ok || s == "" || len(s) > maxKeyID || keyid {
				return Params{}, fail(CodeBadHeader, "bad keyid")
			}
			keyid, p.KeyID = true, s
		case "alg":
			s, ok := unquote(v)
			if !ok || alg {
				return Params{}, fail(CodeBadHeader, "bad alg")
			}
			if s != Alg {
				return Params{}, fail(CodeUnsupportedAlg, "alg must be %q", Alg)
			}
			alg = true
		case "tag":
			s, ok := unquote(v)
			if !ok || s != Tag || tag {
				return Params{}, fail(CodeBadHeader, "tag must be %q", Tag)
			}
			tag = true
		default:
			return Params{}, fail(CodeBadHeader, "unknown parameter")
		}
	}
	if !created || !alg || !tag || !keyid {
		return Params{}, fail(CodeBadHeader, "created, keyid, alg and tag are required")
	}
	enc, ok := strings.CutPrefix(sg[0], Label+"=:")
	if ok {
		enc, ok = strings.CutSuffix(enc, ":")
	}
	if !ok {
		return Params{}, fail(CodeBadHeader, "malformed Signature")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(enc)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Params{}, fail(CodeBadHeader, "Signature is not an Ed25519 signature")
	}
	p.Signature = sig
	return p, nil
}

func unquote(v string) (string, bool) {
	s, ok := strings.CutPrefix(v, `"`)
	if ok {
		s, ok = strings.CutSuffix(s, `"`)
	}
	if !ok || strings.ContainsAny(s, `"\`) {
		return "", false
	}
	return s, true
}

func equalList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Verify checks the digest of body against the request's Content-Digest, the
// signature against pub, and created against now (within skew; 0 means MaxSkew).
// The digest is checked first, so a wrong body is bad_digest, not bad_signature.
func Verify(req *http.Request, body []byte, p Params, pub ed25519.PublicKey, now time.Time, skew time.Duration) error {
	if len(pub) != ed25519.PublicKeySize {
		return fail(CodeBadSignature, "no usable public key")
	}
	if skew <= 0 {
		skew = MaxSkew
	}
	if d := now.Sub(p.Created); d > skew || d < -skew {
		return fail(CodeClockSkew, "created is outside the allowed window")
	}
	got := req.Header.Values("Content-Digest")
	if len(got) != 1 || got[0] != ContentDigest(body) {
		return fail(CodeBadDigest, "Content-Digest does not match the body")
	}
	base, err := signatureBase(req, p.Components, p.Raw)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, []byte(base), p.Signature) {
		return fail(CodeBadSignature, "signature does not verify")
	}
	return nil
}
