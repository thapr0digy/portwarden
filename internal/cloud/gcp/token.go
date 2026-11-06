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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Fixed Google endpoints (never taken from config, a key file or a host).
const (
	tokenURL    = "https://oauth2.googleapis.com/token"
	metadataURL = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
	// scope is read-only Compute Engine access.
	scope = "https://www.googleapis.com/auth/compute.readonly"
	// maxTokenBody caps a token response.
	maxTokenBody = 64 << 10
	// tokenSlack refreshes a token this long before it expires.
	tokenSlack = 60 * time.Second
)

// serviceAccountKey is the part of a service-account JSON key the look-up reads. The
// key's token_uri is ignored: the fixed endpoint is used.
type serviceAccountKey struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
}

// jwtSigner holds a parsed service-account key.
type jwtSigner struct {
	email, keyID string
	key          *rsa.PrivateKey
}

// parseKey parses a service-account JSON key file's content. Errors never quote the key.
func parseKey(b []byte) (*jwtSigner, error) {
	var k serviceAccountKey
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("key file is not JSON: %w", err)
	}
	if k.Type != "service_account" {
		return nil, fmt.Errorf("key file type is %q, not service_account", k.Type)
	}
	if k.ClientEmail == "" {
		return nil, errors.New("key file has no client_email")
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return nil, errors.New("key file's private_key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key file's private_key is not an RSA key")
		}
		key = rk
	} else if rk, err1 := x509.ParsePKCS1PrivateKey(block.Bytes); err1 == nil {
		key = rk
	} else {
		return nil, errors.New("key file's private_key is neither PKCS#8 nor PKCS#1 RSA")
	}
	return &jwtSigner{email: k.ClientEmail, keyID: k.PrivateKeyID, key: key}, nil
}

// assertion builds the signed JWT (RS256) for the token request.
func (s *jwtSigner) assertion(now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}
	claims := map[string]any{"iss": s.email, "scope": scope, "aud": tokenURL,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	enc := func(v any) (string, error) {
		b, err := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b), err
	}
	h, err := enc(header)
	if err != nil {
		return "", err
	}
	c, err := enc(claims)
	if err != nil {
		return "", err
	}
	signing := h + "." + c
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// tokens hands out a cached access token, fetching a new one shortly before expiry. One
// fetch runs at a time; callers wait for it without holding the lock (each with its own
// context).
type tokens struct {
	fetch func(ctx context.Context) (string, time.Duration, error)
	now   func() time.Time

	mu       sync.Mutex
	tok      string
	exp      time.Time
	inflight *fetchCall
}

type fetchCall struct {
	done chan struct{}
	tok  string
	err  error
}

func (t *tokens) token(ctx context.Context) (string, error) {
	t.mu.Lock()
	if t.tok != "" && t.now().Before(t.exp) {
		tok := t.tok
		t.mu.Unlock()
		return tok, nil
	}
	c := t.inflight
	if c == nil {
		c = &fetchCall{done: make(chan struct{})}
		t.inflight = c
		go t.run(ctx, c)
	}
	t.mu.Unlock()
	select {
	case <-c.done:
		return c.tok, c.err
	case <-ctx.Done():
		return "", fmt.Errorf("gcp: token: %w", ctx.Err())
	}
}

// run fetches once for every waiter. It is bounded by the first caller's context and the
// HTTP client's timeout.
func (t *tokens) run(ctx context.Context, c *fetchCall) {
	tok, ttl, err := t.fetch(context.WithoutCancel(ctx))
	t.mu.Lock()
	if err != nil {
		c.err = fmt.Errorf("gcp: token: %w", err)
	} else {
		c.tok = tok
		t.tok, t.exp = tok, t.now().Add(ttl-tokenSlack)
	}
	t.inflight = nil
	t.mu.Unlock()
	close(c.done)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// jwtFetch exchanges a signed JWT at the token endpoint.
func jwtFetch(c *http.Client, endpoint string, s *jwtSigner, now func() time.Time) func(context.Context) (string, time.Duration, error) {
	return func(ctx context.Context) (string, time.Duration, error) {
		a, err := s.assertion(now())
		if err != nil {
			return "", 0, err
		}
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {a}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return doToken(c, req, false)
	}
}

// metadataFetch asks the metadata server of the GCE machine the backend runs on.
func metadataFetch(c *http.Client, endpoint string) func(context.Context) (string, time.Duration, error) {
	return func(ctx context.Context) (string, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Metadata-Flavor", "Google")
		return doToken(c, req, true)
	}
}

func doToken(c *http.Client, req *http.Request, metadata bool) (string, time.Duration, error) {
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if metadata && resp.Header.Get("Metadata-Flavor") != "Google" {
		return "", 0, errors.New("metadata server response lacks Metadata-Flavor: Google")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody+1))
	if err != nil {
		return "", 0, err
	}
	if len(body) > maxTokenBody {
		return "", 0, fmt.Errorf("token response over %d bytes", maxTokenBody)
	}
	var tr tokenResponse
	jerr := json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK {
		if jerr == nil && tr.Error != "" {
			return "", 0, fmt.Errorf("%s: %s %s", resp.Status, tr.Error, truncate(tr.Description, 200))
		}
		return "", 0, fmt.Errorf("%s", resp.Status)
	}
	if jerr != nil {
		return "", 0, fmt.Errorf("token response is not JSON: %w", jerr)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", 0, errors.New("token response has no bearer access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= tokenSlack {
		ttl = tokenSlack + time.Second // use it once, fetch again next time
	}
	return tr.AccessToken, ttl, nil
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
