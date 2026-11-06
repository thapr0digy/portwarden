package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Fixed Microsoft endpoints (never taken from config or a host).
const (
	loginURL = "https://login.microsoftonline.com"
	imdsURL  = "http://169.254.169.254/metadata/identity/oauth2/token"
	// armScope and armResource ask for an ARM token (v2 scope; IMDS's v1 resource).
	armScope    = "https://management.azure.com/.default"
	armResource = "https://management.azure.com/"
	// maxTokenBody caps a token response; maxAssertion a federated token file.
	maxTokenBody = 64 << 10
	maxAssertion = 64 << 10
	// tokenSlack refreshes a token this long before it expires.
	tokenSlack = 5 * time.Minute
)

// tenantRe is a tenant id: a UUID or a domain name.
var tenantRe = regexp.MustCompile(`^(?:` + uuidPattern + `|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$`)

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
		return "", fmt.Errorf("azure: token: %w", ctx.Err())
	}
}

// run fetches once for every waiter, bounded by the HTTP client's timeout.
func (t *tokens) run(ctx context.Context, c *fetchCall) {
	tok, ttl, err := t.fetch(context.WithoutCancel(ctx))
	t.mu.Lock()
	if err != nil {
		c.err = fmt.Errorf("azure: token: %w", err)
	} else {
		c.tok = tok
		t.tok, t.exp = tok, t.now().Add(ttl-tokenSlack)
	}
	t.inflight = nil
	t.mu.Unlock()
	close(c.done)
}

// seconds is expires_in: a number from Entra ID, a string from IMDS.
type seconds int64

func (s *seconds) UnmarshalJSON(b []byte) error {
	b = bytes.Trim(b, `"`)
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("expires_in %q is not a number of seconds", truncate(string(b), 20))
	}
	*s = seconds(n)
	return nil
}

type tokenResponse struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   seconds `json:"expires_in"`
	TokenType   string  `json:"token_type"`
	Error       string  `json:"error"`
	// ErrorCodes are Entra ID's AADSTS numbers; the description is not reported (it can
	// echo request details).
	ErrorCodes []int `json:"error_codes"`
}

// clientCredentials posts a client-credentials grant to the tenant's v2 token endpoint;
// form adds the secret or the assertion.
func clientCredentials(c *http.Client, endpoint string, form func() (url.Values, error)) func(context.Context) (string, time.Duration, error) {
	return func(ctx context.Context) (string, time.Duration, error) {
		f, err := form()
		if err != nil {
			return "", 0, err
		}
		f.Set("grant_type", "client_credentials")
		f.Set("scope", armScope)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(f.Encode()))
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return doToken(c, req)
	}
}

// tokenEndpoint is the tenant's v2 token endpoint under base (the fixed login host).
func tokenEndpoint(base, tenant string) string {
	return strings.TrimSuffix(base, "/") + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
}

// secretForm sends a client secret.
func secretForm(clientID, secret string) func() (url.Values, error) {
	return func() (url.Values, error) {
		return url.Values{"client_id": {clientID}, "client_secret": {secret}}, nil
	}
}

// federatedForm sends the federated token, re-read from its file at every exchange (the
// issuer rotates it).
func federatedForm(clientID, file string) func() (url.Values, error) {
	return func() (url.Values, error) {
		a, err := readSmall(file, maxAssertion)
		if err != nil {
			return nil, fmt.Errorf("federated token file: %w", err)
		}
		a = strings.TrimSpace(a)
		if a == "" {
			return nil, errors.New("federated token file is empty")
		}
		return url.Values{"client_id": {clientID}, "client_assertion": {a},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}}, nil
	}
}

// imdsFetch asks the instance metadata service of the Azure VM the backend runs on for
// its managed identity's token (clientID selects a user-assigned identity).
func imdsFetch(c *http.Client, endpoint, clientID string) func(context.Context) (string, time.Duration, error) {
	return func(ctx context.Context) (string, time.Duration, error) {
		q := url.Values{"api-version": {"2018-02-01"}, "resource": {armResource}}
		if clientID != "" {
			q.Set("client_id", clientID)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Metadata", "true")
		return doToken(c, req)
	}
}

func doToken(c *http.Client, req *http.Request) (string, time.Duration, error) {
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
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
			msg := fmt.Sprintf("%s: %s", resp.Status, truncate(tr.Error, 100))
			if len(tr.ErrorCodes) > 0 {
				msg += fmt.Sprintf(" (AADSTS%d)", tr.ErrorCodes[0])
			}
			return "", 0, errors.New(msg)
		}
		return "", 0, errors.New(resp.Status)
	}
	if jerr != nil {
		return "", 0, fmt.Errorf("token response is not the expected JSON: %w", jerr)
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

// readSmall reads a file of at most limit bytes.
func readSmall(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(b)) > limit {
		return "", fmt.Errorf("over %d bytes", limit)
	}
	return string(b), nil
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
