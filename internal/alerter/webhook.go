package alerter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Signature headers. The signature is HMAC-SHA256 over "<timestamp>.<body>" with the
// shared secret, hex encoded: receivers recompute it, compare in constant time and
// reject stale timestamps (replay).
const (
	HeaderTimestamp = "X-Portwarden-Timestamp"
	HeaderSignature = "X-Portwarden-Signature"
	HeaderAlertID   = "X-Portwarden-Alert-Id"
	userAgent       = "portwarden-alerter/1"
)

// Sign returns the signature header value for body sent at ts.
func Sign(secret []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	fmt.Fprintf(m, "%d.", ts)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// Verify checks a signature header (for receivers and tests). Receivers should use
// VerifyFresh, which also refuses replays of old requests.
func Verify(secret []byte, ts int64, body []byte, header string) bool {
	return hmac.Equal([]byte(Sign(secret, ts, body)), []byte(header))
}

// VerifyFresh checks the signature and that ts is within maxSkew of now.
func VerifyFresh(secret []byte, ts int64, body []byte, header string, now time.Time, maxSkew time.Duration) bool {
	d := now.Sub(time.Unix(ts, 0))
	return d <= maxSkew && d >= -maxSkew && Verify(secret, ts, body, header)
}

// CheckURL refuses a webhook URL that is not https, unless allowInsecure (alert bodies
// and the signature would cross the network in cleartext).
func CheckURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("webhook url %q is not a URL", raw)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && allowInsecure:
		return nil
	}
	return fmt.Errorf("webhook url %q must be https (set allow_insecure for plain http)", raw)
}

// Webhook delivers alerts by POST. Each alert is tried at most MaxAttempts times with
// exponential backoff (1 s doubling, at most 30 s); a 4xx other than 408 and 429 is not
// retried. Redirects are never followed.
type Webhook struct {
	URL         string
	Secret      []byte
	Timeout     time.Duration
	MaxAttempts int
	Client      *http.Client
	Now         func() time.Time
	sleep       func(context.Context, time.Duration) error
}

// NewWebhook returns a webhook with defaults (5 s timeout, 5 attempts).
func NewWebhook(url string, secret []byte, timeout time.Duration, attempts int) *Webhook {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if attempts <= 0 {
		attempts = 5
	}
	return &Webhook{URL: url, Secret: secret, Timeout: timeout, MaxAttempts: attempts,
		Client: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Now:    time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}}
}

var errPermanent = errors.New("permanent")

// SendOnce makes one delivery attempt. permanent reports a failure retrying cannot fix
// (a 4xx other than 408/429, a bad request).
func (w *Webhook) SendOnce(ctx context.Context, a *Alert) (permanent bool, err error) {
	body, err := json.Marshal(a)
	if err != nil {
		return true, err
	}
	err = w.post(ctx, a.ID, body)
	return errors.Is(err, errPermanent), err
}

// Send delivers one alert, retrying as configured.
func (w *Webhook) Send(ctx context.Context, a *Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	backoff := time.Second
	var last error
	for attempt := 1; attempt <= w.MaxAttempts; attempt++ {
		last = w.post(ctx, a.ID, body)
		if last == nil {
			return nil
		}
		if errors.Is(last, errPermanent) || attempt == w.MaxAttempts {
			break
		}
		slog.Warn("webhook delivery failed; retrying", "alert", a.ID, "attempt", attempt, "err", last, "in", backoff)
		if err := w.sleep(ctx, backoff); err != nil {
			return err
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return fmt.Errorf("webhook: alert %s not delivered: %w", a.ID, last)
}

func (w *Webhook) post(ctx context.Context, id string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, w.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %v", errPermanent, err)
	}
	ts := w.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign(w.Secret, ts, body))
	req.Header.Set(HeaderAlertID, id)
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return fmt.Errorf("%w: HTTP %d", errPermanent, resp.StatusCode)
}
