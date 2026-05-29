// Package captcha provides pluggable CAPTCHA verification for the AuthShield
// CAPTCHA tier — the middle ground between "fine" and "locked out".
//
// The CAPTCHA tier exists because real attacker traffic almost always falls
// in the gap where it's suspicious but not yet over the lockout threshold.
// Requiring a CAPTCHA there separates humans (mildly inconvenienced) from
// credential stuffers (effectively blocked) without paying the
// customer-support cost of locking out a real user.
//
// Built-in providers cover the three commercial CAPTCHA services
// (hCaptcha, Cloudflare Turnstile, Google reCAPTCHA v2) and a self-hosted
// arithmetic challenge for projects that don't want a third party.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider verifies a CAPTCHA token returned by the user's browser.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Name identifies the provider in logs and dashboard ("hcaptcha", etc).
	Name() string
	// Verify checks the supplied token (from the request) against the
	// provider, returning nil on success. Implementations should bound
	// their HTTP timeout themselves — Verify is called inline in the
	// request path.
	Verify(ctx context.Context, token, clientIP string) error
}

// ErrInvalid is returned when the CAPTCHA token is missing, malformed, or
// rejected by the provider.
var ErrInvalid = errors.New("captcha: invalid token")

// --- hCaptcha ---

// HCaptchaProvider verifies tokens with hCaptcha's siteverify endpoint.
type HCaptchaProvider struct {
	secret string
	client *http.Client
	url    string
}

// NewHCaptchaProvider returns a Provider that verifies against hCaptcha.
func NewHCaptchaProvider(secret string) *HCaptchaProvider {
	return &HCaptchaProvider{
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
		url:    "https://hcaptcha.com/siteverify",
	}
}

// Name implements Provider.
func (h *HCaptchaProvider) Name() string { return "hcaptcha" }

// Verify implements Provider.
func (h *HCaptchaProvider) Verify(ctx context.Context, token, clientIP string) error {
	return verifySiteverify(ctx, h.client, h.url, h.secret, token, clientIP)
}

// --- Cloudflare Turnstile ---

// TurnstileProvider verifies tokens with Cloudflare Turnstile.
type TurnstileProvider struct {
	secret string
	client *http.Client
	url    string
}

// NewTurnstileProvider returns a Provider that verifies against Cloudflare Turnstile.
func NewTurnstileProvider(secret string) *TurnstileProvider {
	return &TurnstileProvider{
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
		url:    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	}
}

// Name implements Provider.
func (t *TurnstileProvider) Name() string { return "turnstile" }

// Verify implements Provider.
func (t *TurnstileProvider) Verify(ctx context.Context, token, clientIP string) error {
	return verifySiteverify(ctx, t.client, t.url, t.secret, token, clientIP)
}

// --- Google reCAPTCHA v2 ---

// RecaptchaProvider verifies tokens with Google reCAPTCHA v2.
type RecaptchaProvider struct {
	secret string
	client *http.Client
	url    string
}

// NewRecaptchaProvider returns a Provider that verifies against Google reCAPTCHA.
func NewRecaptchaProvider(secret string) *RecaptchaProvider {
	return &RecaptchaProvider{
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
		url:    "https://www.google.com/recaptcha/api/siteverify",
	}
}

// Name implements Provider.
func (r *RecaptchaProvider) Name() string { return "recaptcha" }

// Verify implements Provider.
func (r *RecaptchaProvider) Verify(ctx context.Context, token, clientIP string) error {
	return verifySiteverify(ctx, r.client, r.url, r.secret, token, clientIP)
}

// verifySiteverify is the shared `secret + response` POST shape that all
// three commercial providers use.
func verifySiteverify(ctx context.Context, client *http.Client, endpoint, secret, token, ip string) error {
	if token == "" {
		return fmt.Errorf("%w: empty token", ErrInvalid)
	}
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)
	if ip != "" {
		form.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: verify: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("captcha: decode: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("%w: %v", ErrInvalid, result.ErrorCodes)
	}
	return nil
}

// --- Self-hosted arithmetic challenge ---

// SelfHostedProvider verifies tokens issued by Sentinel itself — useful for
// projects that don't want a third-party CAPTCHA. Tokens are HMAC-signed
// answers to a simple arithmetic problem ("3 + 4"). The matching JS widget
// lives in the dashboard; minimal but real friction for bots.
type SelfHostedProvider struct {
	secret string
}

// NewSelfHostedProvider returns a Provider that validates self-issued tokens.
// secret should be the same key used by IssueSelfHostedToken — typically
// Config.Dashboard.SecretKey.
func NewSelfHostedProvider(secret string) *SelfHostedProvider {
	return &SelfHostedProvider{secret: secret}
}

// Name implements Provider.
func (s *SelfHostedProvider) Name() string { return "self-hosted" }

// Verify implements Provider. The expected token shape is documented at
// IssueSelfHostedToken; treat any malformed token as invalid.
func (s *SelfHostedProvider) Verify(_ context.Context, token, _ string) error {
	if err := verifySelfHostedToken(s.secret, token); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}
