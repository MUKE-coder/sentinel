// Package safefetch provides an SSRF-hardened *http.Client.
//
// SSRF (Server-Side Request Forgery) is one of the highest-blast-radius web
// vulns: an attacker tricks the server into making an outbound request to
// 169.254.169.254 (cloud metadata IAM credentials), internal Redis/Postgres,
// or other systems unreachable from the public internet. The classic
// trigger is a feature shipped without SSRF in mind: webhook delivery,
// "fetch image from URL", PDF render from URL, OEmbed expansion.
//
// safefetch.Client returns a drop-in *http.Client that enforces the SSRF
// policy at three points:
//
//  1. Request build — scheme allowlist (http/https only by default).
//  2. Redirect check — every redirect URL re-evaluated against the policy.
//  3. TCP connect — net.Dialer.Control re-checks the *resolved* IP, closing
//     the DNS-rebinding TOCTOU window where local validation passes but the
//     hostname re-resolves to an internal IP at connect time.
//
// Every blocked attempt can be reported to a Sentinel pipeline so SSRF
// findings show up next to WAF blocks in the dashboard.
package safefetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// ErrBlocked is returned when a request is refused by the SSRF policy.
// Wrapped errors carry the specific reason.
var ErrBlocked = errors.New("safefetch: request blocked by SSRF policy")

// Reporter receives a record of every blocked outbound attempt. Sentinel's
// pipeline.Pipeline implements this via the EmitThreat method.
type Reporter interface {
	EmitThreat(payload interface{})
}

// Options configures the SSRF policy of a safefetch Client.
type Options struct {
	// AllowedSchemes is the set of URL schemes permitted. If empty,
	// defaults to {"http", "https"}.
	AllowedSchemes []string

	// AllowedHosts is an explicit allowlist of hostnames that override the
	// IP-range denylist. Use for legitimate internal calls where you know
	// the target.
	AllowedHosts []string

	// AllowedCIDRs is an explicit allowlist of CIDR ranges that override the
	// built-in private/loopback/metadata denylist.
	AllowedCIDRs []string

	// AllowPrivateRanges, when true, disables the RFC1918 / loopback /
	// link-local / CGNAT denylist. Off by default. Use only when the
	// caller genuinely needs to talk to internal services.
	AllowPrivateRanges bool

	// Timeout is the per-request timeout. Default: 30s.
	Timeout time.Duration

	// Reporter, if non-nil, receives a ThreatEvent payload for every blocked
	// attempt — so SSRF events flow into Sentinel's dashboard alongside WAF
	// blocks.
	Reporter Reporter
}

// Client returns an SSRF-hardened *http.Client. Calls to URLs that fail
// the policy return ErrBlocked. Reuses one client across calls — safe for
// concurrent use.
func Client(opts Options) *http.Client {
	if len(opts.AllowedSchemes) == 0 {
		opts.AllowedSchemes = []string{"http", "https"}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	allowedCIDRs := parseCIDRs(opts.AllowedCIDRs)
	allowedHosts := make(map[string]bool, len(opts.AllowedHosts))
	for _, h := range opts.AllowedHosts {
		allowedHosts[strings.ToLower(strings.TrimSpace(h))] = true
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			// network is "tcp4"/"tcp6"; address is "ip:port" already resolved.
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if hostExplicitlyAllowed("", allowedHosts) { // host-allow already vetted upstream
				return nil
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: dial resolved to invalid IP %q", ErrBlocked, host)
			}
			if !opts.AllowPrivateRanges && isBlockedIP(addr, allowedCIDRs) {
				return fmt.Errorf("%w: dial resolved to disallowed IP %s", ErrBlocked, host)
			}
			return nil
		},
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	check := func(req *http.Request) error {
		return validateRequest(req, opts, allowedHosts, allowedCIDRs)
	}

	return &http.Client{
		Timeout:   opts.Timeout,
		Transport: &guardedTransport{base: transport, check: check, opts: opts},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("safefetch: stopped after 10 redirects")
			}
			return check(req)
		},
	}
}

// guardedTransport runs the SSRF check before every RoundTrip so callers
// who bypass http.Client (rare) still get protection.
type guardedTransport struct {
	base  http.RoundTripper
	check func(*http.Request) error
	opts  Options
}

func (g *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.check(req); err != nil {
		g.opts.report(req, err)
		return nil, err
	}
	return g.base.RoundTrip(req)
}

func (o Options) report(req *http.Request, blockErr error) {
	if o.Reporter == nil {
		return
	}
	host := ""
	if req.URL != nil {
		host = req.URL.Host
	}
	cvss := sentinel.DefaultCVSSForType(string(sentinel.ThreatSSRF))
	o.Reporter.EmitThreat(&sentinel.ThreatEvent{
		Timestamp:   time.Now(),
		Method:      req.Method,
		Path:        host,
		ThreatTypes: []string{string(sentinel.ThreatSSRF)},
		Severity:    sentinel.SeverityHigh,
		Confidence:  95,
		Blocked:     true,
		CVSS:        cvss.Score,
		CVSSVector:  cvss.Vector,
		Evidence: []sentinel.Evidence{
			{Pattern: "ssrf-policy", Matched: blockErr.Error(), Location: "outbound-request"},
		},
	})
}

func validateRequest(req *http.Request, opts Options, allowedHosts map[string]bool, allowedCIDRs []netip.Prefix) error {
	if req.URL == nil {
		return fmt.Errorf("%w: nil URL", ErrBlocked)
	}
	scheme := strings.ToLower(req.URL.Scheme)
	if !contains(opts.AllowedSchemes, scheme) {
		return fmt.Errorf("%w: disallowed scheme %q", ErrBlocked, scheme)
	}
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBlocked)
	}
	if hostExplicitlyAllowed(host, allowedHosts) {
		return nil
	}
	// Block known cloud-metadata hostnames outright.
	if isMetadataHostname(host) {
		return fmt.Errorf("%w: cloud metadata hostname %q", ErrBlocked, host)
	}
	// If host parses as a literal IP, check immediately.
	if addr, err := netip.ParseAddr(host); err == nil {
		if !opts.AllowPrivateRanges && isBlockedIP(addr, allowedCIDRs) {
			return fmt.Errorf("%w: literal IP %s is in a denied range", ErrBlocked, host)
		}
		return nil
	}
	// Otherwise resolve and check every returned IP. Dialer.Control re-checks
	// at connect time — this is the defence-in-depth pass that gives clear
	// errors instead of a generic dial failure.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("%w: DNS lookup failed for %q: %v", ErrBlocked, host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: no IPs resolved for %q", ErrBlocked, host)
	}
	if opts.AllowPrivateRanges {
		return nil
	}
	for _, raw := range ips {
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			return fmt.Errorf("%w: invalid resolved IP for %q", ErrBlocked, host)
		}
		if isBlockedIP(addr.Unmap(), allowedCIDRs) {
			return fmt.Errorf("%w: %q resolved to disallowed IP %s", ErrBlocked, host, addr)
		}
	}
	return nil
}

// WithContext is a tiny helper for callers who want a per-call deadline on
// top of the client's Timeout.
func WithContext(ctx context.Context, req *http.Request) *http.Request {
	return req.WithContext(ctx)
}

func hostExplicitlyAllowed(host string, allowed map[string]bool) bool {
	if len(allowed) == 0 {
		return false
	}
	return allowed[host]
}

func isMetadataHostname(host string) bool {
	switch host {
	case "metadata.google.internal", "metadata", "instance-data":
		return true
	}
	return false
}

func parseCIDRs(in []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// blockedRanges enumerates the IP ranges that must never be the target of
// outbound HTTP from server-side code. Covers loopback, link-local, CGNAT,
// RFC1918 private, IPv6 ULA, AWS IMDS, and the AWS IPv6 link-local range.
var blockedRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"), // includes 169.254.169.254
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fd00:ec2::/32"),
}

func isBlockedIP(addr netip.Addr, allowedCIDRs []netip.Prefix) bool {
	for _, allowed := range allowedCIDRs {
		if allowed.Contains(addr) {
			return false
		}
	}
	for _, blocked := range blockedRanges {
		if blocked.Contains(addr) {
			return true
		}
	}
	return false
}
