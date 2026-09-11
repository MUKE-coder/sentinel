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
	// IP-range denylist, at request build and at connect time. Use for
	// legitimate internal calls where you know the target.
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

// lookupIPAddr resolves hostnames for the pre-flight check. A variable so
// tests can stand in for resolvers that turn numeric forms like
// "2130706433" or "0x7f.1" into 127.0.0.1, as getaddrinfo does.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

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
		allowedHosts[normalizeHost(h)] = true
	}

	// guarded re-checks every resolved address at connect time — Control
	// runs after DNS resolution, once per address attempted. direct skips
	// that check and is used only for AllowedHosts, which the operator has
	// vetted and which may legitimately resolve to private addresses.
	guarded := &net.Dialer{Timeout: 10 * time.Second, Control: dialControl(opts, allowedCIDRs)}
	direct := &net.Dialer{Timeout: 10 * time.Second}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// address is still "hostname:port" here (resolution happens inside
			// the dialer), so this is the one place a connection can be
			// matched against AllowedHosts.
			if host, _, err := net.SplitHostPort(address); err == nil && hostExplicitlyAllowed(normalizeHost(host), allowedHosts) {
				return direct.DialContext(ctx, network, address)
			}
			return guarded.DialContext(ctx, network, address)
		},
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
			if err := check(req); err != nil {
				opts.report(req, err)
				return err
			}
			return nil
		},
	}
}

// dialControl returns the connect-time guard. The address it sees is the
// resolved "ip:port" actually being dialled, so a hostname that passed
// validation and then re-resolves to an internal address is still refused.
func dialControl(opts Options, allowedCIDRs []netip.Prefix) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: unparseable dial address %q", ErrBlocked, address)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("%w: dial resolved to invalid IP %q", ErrBlocked, host)
		}
		if !opts.AllowPrivateRanges && isBlockedIP(addr, allowedCIDRs) {
			return fmt.Errorf("%w: dial resolved to disallowed IP %s", ErrBlocked, host)
		}
		return nil
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
	host := normalizeHost(req.URL.Hostname())
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
	ips, err := lookupIPAddr(req.Context(), host)
	if err != nil {
		return fmt.Errorf("%w: DNS lookup failed for %q: %v", ErrBlocked, host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: no IPs resolved for %q", ErrBlocked, host)
	}
	if opts.AllowPrivateRanges {
		return nil
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			return fmt.Errorf("%w: invalid resolved IP for %q", ErrBlocked, host)
		}
		if isBlockedIP(addr, allowedCIDRs) {
			return fmt.Errorf("%w: %q resolved to disallowed IP %s", ErrBlocked, host, addr.Unmap())
		}
	}
	return nil
}

// WithContext is a tiny helper for callers who want a per-call deadline on
// top of the client's Timeout.
func WithContext(ctx context.Context, req *http.Request) *http.Request {
	return req.WithContext(ctx)
}

// normalizeHost lowercases and strips the DNS root dot, so
// "Metadata.Google.Internal." can't dodge a hostname comparison.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func hostExplicitlyAllowed(host string, allowed map[string]bool) bool {
	if len(allowed) == 0 {
		return false
	}
	return allowed[host]
}

func isMetadataHostname(host string) bool {
	switch host {
	case "metadata.google.internal", "metadata.goog", "metadata", "instance-data":
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
// outbound HTTP from server-side code.
var blockedRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, includes AWS/GCP/Azure metadata 169.254.169.254
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT, includes Alibaba metadata 100.100.100.200
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network" — 0.0.0.0 dials localhost on Linux
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments, includes Oracle Cloud metadata 192.0.0.192
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking, routed internally by some providers
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, includes 255.255.255.255 broadcast
	netip.MustParsePrefix("::/128"),         // unspecified — like 0.0.0.0, dials localhost
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),       // ULA, includes AWS IPv6 metadata fd00:ec2::254
	netip.MustParsePrefix("ff00::/8"),       // multicast
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64 (RFC 8215) — operator-defined embedding
	netip.MustParsePrefix("2001::/32"),      // Teredo — tunnels to an embedded IPv4 endpoint
}

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
)

// embeddedIPv4 returns the IPv4 target a NAT64 (64:ff9b::/96) or 6to4
// (2002::/16) address routes to. Neither prefix is denied outright — on an
// IPv6-only host behind DNS64 every IPv4-only site resolves into
// 64:ff9b::/96 — so the embedded address is checked against the IPv4
// denylist instead: 64:ff9b::a9fe:a9fe is 169.254.169.254.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	b := addr.As16()
	switch {
	case nat64WellKnown.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

func isBlockedIP(addr netip.Addr, allowedCIDRs []netip.Prefix) bool {
	// Prefix.Contains never matches an address that carries an IPv6 zone,
	// and an IPv4-mapped address never matches an IPv4 prefix — so without
	// this "[fe80::1%25eth0]" and "[::ffff:127.0.0.1]" pass every range.
	addr = addr.WithZone("").Unmap()
	if !addr.IsValid() {
		return true
	}
	for _, allowed := range allowedCIDRs {
		if allowed.Contains(addr) {
			return false
		}
	}
	if v4, ok := embeddedIPv4(addr); ok {
		return isBlockedIP(v4, allowedCIDRs)
	}
	for _, blocked := range blockedRanges {
		if blocked.Contains(addr) {
			return true
		}
	}
	return false
}
