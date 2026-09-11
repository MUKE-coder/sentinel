package middleware

import (
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	trustedProxiesMu sync.RWMutex
	trustedProxies   []netip.Prefix
)

// ConfigureTrustedProxies sets the package-wide list of trusted reverse-proxy
// addresses or CIDR ranges whose X-Forwarded-For / X-Real-IP headers will be
// honored when extracting the client IP. If empty, those headers are ignored
// entirely and only the direct connection IP is used — the safe default that
// closes the IP-spoofing bypass for IP blocks and rate limits.
//
// Accepts individual IPs ("10.0.0.5"), CIDR ranges ("10.0.0.0/8"), or a
// mixed list. Invalid entries are silently dropped.
func ConfigureTrustedProxies(list []string) {
	prefixes := make([]netip.Prefix, 0, len(list))
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		if addr, err := netip.ParseAddr(raw); err == nil {
			bits := addr.BitLen()
			if p, err := addr.Prefix(bits); err == nil {
				prefixes = append(prefixes, p)
			}
		}
	}
	trustedProxiesMu.Lock()
	trustedProxies = prefixes
	trustedProxiesMu.Unlock()
}

func isTrustedProxy(ip string) bool {
	trustedProxiesMu.RLock()
	defer trustedProxiesMu.RUnlock()
	if len(trustedProxies) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	// A dual-stack listener can report an IPv4 peer as ::ffff:a.b.c.d, and
	// Prefix.Contains never matches a mapped address against an IPv4 prefix.
	addr = addr.WithZone("").Unmap()
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// proxyHeaderWarnOnce guards the one-time warning emitted when proxy headers
// arrive but no trusted proxies are configured — the deployment is almost
// certainly behind a reverse proxy, and every per-IP feature (blocks, rate
// limits, threat attribution) is keying on the proxy's address, not the
// client's (issue #8).
var proxyHeaderWarnOnce sync.Once

// ClientIP returns the request's client IP under the same trusted-proxy rules
// every Sentinel middleware uses. Prefer it to gin's c.ClientIP(), which —
// unless the engine's SetTrustedProxies has been configured — believes
// X-Forwarded-For from any peer, so any client can pick its own address.
func ClientIP(c *gin.Context) string {
	return extractClientIP(c)
}

// extractClientIP returns the client IP from the request. Proxy headers
// (X-Forwarded-For, X-Real-IP) are honored only when the direct connection
// originates from a configured trusted proxy. This prevents trivial header
// spoofing of the source IP used for blocks and rate limits.
func extractClientIP(c *gin.Context) string {
	directIP := directConnectionIP(c)

	trustedProxiesMu.RLock()
	noTrustedProxies := len(trustedProxies) == 0
	trustedProxiesMu.RUnlock()
	if noTrustedProxies && (c.GetHeader("X-Forwarded-For") != "" || c.GetHeader("X-Real-IP") != "") {
		proxyHeaderWarnOnce.Do(func() {
			log.Printf("[sentinel] WARNING: request carries X-Forwarded-For/X-Real-IP but WAF.TrustedProxies is empty — recording the direct connection IP (%s), which is likely your reverse proxy. Per-IP rate limits, IP blocks, and threat attribution will all key on that single address. Set WAF.TrustedProxies to your proxy's IP/CIDR.", directIP)
		})
	}

	if isTrustedProxy(directIP) {
		if xff := c.Request.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			if ip := clientFromForwardedFor(xff); ip != "" {
				return ip
			}
			// The header is present but yields no address — garbage the
			// proxy passed through. Fall back to the proxy itself rather
			// than X-Real-IP, which the client may also have set.
			return directIP
		}
		if ip := parseForwardedHop(c.GetHeader("X-Real-IP")); ip != "" {
			return ip
		}
	}

	if directIP != "" {
		return directIP
	}
	return c.ClientIP()
}

// clientFromForwardedFor picks the client address out of X-Forwarded-For.
// Each proxy appends the address of the peer it received the request from,
// so only the right-hand end of the chain is trustworthy: everything left of
// the first hop we don't trust was written by the client and can say
// anything. Walk right to left, skip our own trusted proxies, and return the
// first address that isn't one. If every entry is a trusted proxy, the
// furthest one is the best answer available.
//
// values holds every X-Forwarded-For header line in order — a proxy may add
// its own line rather than extend the client's, and reading only the first
// line would hand the choice back to the client.
func clientFromForwardedFor(values []string) string {
	var hops []string
	for _, v := range values {
		hops = append(hops, strings.Split(v, ",")...)
	}
	furthestTrusted := ""
	for i := len(hops) - 1; i >= 0; i-- {
		ip := parseForwardedHop(hops[i])
		if ip == "" {
			// A proxy always writes a real peer address, so an unparseable
			// entry came from the client side: nothing at or left of it can
			// be believed.
			break
		}
		if !isTrustedProxy(ip) {
			return ip
		}
		furthestTrusted = ip
	}
	return furthestTrusted
}

// parseForwardedHop normalises one forwarded-for entry to a bare IP, or ""
// if it isn't one. Some proxies (Azure Application Gateway, IIS ARR) append
// "ip:port", so that form is accepted too.
func parseForwardedHop(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.WithZone("").Unmap().String()
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().WithZone("").Unmap().String()
	}
	return ""
}

func directConnectionIP(c *gin.Context) string {
	raw := c.Request.RemoteAddr
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}
