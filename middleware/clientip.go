package middleware

import (
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
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// extractClientIP returns the client IP from the request. Proxy headers
// (X-Forwarded-For, X-Real-IP) are honored only when the direct connection
// originates from a configured trusted proxy. This prevents trivial header
// spoofing of the source IP used for blocks and rate limits.
func extractClientIP(c *gin.Context) string {
	directIP := directConnectionIP(c)

	if isTrustedProxy(directIP) {
		if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			candidate := strings.TrimSpace(parts[0])
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
		if xri := strings.TrimSpace(c.GetHeader("X-Real-IP")); xri != "" {
			if net.ParseIP(xri) != nil {
				return xri
			}
		}
	}

	if directIP != "" {
		return directIP
	}
	return c.ClientIP()
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
