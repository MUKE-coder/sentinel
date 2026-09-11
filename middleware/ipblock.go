package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BlockCheckers combines block lists: an IP is blocked if any of them says
// so. Mount combines the IP manager (dashboard blocks and AutoBlock) with
// blocklist feeds.
type BlockCheckers []IPBlockChecker

// IsBlocked reports whether any checker blocks ip.
func (b BlockCheckers) IsBlocked(ip string) bool {
	for _, c := range b {
		if c != nil && c.IsBlocked(ip) {
			return true
		}
	}
	return false
}

// IPBlockMiddleware rejects requests from blocked IPs with 403. The WAF does
// this as its first step; Mount installs this middleware only when the WAF
// is disabled, so IP blocks — from the dashboard, AutoBlock, or feeds — are
// enforced either way. Before v2.4.0 a block with the WAF off did nothing.
func IPBlockMiddleware(checker IPBlockChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if checker != nil && checker.IsBlocked(extractClientIP(c)) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "IP_BLOCKED",
			})
			return
		}
		c.Next()
	}
}
