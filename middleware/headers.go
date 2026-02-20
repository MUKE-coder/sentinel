package middleware

import (
	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/gin-gonic/gin"
)

// HeadersMiddleware creates a Gin middleware that injects security headers
// into every response.
func HeadersMiddleware(config sentinel.HeaderConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.Enabled != nil && !*config.Enabled {
			c.Next()
			return
		}

		// Always set these defaults
		c.Header("X-Content-Type-Options", "nosniff")

		if config.XFrameOptions != "" {
			c.Header("X-Frame-Options", config.XFrameOptions)
		}

		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		if config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		if config.StrictTransportSecurity {
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
		}

		c.Next()
	}
}
