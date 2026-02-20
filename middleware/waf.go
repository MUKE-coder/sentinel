package middleware

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/detection"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/MUKE-coder/sentinel/storage"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const maxBodyRead = 10 * 1024 // 10KB

// WAFMiddleware creates a Gin middleware that inspects requests for threats
// and handles them according to the configured WAF mode.
// An optional CustomRuleEngine can be passed to also check custom rules.
func WAFMiddleware(config sentinel.WAFConfig, store storage.Store, pipe *pipeline.Pipeline, customEngine ...*detection.CustomRuleEngine) gin.HandlerFunc {
	var customRuleEngine *detection.CustomRuleEngine
	if len(customEngine) > 0 {
		customRuleEngine = customEngine[0]
	}
	excludeRouteSet := make(map[string]bool)
	for _, r := range config.ExcludeRoutes {
		excludeRouteSet[r] = true
	}
	excludeIPSet := make(map[string]bool)
	for _, ip := range config.ExcludeIPs {
		excludeIPSet[ip] = true
	}

	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		path := c.Request.URL.Path

		// Check if route is excluded
		if excludeRouteSet[path] {
			c.Next()
			return
		}

		clientIP := extractClientIP(c)

		// Check if IP is excluded
		if excludeIPSet[clientIP] {
			c.Next()
			return
		}

		// Check if IP is blocked
		if store != nil {
			blocked, _ := store.IsIPBlocked(c.Request.Context(), clientIP)
			if blocked {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Access denied",
					"code":  "IP_BLOCKED",
				})
				return
			}
		}

		// Read and restore request body
		var bodyStr string
		if c.Request.Body != nil && c.Request.ContentLength > 0 {
			bodyBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyRead))
			if err == nil {
				bodyStr = string(bodyBytes)
				// Restore body for downstream handlers
				remaining, _ := io.ReadAll(c.Request.Body)
				c.Request.Body = io.NopCloser(bytes.NewReader(append(bodyBytes, remaining...)))
			}
		}

		// Build inspected request
		inspected := sentinel.InspectedRequest{
			Method:    c.Request.Method,
			Path:      path,
			RawQuery:  c.Request.URL.RawQuery,
			Headers:   c.Request.Header,
			Body:      bodyStr,
			IP:        clientIP,
			UserAgent: c.Request.UserAgent(),
		}

		// Classify and score
		matches := detection.ClassifyRequest(inspected)

		// Also check custom rules if engine is available
		if customRuleEngine != nil {
			matches = append(matches, customRuleEngine.ClassifyRequest(inspected)...)
		}

		if len(matches) == 0 {
			c.Next()
			return
		}

		severity, confidence := detection.ScoreThreats(matches)
		threatTypes := detection.MatchesToThreatTypes(matches)
		evidence := detection.MatchesToEvidence(matches)

		// Build body snippet (first 500 chars only — never log full body)
		bodySnippet := bodyStr
		if len(bodySnippet) > 500 {
			bodySnippet = bodySnippet[:500]
		}

		// Build query params string for logging
		queryParams := c.Request.URL.RawQuery
		if len(queryParams) > 500 {
			queryParams = queryParams[:500]
		}

		threatEvent := &sentinel.ThreatEvent{
			ID:          uuid.New().String(),
			Timestamp:   time.Now(),
			IP:          clientIP,
			ActorID:     "actor_" + strings.ReplaceAll(clientIP, ".", "_"),
			Method:      c.Request.Method,
			Path:        path,
			UserAgent:   c.Request.UserAgent(),
			Referer:     c.Request.Referer(),
			QueryParams: queryParams,
			BodySnippet: bodySnippet,
			ThreatTypes: threatTypes,
			Severity:    severity,
			Confidence:  confidence,
			Evidence:    evidence,
		}

		switch config.Mode {
		case sentinel.ModeBlock:
			threatEvent.Blocked = true
			threatEvent.StatusCode = http.StatusForbidden

			// Emit event async
			if pipe != nil {
				pipe.EmitThreat(threatEvent)
			}

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Request blocked by WAF",
				"code":  "WAF_BLOCKED",
			})
			return

		case sentinel.ModeChallenge:
			threatEvent.Blocked = true
			threatEvent.StatusCode = http.StatusTooManyRequests

			if pipe != nil {
				pipe.EmitThreat(threatEvent)
			}

			c.Header("Retry-After", "30")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Request challenged by WAF",
				"code":  "WAF_CHALLENGE",
			})
			return

		default: // ModeLog
			threatEvent.Blocked = false

			if pipe != nil {
				pipe.EmitThreat(threatEvent)
			}

			c.Next()

			// Update status code after handler runs
			threatEvent.StatusCode = c.Writer.Status()
		}
	}
}

// responseWriter wraps gin.ResponseWriter to capture status code and response size.
type responseWriter struct {
	gin.ResponseWriter
	statusCode   int
	responseSize int
}

// WriteHeader captures the status code.
func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// Write captures the response size.
func (w *responseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.responseSize += n
	return n, err
}

// extractClientIP returns the client IP from the request, handling proxied requests.
func extractClientIP(c *gin.Context) string {
	// Try X-Forwarded-For first
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Try X-Real-IP
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	ip := c.ClientIP()
	if ip == "" {
		ip = c.Request.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
	}

	return ip
}
