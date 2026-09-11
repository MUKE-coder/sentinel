package middleware

import (
	"log"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ThreatIDKey is the gin context key under which the WAF records the ID of a
// threat it logged for the current request, so the user-activity record for
// that request can link to it. Only log mode sets it — a blocked request
// never reaches the handler that authenticates the user.
const ThreatIDKey = "sentinel.threat_id"

var extractorPanicOnce sync.Once

// UserActivityMiddleware records one UserActivity for every request made by
// an authenticated user — the data behind the Users page, the GDPR report's
// per-user access section, and anomaly detection, none of which see anything
// without it.
//
// The extractor runs after the rest of the chain, so it can read whatever
// the host application's auth middleware put on the context. Requests for
// which it returns nil (or an empty ID) are not recorded, and neither are
// requests to Sentinel's own routes under skipPrefix. Path is the matched
// route pattern ("/api/users/:id") rather than the raw URL, which keeps
// record IDs out of the activity log and gives anomaly baselines stable keys.
func UserActivityMiddleware(extractor func(*gin.Context) *sentinel.UserContext, pipe *pipeline.Pipeline, skipPrefix string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if extractor == nil || pipe == nil || underPrefix(c.Request.URL.Path, skipPrefix) {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()
		duration := time.Since(start)

		user := extractUser(extractor, c)
		if user == nil || user.ID == "" {
			return
		}
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		pipe.EmitUserActivity(&sentinel.UserActivity{
			ID:         uuid.New().String(),
			Timestamp:  start,
			UserID:     user.ID,
			UserEmail:  user.Email,
			Action:     "request",
			Path:       path,
			Method:     c.Request.Method,
			IP:         extractClientIP(c),
			UserAgent:  c.Request.UserAgent(),
			StatusCode: c.Writer.Status(),
			Duration:   duration.Milliseconds(),
			ThreatID:   c.GetString(ThreatIDKey),
		})
	}
}

// extractUser calls the host-supplied extractor and contains a panic. The
// response has already been written by then, so a bug in the extractor
// should cost one activity record, not crash the request path.
func extractUser(extractor func(*gin.Context) *sentinel.UserContext, c *gin.Context) (user *sentinel.UserContext) {
	defer func() {
		if r := recover(); r != nil {
			extractorPanicOnce.Do(func() {
				log.Printf("[sentinel] UserExtractor panicked — activity not recorded (logged once): %v", r)
			})
			user = nil
		}
	}()
	return extractor(c)
}

func underPrefix(path, prefix string) bool {
	return prefix != "" && (path == prefix || strings.HasPrefix(path, prefix+"/"))
}
