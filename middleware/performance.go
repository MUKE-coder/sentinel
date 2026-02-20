package middleware

import (
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PerformanceMiddleware creates a Gin middleware that tracks request performance.
func PerformanceMiddleware(config sentinel.PerformanceConfig, pipe *pipeline.Pipeline) gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.Enabled != nil && !*config.Enabled {
			c.Next()
			return
		}

		start := time.Now()

		// Wrap response writer to capture status and size
		rw := &responseWriter{ResponseWriter: c.Writer, statusCode: 200}
		c.Writer = rw

		c.Next()

		duration := time.Since(start)
		statusCode := rw.statusCode

		if pipe != nil {
			pipe.EmitPerformance(&sentinel.PerformanceMetric{
				ID:           uuid.New().String(),
				Timestamp:    start,
				Route:        c.FullPath(),
				Method:       c.Request.Method,
				StatusCode:   statusCode,
				Duration:     duration.Milliseconds(),
				ResponseSize: int64(rw.responseSize),
				IP:           extractClientIP(c),
			})
		}
	}
}
