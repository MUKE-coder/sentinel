package middleware

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// rateLimitEntry tracks request count within a sliding window.
type rateLimitEntry struct {
	count     int
	windowEnd time.Time
}

// RateLimiter holds in-memory rate limit state.
type RateLimiter struct {
	mu       sync.RWMutex
	counters map[string]*rateLimitEntry
	stopCh   chan struct{}
}

// NewRateLimiter creates a new rate limiter with automatic cleanup.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		counters: make(map[string]*rateLimitEntry),
		stopCh:   make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

func (rl *RateLimiter) check(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.counters[key]

	if !exists || now.After(entry.windowEnd) {
		rl.counters[key] = &rateLimitEntry{
			count:     1,
			windowEnd: now.Add(window),
		}
		return true
	}

	entry.count++
	return entry.count <= limit
}

func (rl *RateLimiter) remaining(key string, limit int) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	entry, exists := rl.counters[key]
	if !exists {
		return limit
	}
	if time.Now().After(entry.windowEnd) {
		return limit
	}
	rem := limit - entry.count
	if rem < 0 {
		return 0
	}
	return rem
}

// RateLimitState represents the current state of a rate limit entry.
type RateLimitState struct {
	Key       string    `json:"key"`
	Count     int       `json:"count"`
	Limit     int       `json:"limit,omitempty"`
	WindowEnd time.Time `json:"window_end"`
	Remaining int       `json:"remaining,omitempty"`
}

// GetCurrentStates returns all active rate limit counters.
func (rl *RateLimiter) GetCurrentStates() []RateLimitState {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()
	var states []RateLimitState
	for key, entry := range rl.counters {
		if now.Before(entry.windowEnd) {
			states = append(states, RateLimitState{
				Key:       key,
				Count:     entry.count,
				WindowEnd: entry.windowEnd,
			})
		}
	}
	return states
}

// ResetKey removes a specific rate limit counter.
func (rl *RateLimiter) ResetKey(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	_, exists := rl.counters[key]
	delete(rl.counters, key)
	return exists
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, entry := range rl.counters {
				if now.After(entry.windowEnd) {
					delete(rl.counters, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// routeLimit pairs a ByRoute pattern with its compiled matcher so wildcard
// keys ("/v1/*", "/api/apps/*/products") actually match. Before v2.1.0 ByRoute
// was exact-lookup only, so a pattern-shaped key silently rate-limited nothing
// (issue #8). All paths matching one pattern share that pattern's counter —
// otherwise an attacker could reset their budget by rotating sub-paths.
type routeLimit struct {
	pattern string
	matcher *RouteMatcher
	limit   sentinel.Limit
}

// compileRouteLimits splits ByRoute into an exact-lookup map and ordered
// pattern matchers (longest pattern first, so more specific wins).
func compileRouteLimits(byRoute map[string]sentinel.Limit) (map[string]sentinel.Limit, []routeLimit) {
	exact := make(map[string]sentinel.Limit)
	var patterns []routeLimit
	for k, v := range byRoute {
		if strings.ContainsAny(k, "*?[") {
			patterns = append(patterns, routeLimit{pattern: k, matcher: NewRouteMatcher([]string{k}), limit: v})
		} else {
			exact[k] = v
		}
	}
	sort.Slice(patterns, func(i, j int) bool {
		if len(patterns[i].pattern) != len(patterns[j].pattern) {
			return len(patterns[i].pattern) > len(patterns[j].pattern)
		}
		return patterns[i].pattern < patterns[j].pattern
	})
	return exact, patterns
}

// RateLimitMiddleware creates a Gin middleware for multi-dimensional rate limiting.
func RateLimitMiddleware(config sentinel.RateLimitConfig, limiter *RateLimiter, pipe *pipeline.Pipeline) gin.HandlerFunc {
	// Wildcard entries in ExcludeRoutes are compiled to real matchers; plain
	// entries keep their long-standing prefix-match behavior so existing
	// configs ("/static" excluding "/static/app.js") are not broken.
	var excludeWildcards []string
	var excludePlain []string
	for _, e := range config.ExcludeRoutes {
		if strings.ContainsAny(e, "*?[") {
			excludeWildcards = append(excludeWildcards, e)
		} else {
			excludePlain = append(excludePlain, e)
		}
	}
	excludeMatcher := NewRouteMatcher(excludeWildcards)
	exactLimits, patternLimits := compileRouteLimits(config.ByRoute)

	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		clientIP := extractClientIP(c)
		path := c.Request.URL.Path

		// Skip excluded routes
		for _, excluded := range excludePlain {
			if strings.HasPrefix(path, excluded) {
				c.Next()
				return
			}
		}
		if !excludeMatcher.Empty() && excludeMatcher.Matches(path) {
			c.Next()
			return
		}

		// Per-route limits (highest priority): exact key first, then the most
		// specific matching wildcard pattern.
		if limit, key, ok := resolveRouteLimit(exactLimits, patternLimits, path); ok {
			counterKey := "route:" + key + ":" + clientIP
			if !limiter.check(counterKey, limit.Requests, limit.Window) {
				emitRateLimitEvent(pipe, clientIP, path, c, "route")
				retryAfter := int(limit.Window.Seconds())
				c.Header("Retry-After", strconv.Itoa(retryAfter))
				c.Header("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
				c.Header("X-RateLimit-Remaining", "0")
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded",
					"code":  "RATE_LIMITED",
				})
				return
			}
		}

		// IP rate limit
		if config.ByIP != nil {
			key := "ip:" + clientIP
			if !limiter.check(key, config.ByIP.Requests, config.ByIP.Window) {
				emitRateLimitEvent(pipe, clientIP, path, c, "ip")
				retryAfter := int(config.ByIP.Window.Seconds())
				c.Header("Retry-After", strconv.Itoa(retryAfter))
				c.Header("X-RateLimit-Limit", strconv.Itoa(config.ByIP.Requests))
				c.Header("X-RateLimit-Remaining", "0")
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded",
					"code":  "RATE_LIMITED",
				})
				return
			}
			rem := limiter.remaining(key, config.ByIP.Requests)
			c.Header("X-RateLimit-Limit", strconv.Itoa(config.ByIP.Requests))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(rem))
		}

		// User rate limit
		if config.ByUser != nil && config.UserIDExtractor != nil {
			userID := config.UserIDExtractor(c)
			if userID != "" {
				key := "user:" + userID
				if !limiter.check(key, config.ByUser.Requests, config.ByUser.Window) {
					emitRateLimitEvent(pipe, clientIP, path, c, "user")
					retryAfter := int(config.ByUser.Window.Seconds())
					c.Header("Retry-After", strconv.Itoa(retryAfter))
					c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
						"error": "Rate limit exceeded",
						"code":  "RATE_LIMITED",
					})
					return
				}
			}
		}

		// Global rate limit
		if config.Global != nil {
			key := "global"
			if !limiter.check(key, config.Global.Requests, config.Global.Window) {
				emitRateLimitEvent(pipe, clientIP, path, c, "global")
				retryAfter := int(config.Global.Window.Seconds())
				c.Header("Retry-After", strconv.Itoa(retryAfter))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded",
					"code":  "RATE_LIMITED",
				})
				return
			}
		}

		c.Next()
	}
}

// resolveRouteLimit returns the limit and counter-key component for a path:
// the exact ByRoute entry when one exists, else the first (most specific)
// matching wildcard pattern.
func resolveRouteLimit(exact map[string]sentinel.Limit, patterns []routeLimit, path string) (sentinel.Limit, string, bool) {
	if limit, ok := exact[path]; ok {
		return limit, path, true
	}
	for _, rl := range patterns {
		if rl.matcher.Matches(path) {
			return rl.limit, rl.pattern, true
		}
	}
	return sentinel.Limit{}, "", false
}

func emitRateLimitEvent(pipe *pipeline.Pipeline, ip, path string, c *gin.Context, dimension string) {
	if pipe == nil {
		return
	}
	pipe.EmitThreat(&sentinel.ThreatEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		IP:          ip,
		Method:      c.Request.Method,
		Path:        path,
		UserAgent:   c.Request.UserAgent(),
		ThreatTypes: []string{string(sentinel.ThreatRateLimitExceeded)},
		Severity:    sentinel.SeverityMedium,
		Confidence:  100,
		Blocked:     true,
		StatusCode:  http.StatusTooManyRequests,
		Evidence: []sentinel.Evidence{
			{Pattern: "RateLimit_" + dimension, Matched: dimension + " limit exceeded", Location: "rate_limiter"},
		},
	})
}
