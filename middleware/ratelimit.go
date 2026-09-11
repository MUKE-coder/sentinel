package middleware

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// rateLimitEntry is one counter's state. Which fields are live depends on
// the limiter's strategy.
type rateLimitEntry struct {
	limit      int
	window     time.Duration
	count      int       // fixed, sliding: requests counted in the current window
	prevCount  int       // sliding: requests counted in the previous window
	windowEnd  time.Time // fixed, sliding: end of the current window
	tokens     float64   // token bucket: tokens available as of lastRefill
	lastRefill time.Time // token bucket
	expires    time.Time // after this the entry affects no decision and can be dropped
}

// RateLimiter holds rate limit state for one process. Counters live in
// memory and are not shared between replicas: behind N instances, each one
// allows the configured limit on its own.
type RateLimiter struct {
	mu       sync.RWMutex
	counters map[string]*rateLimitEntry
	strategy sentinel.RateLimitStrategy
	routes   atomic.Pointer[routeTable]
	now      func() time.Time
	stopCh   chan struct{}
}

// NewRateLimiter creates a sliding-window rate limiter with automatic cleanup.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		counters: make(map[string]*rateLimitEntry),
		strategy: sentinel.SlidingWindow,
		now:      time.Now,
		stopCh:   make(chan struct{}),
	}
	rl.SetRouteLimits(nil)
	go rl.cleanup()
	return rl
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// SetStrategy selects the algorithm. sentinel.SlidingWindow — the default,
// also used for an empty or unknown value — counts requests over the window
// ending now. sentinel.FixedWindow counts per consecutive window and can let
// up to twice the limit through across a window boundary.
// sentinel.TokenBucket allows a burst of up to the limit, then a steady
// limit-per-window rate. Changing strategy resets every counter, since the
// state means different things under each.
//
// Before v2.3.0 RateLimitConfig.Strategy was never read and every limit was
// a fixed window, whatever the config said.
func (rl *RateLimiter) SetStrategy(strategy sentinel.RateLimitStrategy) {
	if strategy != sentinel.FixedWindow && strategy != sentinel.TokenBucket {
		strategy = sentinel.SlidingWindow
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if strategy != rl.strategy {
		rl.counters = make(map[string]*rateLimitEntry)
	}
	rl.strategy = strategy
}

// Strategy returns the algorithm in use.
func (rl *RateLimiter) Strategy() sentinel.RateLimitStrategy {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.strategy
}

func (rl *RateLimiter) check(key string, limit int, window time.Duration) bool {
	if window <= 0 {
		// A non-positive window never accumulates anything; ValidateConfig
		// reports it.
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e := rl.counters[key]
	if e == nil {
		e = &rateLimitEntry{}
		rl.counters[key] = e
	}
	e.limit, e.window = limit, window
	now := rl.now()
	switch rl.strategy {
	case sentinel.FixedWindow:
		return e.takeFixed(now)
	case sentinel.TokenBucket:
		return e.takeToken(now)
	default:
		return e.takeSliding(now)
	}
}

// takeFixed counts the request against the current fixed window, which
// starts at the first request after the previous one ended.
func (e *rateLimitEntry) takeFixed(now time.Time) bool {
	if !now.Before(e.windowEnd) {
		e.count = 0
		e.windowEnd = now.Add(e.window)
	}
	e.count++
	e.expires = e.windowEnd
	return e.count <= e.limit
}

// takeSliding approximates a true sliding window from two fixed windows: the
// previous window's count, weighted by how much of it still overlaps the
// window ending now, plus the current window's count. Rejected requests are
// not counted.
func (e *rateLimitEntry) takeSliding(now time.Time) bool {
	e.roll(now)
	if e.slidingUsage(now) >= float64(e.limit) {
		return false
	}
	e.count++
	e.expires = e.windowEnd.Add(e.window)
	return true
}

// roll advances the sliding window to the one containing now.
func (e *rateLimitEntry) roll(now time.Time) {
	if e.windowEnd.IsZero() {
		e.windowEnd = now.Add(e.window)
		return
	}
	if now.Before(e.windowEnd) {
		return
	}
	passed := now.Sub(e.windowEnd)/e.window + 1
	if passed == 1 {
		e.prevCount = e.count
	} else {
		e.prevCount = 0
	}
	e.count = 0
	e.windowEnd = e.windowEnd.Add(passed * e.window)
}

func (e *rateLimitEntry) slidingUsage(now time.Time) float64 {
	overlap := float64(e.windowEnd.Sub(now)) / float64(e.window)
	return float64(e.prevCount)*math.Max(0, math.Min(1, overlap)) + float64(e.count)
}

// takeToken spends a token from a bucket that holds up to limit tokens and
// refills at limit tokens per window.
func (e *rateLimitEntry) takeToken(now time.Time) bool {
	e.refill(now)
	allowed := e.tokens >= 1
	if allowed {
		e.tokens--
	}
	e.expires = now.Add(e.untilFull())
	return allowed
}

func (e *rateLimitEntry) refill(now time.Time) {
	if e.lastRefill.IsZero() {
		e.tokens = float64(e.limit)
	} else {
		perNano := float64(e.limit) / float64(e.window)
		e.tokens = math.Min(float64(e.limit), e.tokens+float64(now.Sub(e.lastRefill))*perNano)
	}
	e.lastRefill = now
}

// untilFull is how long the bucket takes to refill completely.
func (e *rateLimitEntry) untilFull() time.Duration {
	if e.limit <= 0 {
		return 0
	}
	return time.Duration((float64(e.limit) - e.tokens) / float64(e.limit) * float64(e.window))
}

// usage reports how much of its limit an entry has consumed as of now. It
// works on a copy, so readers holding only the read lock never mutate state.
func (rl *RateLimiter) usage(e *rateLimitEntry, now time.Time) float64 {
	c := *e
	if c.window <= 0 {
		return 0
	}
	switch rl.strategy {
	case sentinel.FixedWindow:
		if !now.Before(c.windowEnd) {
			return 0
		}
		return float64(c.count)
	case sentinel.TokenBucket:
		c.refill(now)
		return float64(c.limit) - c.tokens
	default:
		c.roll(now)
		return c.slidingUsage(now)
	}
}

func (rl *RateLimiter) remaining(key string, limit int) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	e, exists := rl.counters[key]
	if !exists {
		return limit
	}
	rem := limit - int(math.Ceil(rl.usage(e, rl.now())))
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

// GetCurrentStates returns all active rate limit counters. Count is how
// much of the limit is used as of now; WindowEnd is when the current window
// ends (fixed, sliding) or when the bucket is full again (token bucket).
func (rl *RateLimiter) GetCurrentStates() []RateLimitState {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := rl.now()
	var states []RateLimitState
	for key, e := range rl.counters {
		if !now.Before(e.expires) {
			continue
		}
		used := int(math.Ceil(rl.usage(e, now)))
		windowEnd := e.windowEnd
		switch rl.strategy {
		case sentinel.TokenBucket:
			windowEnd = e.expires
		case sentinel.SlidingWindow:
			c := *e
			c.roll(now)
			windowEnd = c.windowEnd
		}
		states = append(states, RateLimitState{
			Key:       key,
			Count:     used,
			Limit:     e.limit,
			WindowEnd: windowEnd,
			Remaining: max(e.limit-used, 0),
		})
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
			now := rl.now()
			for key, entry := range rl.counters {
				if !now.Before(entry.expires) {
					delete(rl.counters, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// routeTable is an immutable snapshot of the per-route limits, swapped
// atomically so the dashboard can change limits while requests run.
type routeTable struct {
	byRoute  map[string]sentinel.Limit // as configured, for display
	exact    map[string]sentinel.Limit
	patterns []routeLimit
}

// SetRouteLimits replaces the per-route limits for every subsequent request.
// Keys take the RateLimitConfig.ByRoute shapes; a key the matcher can't
// compile is logged and ignored — check it with ValidateRoutePattern first
// to reject it instead. Before v2.3.0 route limits were fixed at mount and
// dashboard edits never reached the middleware.
func (rl *RateLimiter) SetRouteLimits(byRoute map[string]sentinel.Limit) {
	copied := make(map[string]sentinel.Limit, len(byRoute))
	for k, v := range byRoute {
		copied[k] = v
	}
	exact, patterns := compileRouteLimits(copied)
	rl.routes.Store(&routeTable{byRoute: copied, exact: exact, patterns: patterns})
}

// RouteLimits returns a copy of the per-route limits currently enforced.
func (rl *RateLimiter) RouteLimits() map[string]sentinel.Limit {
	table := rl.routes.Load()
	out := make(map[string]sentinel.Limit, len(table.byRoute))
	for k, v := range table.byRoute {
		out[k] = v
	}
	return out
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

// RateLimitMiddleware creates a Gin middleware for multi-dimensional rate
// limiting. It applies config.Strategy and config.ByRoute to limiter; the
// route limits can be replaced later with limiter.SetRouteLimits.
func RateLimitMiddleware(config sentinel.RateLimitConfig, limiter *RateLimiter, pipe *pipeline.Pipeline) gin.HandlerFunc {
	limiter.SetStrategy(config.Strategy)
	limiter.SetRouteLimits(config.ByRoute)

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
		routes := limiter.routes.Load()
		if limit, key, ok := resolveRouteLimit(routes.exact, routes.patterns, path); ok {
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
