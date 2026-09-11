package middleware

import (
	"context"
	"log"
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

// RateLimiter enforces rate limits against a sentinel.CounterStore. With the
// default in-memory store each process counts on its own: behind N
// instances, each one allows the configured limit. A shared store
// (redisstore) makes the limits hold across replicas.
type RateLimiter struct {
	store    sentinel.CounterStore
	ownStore *MemoryCounterStore // closed by Stop when the limiter created it

	mu       sync.RWMutex
	strategy sentinel.RateLimitStrategy

	routes atomic.Pointer[routeTable]
	now    func() time.Time
	errLog rateLimitedLog
}

// NewRateLimiter creates a sliding-window rate limiter with an in-memory
// counter store.
func NewRateLimiter() *RateLimiter {
	mem := NewMemoryCounterStore()
	rl := NewRateLimiterWithStore(mem)
	rl.ownStore = mem
	return rl
}

// NewRateLimiterWithStore creates a sliding-window rate limiter that keeps its
// counters in store. Give every replica the same shared store and a client
// gets each limit once, not once per replica.
func NewRateLimiterWithStore(store sentinel.CounterStore) *RateLimiter {
	rl := &RateLimiter{
		store:    store,
		strategy: sentinel.SlidingWindow,
		now:      time.Now,
	}
	rl.SetRouteLimits(nil)
	return rl
}

// Stop stops the in-memory store's cleanup goroutine, if this limiter
// created the store.
func (rl *RateLimiter) Stop() {
	if rl.ownStore != nil {
		rl.ownStore.Close()
	}
}

// SetStrategy selects the algorithm. sentinel.SlidingWindow — the default,
// also used for an empty or unknown value — counts requests over the window
// ending now. sentinel.FixedWindow counts per consecutive window and can let
// up to twice the limit through across a window boundary.
// sentinel.TokenBucket allows a burst of up to the limit, then a steady
// limit-per-window rate. Counters are kept per strategy, since the state
// means different things under each, so changing strategy starts every
// client from zero.
//
// Before v2.3.0 RateLimitConfig.Strategy was never read and every limit was
// a fixed window, whatever the config said.
func (rl *RateLimiter) SetStrategy(strategy sentinel.RateLimitStrategy) {
	if strategy != sentinel.FixedWindow && strategy != sentinel.TokenBucket {
		strategy = sentinel.SlidingWindow
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.strategy = strategy
}

// Strategy returns the algorithm in use.
func (rl *RateLimiter) Strategy() sentinel.RateLimitStrategy {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.strategy
}

// counterPrefix namespaces rate-limit counters in the store, per strategy.
func counterPrefix(strategy sentinel.RateLimitStrategy) string {
	return "rl:" + string(strategy) + ":"
}

func (rl *RateLimiter) check(key string, limit int, window time.Duration) bool {
	if window <= 0 {
		// A non-positive window never accumulates anything; ValidateConfig
		// reports it.
		return true
	}
	strategy := rl.Strategy()
	ok, err := rl.store.Take(context.Background(), counterPrefix(strategy)+key, limit, window, strategy, rl.now())
	if err != nil {
		// Fail open: a counter store outage must not take the application
		// down with it.
		rl.errLog.log("rate limit counter store: %v (requests allowed until it recovers)", err)
		return true
	}
	return ok
}

func (rl *RateLimiter) remaining(key string, limit int) int {
	strategy := rl.Strategy()
	u, ok, err := rl.store.Usage(context.Background(), counterPrefix(strategy)+key, strategy, rl.now())
	if err != nil || !ok {
		return limit
	}
	return max(limit-int(math.Ceil(u.Used)), 0)
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
	ctx := context.Background()
	strategy := rl.Strategy()
	prefix := counterPrefix(strategy)
	keys, err := rl.store.Keys(ctx, prefix)
	if err != nil {
		rl.errLog.log("rate limit counter store: %v", err)
		return nil
	}
	now := rl.now()
	var states []RateLimitState
	for _, k := range keys {
		u, ok, err := rl.store.Usage(ctx, k, strategy, now)
		if err != nil || !ok {
			continue
		}
		used := int(math.Ceil(u.Used))
		states = append(states, RateLimitState{
			Key:       strings.TrimPrefix(k, prefix),
			Count:     used,
			Limit:     u.Limit,
			WindowEnd: u.WindowEnd,
			Remaining: max(u.Limit-used, 0),
		})
	}
	return states
}

// ResetKey removes a specific rate limit counter.
func (rl *RateLimiter) ResetKey(key string) bool {
	existed, err := rl.store.Delete(context.Background(), counterPrefix(rl.Strategy())+key)
	if err != nil {
		rl.errLog.log("rate limit counter store: %v", err)
	}
	return existed
}

// rateLimitedLog logs at most once a minute, so a counter store outage
// doesn't write one line per request.
type rateLimitedLog struct {
	mu   sync.Mutex
	last time.Time
}

func (l *rateLimitedLog) log(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.last) < time.Minute {
		return
	}
	l.last = time.Now()
	log.Printf("[sentinel] "+format, args...)
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
