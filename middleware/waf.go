package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/detection"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// defaultMaxBodyBytes is the default inspection cap when WAFConfig.MaxBodyBytes
// is unset. 64 KB is large enough to cover virtually all JSON API payloads
// while bounding inspection cost.
const defaultMaxBodyBytes int64 = 64 * 1024

// ActorIDFromIP returns a stable, IPv6-safe actor identifier derived from
// a SHA-256 hash of the IP. Exported so tests and downstream code can build
// the same ID without re-implementing the scheme.
func ActorIDFromIP(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return "actor_" + hex.EncodeToString(sum[:8])
}

// IPBlockChecker answers "is this IP blocked?" from an in-memory cache.
// *intelligence.IPManager satisfies it: it syncs from storage every 30s and
// is updated immediately on block/unblock, so lookups never hit the database
// on the request hot path.
type IPBlockChecker interface {
	IsBlocked(ip string) bool
}

// WAFMiddleware creates a Gin middleware that inspects requests for threats
// and handles them according to the configured WAF mode. customEngine may be
// nil; pass a configured *detection.CustomRuleEngine to also evaluate custom
// rules alongside the built-in pattern set.
//
// Pass an IPBlockChecker (e.g. intelligence.IPManager) to answer blocklist
// lookups from memory. Without one, every request costs a storage round trip
// ahead of the handler — one DB query per request on the hot path (issue #8).
// Mount always supplies the checker; the store fallback exists for callers
// wiring the middleware directly.
func WAFMiddleware(config sentinel.WAFConfig, store storage.Store, pipe *pipeline.Pipeline, customEngine *detection.CustomRuleEngine, blockChecker ...IPBlockChecker) gin.HandlerFunc {
	return NewWAF(config, store, pipe, customEngine, blockChecker...).Handler()
}

// WAF is the WAF middleware together with the settings that can change
// while it runs. The dashboard switches the mode and per-category
// sensitivity through SetMode and SetRules; before v2.3.0 those edits only
// changed the API server's copy of the config and never reached requests.
type WAF struct {
	mode    atomic.Value // sentinel.WAFMode
	rules   atomic.Pointer[sentinel.RuleSet]
	handler gin.HandlerFunc
}

// NewWAF builds the WAF middleware; see WAFMiddleware for the parameters.
// Use it instead of WAFMiddleware when the mode or rules need to change at
// runtime.
func NewWAF(config sentinel.WAFConfig, store storage.Store, pipe *pipeline.Pipeline, customEngine *detection.CustomRuleEngine, blockChecker ...IPBlockChecker) *WAF {
	w := &WAF{}
	w.mode.Store(config.Mode)
	rules := config.Rules
	w.rules.Store(&rules)
	w.handler = w.build(config, store, pipe, customEngine, blockChecker)
	return w
}

// Handler returns the gin middleware.
func (w *WAF) Handler() gin.HandlerFunc { return w.handler }

// Mode returns the mode applied to requests right now.
func (w *WAF) Mode() sentinel.WAFMode { return w.mode.Load().(sentinel.WAFMode) }

// SetMode changes the mode for every subsequent request.
func (w *WAF) SetMode(mode sentinel.WAFMode) error {
	if !ValidWAFMode(mode) {
		return fmt.Errorf("unknown WAF mode %q (use log, block, or challenge)", mode)
	}
	w.mode.Store(mode)
	return nil
}

// Rules returns the per-category sensitivity applied to requests right now.
func (w *WAF) Rules() sentinel.RuleSet { return *w.rules.Load() }

// SetRules changes the per-category sensitivity for every subsequent request.
func (w *WAF) SetRules(rules sentinel.RuleSet) error {
	if err := ValidateRuleSet(rules); err != nil {
		return err
	}
	w.rules.Store(&rules)
	return nil
}

func (w *WAF) build(config sentinel.WAFConfig, store storage.Store, pipe *pipeline.Pipeline, customEngine *detection.CustomRuleEngine, blockChecker []IPBlockChecker) gin.HandlerFunc {
	customRuleEngine := customEngine
	excludeRoutes := NewRouteMatcher(config.ExcludeRoutes)
	var checker IPBlockChecker
	if len(blockChecker) > 0 {
		checker = blockChecker[0]
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

		// Check if route is excluded (exact, "/prefix/*", or glob — see RouteMatcher)
		if excludeRoutes.Matches(path) {
			c.Next()
			return
		}

		clientIP := extractClientIP(c)

		// Check if IP is excluded
		if excludeIPSet[clientIP] {
			c.Next()
			return
		}

		// Check if IP is blocked — from cache when a checker is wired,
		// otherwise falling back to a storage lookup.
		blocked := false
		if checker != nil {
			blocked = checker.IsBlocked(clientIP)
		} else if store != nil {
			var err error
			blocked, err = store.IsIPBlocked(c.Request.Context(), clientIP)
			if err != nil {
				// Fail open, but never silently: a storage outage otherwise
				// degrades to "nothing is blocked" with no operator signal.
				logBlockLookupError(err)
			}
		}
		if blocked {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "IP_BLOCKED",
			})
			return
		}

		// Determine inspection cap
		maxBody := config.MaxBodyBytes
		if maxBody <= 0 {
			maxBody = defaultMaxBodyBytes
		}

		// Reject oversized bodies entirely if configured. This closes the
		// bypass where attackers hide payloads past the inspection cap.
		if config.RejectOversizedBody && c.Request.ContentLength > maxBody {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request body exceeds inspection limit",
				"code":  "WAF_BODY_TOO_LARGE",
			})
			return
		}

		// Read and restore request body up to the inspection cap.
		var bodyStr string
		if c.Request.Body != nil && c.Request.ContentLength != 0 {
			bodyBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody))
			if err == nil {
				bodyStr = string(bodyBytes)
				// Restore body for downstream handlers, preserving any bytes
				// past the inspection cap so legitimate large uploads still work.
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

		// Classify and score. Built-in matches are filtered by the current
		// per-category sensitivity (WAF.Rules), which the dashboard can change.
		matches := detection.ApplySensitivity(detection.ClassifyRequest(inspected), w.Rules())

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

		cvss := sentinel.DefaultCVSSForTypes(threatTypes)
		threatEvent := &sentinel.ThreatEvent{
			ID:          uuid.New().String(),
			Timestamp:   time.Now(),
			IP:          clientIP,
			ActorID:     ActorIDFromIP(clientIP),
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
			CVSS:        cvss.Score,
			CVSSVector:  cvss.Vector,
		}

		// A request that only trips custom rules with Action "log" is recorded
		// but never enforced — that is how a new rule is watched against real
		// traffic before it is trusted to block.
		mode := w.Mode()
		if !detection.AnyEnforced(matches) {
			mode = sentinel.ModeLog
		}
		switch mode {
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

			// Run handlers first, capture status, then emit. Emitting before
			// c.Next() races the worker goroutine against the mutation of
			// StatusCode below.
			c.Next()
			threatEvent.StatusCode = c.Writer.Status()
			c.Set(ThreatIDKey, threatEvent.ID)

			if pipe != nil {
				pipe.EmitThreat(threatEvent)
			}
		}
	}
}

// lastBlockLookupErrLog throttles block-lookup failure logging to once per
// minute — a storage outage under traffic would otherwise flood the log with
// one line per request.
var lastBlockLookupErrLog atomic.Int64

func logBlockLookupError(err error) {
	now := time.Now().Unix()
	last := lastBlockLookupErrLog.Load()
	if now-last >= 60 && lastBlockLookupErrLog.CompareAndSwap(last, now) {
		log.Printf("[sentinel] IP block lookup failed (failing open, throttled 1/min): %v", err)
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

