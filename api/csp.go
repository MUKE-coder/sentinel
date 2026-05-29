package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/middleware"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CSP report handling. Accepts both the legacy
// `application/csp-report` envelope shipped by older browsers and the
// modern Reports API (`application/reports+json`) format, normalizes to a
// single shape, and pushes the result into Sentinel's existing threat
// pipeline so it shows up in the dashboard next to WAF blocks.

const cspReportMaxBody = 64 * 1024 // 64 KB — browsers send small payloads

// cspReportLimiter is a tiny in-memory per-IP limiter dedicated to the CSP
// receiver. CSP reports can be hostile traffic (an attacker can spray
// hundreds per second to flood storage), so this endpoint must be rate
// limited regardless of whether the main rate limiter is enabled.
type cspReportLimiter struct {
	mu      sync.Mutex
	buckets map[string]*cspBucket
	limit   int
	window  time.Duration
}

type cspBucket struct {
	count     int
	resetAt   time.Time
}

func newCSPLimiter(limit int, window time.Duration) *cspReportLimiter {
	return &cspReportLimiter{
		buckets: make(map[string]*cspBucket),
		limit:   limit,
		window:  window,
	}
}

func (l *cspReportLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[ip]
	if !ok || now.After(b.resetAt) {
		l.buckets[ip] = &cspBucket{count: 1, resetAt: now.Add(l.window)}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// cspViolation is the normalized form we store. Both legacy and modern
// browser shapes flatten into this.
type cspViolation struct {
	DocumentURI        string `json:"document_uri,omitempty"`
	Referrer           string `json:"referrer,omitempty"`
	ViolatedDirective  string `json:"violated_directive,omitempty"`
	EffectiveDirective string `json:"effective_directive,omitempty"`
	BlockedURI         string `json:"blocked_uri,omitempty"`
	SourceFile         string `json:"source_file,omitempty"`
	LineNumber         int    `json:"line_number,omitempty"`
	ColumnNumber       int    `json:"column_number,omitempty"`
	ScriptSample       string `json:"script_sample,omitempty"`
	StatusCode         int    `json:"status_code,omitempty"`
	Disposition        string `json:"disposition,omitempty"`
}

// CSP report endpoint setup — registered by api.Server.

func (s *Server) registerCSPReport(r *gin.Engine, prefix string) {
	limiter := newCSPLimiter(100, time.Minute) // 100 / min / IP
	r.POST(prefix+"/csp-report", s.handleCSPReport(limiter))
}

func (s *Server) handleCSPReport(limiter *cspReportLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded for CSP reports",
				"code":  "CSP_REPORT_RATE_LIMIT",
			})
			return
		}

		body, err := io.ReadAll(io.LimitReader(c.Request.Body, cspReportMaxBody))
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		violations := parseCSPReport(c.GetHeader("Content-Type"), body)
		if len(violations) == 0 {
			// Browsers sometimes send empty/malformed reports — ack anyway
			// so they don't retry-storm.
			c.Status(http.StatusNoContent)
			return
		}

		for _, v := range violations {
			s.emitCSPViolation(ip, c.Request.UserAgent(), v)
		}
		c.Status(http.StatusNoContent)
	}
}

func (s *Server) emitCSPViolation(ip, ua string, v cspViolation) {
	if s.pipe == nil {
		return
	}
	cvss := sentinel.DefaultCVSSForType(string(sentinel.ThreatCSPViolation))
	encoded, _ := json.Marshal(v)
	te := &sentinel.ThreatEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		IP:          ip,
		ActorID:     middleware.ActorIDFromIP(ip),
		Method:      "POST",
		Path:        v.DocumentURI,
		UserAgent:   ua,
		ThreatTypes: []string{string(sentinel.ThreatCSPViolation)},
		Severity:    middleware.DefaultCSPSeverity(),
		Confidence:  100, // browser-reported = high signal
		CVSS:        cvss.Score,
		CVSSVector:  cvss.Vector,
		BodySnippet: truncate(string(encoded), 500),
		Evidence: []sentinel.Evidence{
			{Pattern: "csp-violation", Matched: v.BlockedURI, Location: v.ViolatedDirective, Parameter: v.SourceFile},
		},
	}
	s.pipe.EmitThreat(te)
}

// parseCSPReport accepts either the legacy single-report envelope or the
// modern Reports API array. Returns one or more normalized cspViolation.
func parseCSPReport(contentType string, body []byte) []cspViolation {
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	switch {
	case strings.HasPrefix(contentType, "application/reports+json"):
		var reports []struct {
			Type string         `json:"type"`
			Body map[string]any `json:"body"`
			URL  string         `json:"url"`
		}
		if err := json.Unmarshal(body, &reports); err != nil {
			return nil
		}
		out := make([]cspViolation, 0, len(reports))
		for _, r := range reports {
			if r.Type != "csp-violation" && r.Type != "csp" {
				continue
			}
			v := violationFromMap(r.Body)
			if v.DocumentURI == "" {
				v.DocumentURI = r.URL
			}
			out = append(out, v)
		}
		return out

	default:
		// Legacy `application/csp-report` shape: {"csp-report": {...}}
		var wrapper struct {
			Report map[string]any `json:"csp-report"`
		}
		if err := json.Unmarshal(body, &wrapper); err != nil {
			return nil
		}
		if wrapper.Report == nil {
			return nil
		}
		return []cspViolation{violationFromMap(wrapper.Report)}
	}
}

func violationFromMap(m map[string]any) cspViolation {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
		return ""
	}
	getInt := func(keys ...string) int {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if f, ok := v.(float64); ok {
					return int(f)
				}
			}
		}
		return 0
	}
	return cspViolation{
		DocumentURI:        get("document-uri", "documentURL"),
		Referrer:           get("referrer"),
		ViolatedDirective:  get("violated-directive", "violatedDirective"),
		EffectiveDirective: get("effective-directive", "effectiveDirective"),
		BlockedURI:         get("blocked-uri", "blockedURL"),
		SourceFile:         get("source-file", "sourceFile"),
		LineNumber:         getInt("line-number", "lineNumber"),
		ColumnNumber:       getInt("column-number", "columnNumber"),
		ScriptSample:       get("script-sample", "sample"),
		StatusCode:         getInt("status-code", "statusCode"),
		Disposition:        get("disposition"),
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
