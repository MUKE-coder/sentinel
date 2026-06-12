package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func newCSPTestServer(t *testing.T) (*gin.Engine, *pipeline.Pipeline, *capturingHandler) {
	t.Helper()
	store := memory.New()
	pipe := pipeline.New(100)
	cap := &capturingHandler{}
	pipe.AddHandler(cap)
	pipe.Start(1)
	t.Cleanup(func() { pipe.Stop() })

	srv := NewServer(store, pipe, nil, nil, sentinel.Config{Dashboard: sentinel.DashboardConfig{Prefix: "/sentinel", SecretKey: "test"}})
	r := gin.New()
	srv.RegisterRoutes(r, "/sentinel")
	return r, pipe, cap
}

type capturingHandler struct{ events []pipeline.Event }

func (c *capturingHandler) Handle(_ context.Context, _ pipeline.Event) error { return nil }

func TestCSPReport_LegacyFormat(t *testing.T) {
	r, _, _ := newCSPTestServer(t)

	body := []byte(`{
		"csp-report": {
			"document-uri": "https://example.com/page",
			"referrer": "",
			"violated-directive": "script-src 'self'",
			"effective-directive": "script-src",
			"blocked-uri": "https://evil.com/x.js",
			"source-file": "https://example.com/page",
			"line-number": 42,
			"column-number": 7,
			"disposition": "report"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/sentinel/csp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/csp-report")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestCSPReport_ModernReportsAPI(t *testing.T) {
	r, _, _ := newCSPTestServer(t)

	body := []byte(`[
		{
			"type": "csp-violation",
			"url": "https://example.com/page",
			"body": {
				"documentURL": "https://example.com/page",
				"violatedDirective": "script-src-elem",
				"effectiveDirective": "script-src-elem",
				"blockedURL": "https://evil.com/x.js",
				"sourceFile": "https://example.com/page",
				"lineNumber": 99,
				"columnNumber": 12,
				"disposition": "enforce"
			}
		}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/sentinel/csp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/reports+json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestCSPReport_RateLimit(t *testing.T) {
	r, _, _ := newCSPTestServer(t)
	body := []byte(`{"csp-report":{"document-uri":"x","violated-directive":"d","blocked-uri":"u"}}`)

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/sentinel/csp-report", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/csp-report")
		req.RemoteAddr = "203.0.113.5:443"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("burst call %d should succeed, got %d", i, w.Code)
		}
	}

	// 101st should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/sentinel/csp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/csp-report")
	req.RemoteAddr = "203.0.113.5:443"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after 100/min, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "CSP_REPORT_RATE_LIMIT") {
		t.Errorf("expected CSP_REPORT_RATE_LIMIT in body, got %s", w.Body.String())
	}
}
