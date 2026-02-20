package middleware

import (
	"net/http/httptest"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/gin-gonic/gin"
)

func TestSecurityHeaders(t *testing.T) {
	enabled := true
	r := gin.New()
	r.Use(HeadersMiddleware(sentinel.HeaderConfig{
		Enabled:                 &enabled,
		XFrameOptions:           "DENY",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		ContentSecurityPolicy:   "default-src 'self'",
		StrictTransportSecurity: true,
	}))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options: DENY")
	}
	if w.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("missing Referrer-Policy")
	}
	if w.Header().Get("Content-Security-Policy") != "default-src 'self'" {
		t.Error("missing Content-Security-Policy")
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("missing Strict-Transport-Security")
	}
}

func TestSecurityHeadersDefaults(t *testing.T) {
	r := gin.New()
	r.Use(HeadersMiddleware(sentinel.HeaderConfig{
		XFrameOptions:  "DENY",
		ReferrerPolicy: "strict-origin-when-cross-origin",
	}))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing default X-Content-Type-Options")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing default X-Frame-Options")
	}
}

func TestSecurityHeadersDisabled(t *testing.T) {
	disabled := false
	r := gin.New()
	r.Use(HeadersMiddleware(sentinel.HeaderConfig{
		Enabled:       &disabled,
		XFrameOptions: "DENY",
	}))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Frame-Options") != "" {
		t.Error("expected no headers when disabled")
	}
}
