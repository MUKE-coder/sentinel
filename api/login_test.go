package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/gin-gonic/gin"
)

// TestLogin_RateLimitIgnoresSpoofedForwardedFor pins the fix for the login
// limiter keying on gin's c.ClientIP(). A gin engine trusts X-Forwarded-For
// from every peer by default, so a brute-forcer rotating that header got a
// fresh 10-attempt budget on every request and the limit never tripped.
func TestLogin_RateLimitIgnoresSpoofedForwardedFor(t *testing.T) {
	middleware.ConfigureTrustedProxies(nil)
	defer middleware.ConfigureTrustedProxies(nil)

	s := &Server{
		config:  sentinel.Config{Dashboard: sentinel.DashboardConfig{Username: "admin", Password: "correct-horse"}},
		loginRL: NewLoginRateLimiter(),
	}
	r := gin.New()
	r.POST("/login", s.handleLogin)

	var last int
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.5:40000"
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('1'+i%9)))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		last = rr.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("11th attempt from one connection IP with rotating X-Forwarded-For: got %d, want 429", last)
	}
}
