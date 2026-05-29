package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestClientIP_IgnoresXFFWhenNoTrustedProxies(t *testing.T) {
	ConfigureTrustedProxies(nil)
	defer ConfigureTrustedProxies(nil)

	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, extractClientIP(c))
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	got := rr.Body.String()
	if got == "8.8.8.8" {
		t.Fatalf("XFF was honored without trusted proxies — spoofing bypass: got %q", got)
	}
	if got != "203.0.113.5" {
		t.Fatalf("expected direct connection IP 203.0.113.5, got %q", got)
	}
}

func TestClientIP_HonorsXFFFromTrustedProxy(t *testing.T) {
	ConfigureTrustedProxies([]string{"10.0.0.0/8"})
	defer ConfigureTrustedProxies(nil)

	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, extractClientIP(c))
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.50:443"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.50")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if got := rr.Body.String(); got != "8.8.8.8" {
		t.Fatalf("expected first XFF hop 8.8.8.8 when behind trusted proxy, got %q", got)
	}
}

func TestClientIP_IgnoresXFFFromUntrustedProxy(t *testing.T) {
	ConfigureTrustedProxies([]string{"10.0.0.0/8"})
	defer ConfigureTrustedProxies(nil)

	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, extractClientIP(c))
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if got := rr.Body.String(); got != "203.0.113.5" {
		t.Fatalf("expected direct IP 203.0.113.5 from untrusted proxy, got %q", got)
	}
}

func TestActorIDFromIP_IPv6Safe(t *testing.T) {
	v4 := ActorIDFromIP("203.0.113.5")
	v6 := ActorIDFromIP("2001:db8::1")
	if v4 == "" || v6 == "" {
		t.Fatal("ActorIDFromIP returned empty")
	}
	if v4 == v6 {
		t.Fatal("ActorIDFromIP collisions on v4/v6")
	}
	if ActorIDFromIP("203.0.113.5") != v4 {
		t.Fatal("ActorIDFromIP not stable")
	}
}
