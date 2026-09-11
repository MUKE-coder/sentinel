package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// clientIPFor runs extractClientIP against a request from remoteAddr. Each
// header value is added as a separate header line.
func clientIPFor(t *testing.T, remoteAddr string, headers map[string][]string) string {
	t.Helper()
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, extractClientIP(c))
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remoteAddr
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr.Body.String()
}

func TestClientIP_IgnoresXFFWhenNoTrustedProxies(t *testing.T) {
	ConfigureTrustedProxies(nil)
	defer ConfigureTrustedProxies(nil)

	got := clientIPFor(t, "203.0.113.5:54321", map[string][]string{"X-Forwarded-For": {"8.8.8.8"}})
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

	got := clientIPFor(t, "10.0.0.50:443", map[string][]string{"X-Forwarded-For": {"8.8.8.8, 10.0.0.50"}})
	if got != "8.8.8.8" {
		t.Fatalf("expected client hop 8.8.8.8 when behind trusted proxy, got %q", got)
	}
}

func TestClientIP_IgnoresXFFFromUntrustedProxy(t *testing.T) {
	ConfigureTrustedProxies([]string{"10.0.0.0/8"})
	defer ConfigureTrustedProxies(nil)

	got := clientIPFor(t, "203.0.113.5:54321", map[string][]string{"X-Forwarded-For": {"8.8.8.8"}})
	if got != "203.0.113.5" {
		t.Fatalf("expected direct IP 203.0.113.5 from untrusted proxy, got %q", got)
	}
}

// TestClientIP_ForwardedForChain pins the right-to-left walk. Proxies append
// the peer they saw, so anything left of the first untrusted hop was written
// by the client. Before v2.2.2 the leftmost entry was used, which let any
// client behind nginx or Caddy choose its own IP and slip per-IP rate
// limits, IP blocks, and AuthShield lockouts.
func TestClientIP_ForwardedForChain(t *testing.T) {
	ConfigureTrustedProxies([]string{"10.0.0.0/8"})
	defer ConfigureTrustedProxies(nil)

	tests := []struct {
		name    string
		xff     []string
		xRealIP string
		want    string
	}{
		{"spoofed leftmost entry is ignored", []string{"1.1.1.1, 203.0.113.9"}, "", "203.0.113.9"},
		{"multiple trusted hops are skipped", []string{"1.1.1.1, 203.0.113.9, 10.0.0.2"}, "", "203.0.113.9"},
		{"proxy-appended second header line", []string{"1.1.1.1", "203.0.113.9"}, "", "203.0.113.9"},
		{"hop with port", []string{"203.0.113.9:4711"}, "", "203.0.113.9"},
		{"bracketed IPv6 hop with port", []string{"[2001:db8::7]:4711"}, "", "2001:db8::7"},
		{"IPv4-mapped hop is normalised", []string{"::ffff:203.0.113.9"}, "", "203.0.113.9"},
		{"all hops trusted yields the furthest", []string{"10.0.0.7, 10.0.0.8"}, "", "10.0.0.7"},
		{"garbage stops the walk at the last trusted hop", []string{"bogus, 10.0.0.7"}, "", "10.0.0.7"},
		{"unparseable header falls back to the proxy, not X-Real-IP", []string{"bogus"}, "1.1.1.1", "10.0.0.50"},
		{"X-Real-IP is used when XFF is absent", nil, "203.0.113.9", "203.0.113.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string][]string{}
			if tt.xff != nil {
				headers["X-Forwarded-For"] = tt.xff
			}
			if tt.xRealIP != "" {
				headers["X-Real-IP"] = []string{tt.xRealIP}
			}
			if got := clientIPFor(t, "10.0.0.50:443", headers); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIP_MappedProxyAddressIsTrusted(t *testing.T) {
	ConfigureTrustedProxies([]string{"10.0.0.0/8"})
	defer ConfigureTrustedProxies(nil)

	got := clientIPFor(t, "[::ffff:10.0.0.50]:443", map[string][]string{"X-Forwarded-For": {"203.0.113.9"}})
	if got != "203.0.113.9" {
		t.Fatalf("an IPv4-mapped peer inside TrustedProxies should be trusted, got %q", got)
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
