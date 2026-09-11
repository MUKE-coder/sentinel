package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Attack regression suite: techniques for getting past one defense —
// re-encoding a payload, lying about the client address, spreading guesses
// over many usernames — run end to end through MountE, not only against the
// package that implements each defense.

// spoofHeaders sets every client-address header an attacker controls to a
// fresh address. With no TrustedProxies configured, Sentinel must ignore
// all of them and use the connection's address.
func spoofHeaders(req *http.Request, i int) {
	fake := "198.51.100." + strconv.Itoa(i%250+1)
	req.Header.Set("X-Forwarded-For", fake)
	req.Header.Set("X-Real-IP", fake)
	req.Header.Set("Forwarded", "for="+fake)
	req.Header.Set("True-Client-IP", fake)
	req.Header.Set("CF-Connecting-IP", fake)
}

func attackRouter(t *testing.T, cfg Config) *gin.Engine {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	r := gin.New()
	cfg.Storage = StorageConfig{Driver: Memory}
	cfg.Dashboard = DashboardConfig{Password: "correct-horse-battery", SecretKey: "attack-suite-secret"}
	if err := MountE(r, nil, cfg); err != nil {
		t.Fatalf("MountE: %v", err)
	}
	return r
}

func serve(r *gin.Engine, req *http.Request, ip string) *httptest.ResponseRecorder {
	req.RemoteAddr = ip + ":5000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// A payload encoded once more than the router decodes, or posted as a form,
// reaches an application that decodes it again; the WAF has to see through
// the same layers. Prose with percent signs must still pass.
func TestAttack_EncodedPayloadsBlocked(t *testing.T) {
	r := attackRouter(t, Config{WAF: WAFConfig{Enabled: true, Mode: ModeBlock}})
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }
	r.GET("/api/items", ok)
	r.POST("/api/login", ok)
	r.GET("/api/files/*name", ok)

	const form = "application/x-www-form-urlencoded"
	cases := []struct {
		name, method, target, contentType, body string
		want                                    int
	}{
		{"double-encoded quote", "GET", "/api/items?id=1%2527%20OR%20%25271%2527%3D%25271", "", "", 403},
		{"double-encoded quote, stray %", "GET", "/api/items?id=1%2527%20OR%20%25271%2527%3D%25271%20100%25", "", "", 403},
		{"double-encoded UNION", "GET", "/api/items?id=1%20UNION%2520SELECT%2520password", "", "", 403},
		{"MySQL executable comment", "GET", "/api/items?id=1/*!50000UNION*/+SELECT+1", "", "", 403},
		{"form-encoded SQLi", "POST", "/api/login", form, "username=admin%27+OR+%271%27%3D%271&password=x", 403},
		{"double-encoded traversal in path", "GET", "/api/files/%252E%252E%252Fetc%252Fpasswd", "", "", 403},
		{"encoded metadata SSRF", "GET", "/api/items?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", "", "", 403},
		{"encoded __proto__ key", "GET", "/api/items?a%5B__proto__%5D%5Badmin%5D=1", "", "", 403},
		{"percent signs in prose", "GET", "/api/items?q=100%25%20cotton%2C%2050%25%20off", "", "", 200},
		{"ordinary form post", "POST", "/api/login", form, "name=Jane+Doe&email=jane%40example.com", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if w := serve(r, req, "192.0.2.50"); w.Code != tc.want {
				t.Errorf("got %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// Rotating forwarding headers must not buy a fresh rate-limit budget.
func TestAttack_SpoofedClientIPDoesNotResetRateLimit(t *testing.T) {
	r := attackRouter(t, Config{RateLimit: RateLimitConfig{
		Enabled: true,
		ByIP:    &Limit{Requests: 5, Window: time.Minute},
	}})
	r.GET("/api/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	limited := 0
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/items", nil)
		spoofHeaders(req, i)
		if serve(r, req, "192.0.2.60").Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 5 {
		t.Errorf("10 requests from one address under a 5/minute limit: %d limited, want 5", limited)
	}
}

// Credential stuffing: one address, a different username each time, fresh
// forwarding headers each time. AuthShield must lock the address out — and
// keep it out even when the next guess is a real account's password.
func TestAttack_CredentialStuffingLockedOut(t *testing.T) {
	r := attackRouter(t, Config{AuthShield: AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 5,
		LockoutDuration:   time.Minute,
	}})
	r.POST("/api/login", func(c *gin.Context) {
		var body struct{ Username, Password string }
		_ = c.ShouldBindJSON(&body)
		c.Set("sentinel_username", body.Username)
		if body.Username == "alice" && body.Password == "right-password" {
			c.Status(http.StatusOK)
			return
		}
		c.Status(http.StatusUnauthorized)
	})

	login := func(i int, user, pass string) int {
		req := httptest.NewRequest("POST", "/api/login",
			strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
		req.Header.Set("Content-Type", "application/json")
		spoofHeaders(req, i)
		return serve(r, req, "192.0.2.70").Code
	}
	for i := 0; i < 5; i++ {
		if code := login(i, "user"+strconv.Itoa(i), "guess"); code != http.StatusUnauthorized {
			t.Fatalf("guess %d: got %d, want 401", i+1, code)
		}
	}
	if code := login(5, "alice", "right-password"); code != http.StatusTooManyRequests {
		t.Errorf("after 5 failed guesses from one address: got %d, want 429", code)
	}
}

// A blocked client can't get out of the block by claiming another address,
// and nobody can get another client blocked by claiming to be it.
func TestAttack_SpoofedClientIPDoesNotEscapeBlock(t *testing.T) {
	r := attackRouter(t, Config{})
	r.GET("/api/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("POST", "/sentinel/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse-battery"}`))
	req.Header.Set("Content-Type", "application/json")
	w := serve(r, req, "192.0.2.1")
	var login struct {
		Token string `json:"token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &login) != nil {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest("POST", "/sentinel/api/ip/block", strings.NewReader(`{"ip":"192.0.2.80","reason":"attack suite"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+login.Token)
	if w := serve(r, req, "192.0.2.1"); w.Code != http.StatusOK {
		t.Fatalf("block: %d %s", w.Code, w.Body.String())
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/api/items", nil)
		spoofHeaders(req, i)
		if code := serve(r, req, "192.0.2.80").Code; code != http.StatusForbidden {
			t.Errorf("blocked address with spoofed forwarding headers: got %d, want 403", code)
		}
	}

	req = httptest.NewRequest("GET", "/api/items", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.80")
	req.Header.Set("X-Real-IP", "192.0.2.80")
	if code := serve(r, req, "192.0.2.81").Code; code != http.StatusOK {
		t.Errorf("an unblocked client claiming a blocked address: got %d, want 200", code)
	}
}
