package sentinel_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/sentinel"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestIntegration_MountAndDetectSQLi(t *testing.T) {
	r := gin.New()

	sentinel.Mount(r, nil, sentinel.Config{
		Storage: sentinel.StorageConfig{
			Driver: sentinel.Memory,
		},
		WAF: sentinel.WAFConfig{
			Enabled: true,
			Mode:    sentinel.ModeBlock,
		},
		Dashboard: sentinel.DashboardConfig{
			Prefix:    "/sentinel",
			Username:  "admin",
			Password:  "testpass",
			SecretKey: "test-secret-key",
		},
	})

	// Add a test route
	r.GET("/api/users", func(c *gin.Context) {
		c.JSON(200, gin.H{"users": []string{}})
	})

	// 1. Test login and get JWT token
	loginBody := `{"username":"admin","password":"testpass"}`
	req := httptest.NewRequest("POST", "/sentinel/api/auth/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: status %d, body: %s", w.Code, w.Body.String())
	}

	var loginRes map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &loginRes); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	token, ok := loginRes["token"].(string)
	if !ok || token == "" {
		t.Fatal("expected JWT token in login response")
	}

	// 2. Send a SQL injection request — should be blocked by WAF
	req = httptest.NewRequest("GET", "/api/users?id=1'+OR+'1'='1", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for SQLi payload, got %d", w.Code)
	}

	var wafRes map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &wafRes); err == nil {
		if code, ok := wafRes["code"].(string); ok && code != "WAF_BLOCKED" {
			t.Errorf("expected WAF_BLOCKED code, got %s", code)
		}
	}

	// 3. Give the pipeline a moment to process the event
	time.Sleep(200 * time.Millisecond)

	// 4. Verify threat was recorded via API
	req = httptest.NewRequest("GET", "/sentinel/api/threats?page=1&page_size=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list threats failed: status %d, body: %s", w.Code, w.Body.String())
	}

	var threatsRes struct {
		Data []map[string]interface{} `json:"data"`
		Meta map[string]interface{}   `json:"meta"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &threatsRes); err != nil {
		t.Fatalf("failed to parse threats response: %v", err)
	}

	if len(threatsRes.Data) == 0 {
		t.Fatal("expected at least one threat recorded after SQLi attack")
	}

	threat := threatsRes.Data[0]
	if threat["blocked"] != true {
		t.Error("expected threat to be marked as blocked")
	}

	types, _ := threat["threat_types"].([]interface{})
	hasSQLi := false
	for _, tt := range types {
		if tt == "SQLi" {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Errorf("expected SQLi threat type, got: %v", types)
	}

	// 5. Verify security score endpoint works
	req = httptest.NewRequest("GET", "/sentinel/api/score", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("score endpoint failed: status %d", w.Code)
	}

	// 6. Verify dashboard UI is served (use /login sub-route to exercise SPA serving)
	req = httptest.NewRequest("GET", "/sentinel/ui/login", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("dashboard UI not served: status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Sentinel") {
		t.Error("dashboard HTML missing expected content")
	}

	// 7. Test auth protection — accessing API without token should fail
	req = httptest.NewRequest("GET", "/sentinel/api/threats", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", w.Code)
	}

	// 8. Test wrong login credentials
	loginBody = `{"username":"admin","password":"wrong"}`
	req = httptest.NewRequest("POST", "/sentinel/api/auth/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d", w.Code)
	}
}

func TestIntegration_LegitimateRequestAllowed(t *testing.T) {
	r := gin.New()

	sentinel.Mount(r, nil, sentinel.Config{
		Storage: sentinel.StorageConfig{
			Driver: sentinel.Memory,
		},
		WAF: sentinel.WAFConfig{
			Enabled: true,
			Mode:    sentinel.ModeBlock,
		},
	})

	r.GET("/api/products", func(c *gin.Context) {
		c.JSON(200, gin.H{"products": []string{"widget"}})
	})

	// Legitimate request should pass through WAF
	req := httptest.NewRequest("GET", "/api/products?page=1&limit=20", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("legitimate request blocked: status %d, body: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_SecurityHeaders(t *testing.T) {
	r := gin.New()

	sentinel.Mount(r, nil, sentinel.Config{
		Storage: sentinel.StorageConfig{
			Driver: sentinel.Memory,
		},
		Headers: sentinel.HeaderConfig{
			ContentSecurityPolicy:   "default-src 'self'",
			StrictTransportSecurity: true,
		},
	})

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") == "" {
		t.Error("missing X-Frame-Options header")
	}
	if w.Header().Get("Content-Security-Policy") != "default-src 'self'" {
		t.Error("missing Content-Security-Policy header")
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("missing HSTS header")
	}
}

func TestIntegration_DefaultConfig(t *testing.T) {
	r := gin.New()

	// Mount with completely empty config — should use all defaults
	sentinel.Mount(r, nil, sentinel.Config{})

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"pong": true})
	})

	req := httptest.NewRequest("GET", "/ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("default config failed: status %d", w.Code)
	}
}
