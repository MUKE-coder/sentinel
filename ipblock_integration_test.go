package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestMountE_IPBlocksEnforcedWithoutWAF: IP blocks were enforced only inside
// the WAF, so with WAF.Enabled false a block from the dashboard did nothing.
func TestMountE_IPBlocksEnforcedWithoutWAF(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	r := gin.New()
	cfg := Config{
		Storage:   StorageConfig{Driver: Memory},
		Dashboard: DashboardConfig{Password: "correct-horse-battery", SecretKey: "integration-secret"},
	}
	if err := MountE(r, nil, cfg); err != nil {
		t.Fatalf("MountE: %v", err)
	}
	r.GET("/api/hello", func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(method, path, ip, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = ip + ":5000"
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	w := do("POST", "/sentinel/api/auth/login", "192.0.2.1", "", `{"username":"admin","password":"correct-horse-battery"}`)
	var login struct {
		Token string `json:"token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &login) != nil {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}

	if code := do("GET", "/api/hello", "192.0.2.10", "", "").Code; code != http.StatusOK {
		t.Fatalf("before the block: got %d", code)
	}
	if code := do("POST", "/sentinel/api/ip/block", "192.0.2.1", login.Token, `{"ip":"192.0.2.10","reason":"test"}`).Code; code != http.StatusOK {
		t.Fatalf("block: got %d", code)
	}
	if code := do("GET", "/api/hello", "192.0.2.10", "", "").Code; code != http.StatusForbidden {
		t.Errorf("a blocked IP must get 403 with the WAF disabled, got %d", code)
	}
	if code := do("GET", "/api/hello", "192.0.2.11", "", "").Code; code != http.StatusOK {
		t.Errorf("other IPs must be unaffected, got %d", code)
	}
}
