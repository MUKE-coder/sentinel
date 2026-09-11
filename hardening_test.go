package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MUKE-coder/sentinel/v2/core"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// An unset SecretKey used to default to a string published in the source,
// so anyone could sign an admin token for a zero-config dashboard.
func TestApplyDefaults_SecretKeyIsRandom(t *testing.T) {
	var a, b Config
	a.ApplyDefaults()
	b.ApplyDefaults()
	if a.Dashboard.SecretKey == core.DefaultInsecureSecretKey || len(a.Dashboard.SecretKey) < 32 {
		t.Fatalf("unset SecretKey defaulted to %q", a.Dashboard.SecretKey)
	}
	if a.Dashboard.SecretKey == b.Dashboard.SecretKey {
		t.Error("two configs were given the same generated SecretKey")
	}

	c := Config{Dashboard: DashboardConfig{SecretKey: "deployment-secret"}}
	c.ApplyDefaults()
	if c.Dashboard.SecretKey != "deployment-secret" {
		t.Errorf("an explicit SecretKey was replaced with %q", c.Dashboard.SecretKey)
	}
}

func TestValidateConfig_SecretKey(t *testing.T) {
	cases := []struct {
		name, key string
		warn      bool
	}{
		{"unset", "", true},
		{"published default", core.DefaultInsecureSecretKey, true},
		{"deployment secret", "a-deployment-specific-secret-value", false},
	}
	for _, tc := range cases {
		issues := ValidateConfig(Config{Dashboard: DashboardConfig{SecretKey: tc.key}})
		if got := hasIssue(issues, IssueWarning, "Dashboard.SecretKey"); got != tc.warn {
			t.Errorf("%s: SecretKey warning = %v, want %v", tc.name, got, tc.warn)
		}
	}
}

func TestDefaultPasswordAcceptedOnlyFromLocalhost(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	mount := func(allowInsecure bool) *gin.Engine {
		r := gin.New()
		cfg := Config{
			Storage:   StorageConfig{Driver: Memory},
			Dashboard: DashboardConfig{AllowInsecureDefaults: allowInsecure},
		}
		if err := MountE(r, nil, cfg); err != nil {
			t.Fatalf("MountE: %v", err)
		}
		return r
	}
	login := func(r *gin.Engine, remote string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/sentinel/api/auth/login",
			strings.NewReader(`{"username":"admin","password":"`+core.DefaultInsecurePassword+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = remote
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	r := mount(false)
	cases := []struct {
		name, remote string
		headers      map[string]string
		want         int
	}{
		{"loopback", "127.0.0.1:5000", nil, http.StatusOK},
		{"IPv6 loopback", "[::1]:5000", nil, http.StatusOK},
		{"another machine", "192.0.2.1:5000", nil, http.StatusForbidden},
		{"relayed by a proxy on localhost", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "203.0.113.9"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		w := login(r, tc.remote, tc.headers)
		if w.Code != tc.want {
			t.Errorf("%s: got %d, want %d: %s", tc.name, w.Code, tc.want, w.Body.String())
		}
		if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), "DEFAULT_PASSWORD_REMOTE") {
			t.Errorf("%s: refusal doesn't say why: %s", tc.name, w.Body.String())
		}
	}

	if w := login(mount(true), "192.0.2.1:5000", nil); w.Code != http.StatusOK {
		t.Errorf("AllowInsecureDefaults: remote login got %d, want 200", w.Code)
	}
}

// The live threat stream used to accept a browser handshake from any origin.
func TestWebSocketRejectsOtherOrigins(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	r := gin.New()
	cfg := Config{
		Storage:   StorageConfig{Driver: Memory},
		Dashboard: DashboardConfig{Password: "correct-horse-battery", SecretKey: "websocket-origin-secret"},
	}
	if err := MountE(r, nil, cfg); err != nil {
		t.Fatalf("MountE: %v", err)
	}
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/sentinel/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"correct-horse-battery"}`))
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&login)
	resp.Body.Close()
	if login.Token == "" {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sentinel/ws/threats?token=" + login.Token
	dial := func(h http.Header) (int, error) {
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, h)
		if conn != nil {
			conn.Close()
		}
		if resp == nil {
			return 0, err
		}
		return resp.StatusCode, err
	}

	if code, err := dial(http.Header{"Origin": {"https://evil.example"}}); err == nil || code != http.StatusForbidden {
		t.Errorf("cross-origin handshake: status %d, err %v; want 403", code, err)
	}
	if _, err := dial(http.Header{"Origin": {srv.URL}}); err != nil {
		t.Errorf("same-origin handshake: %v", err)
	}
	if _, err := dial(http.Header{"Origin": {"https://dash.example.com"}, "X-Forwarded-Host": {"dash.example.com"}}); err != nil {
		t.Errorf("handshake through a proxy that rewrites Host: %v", err)
	}
	if _, err := dial(nil); err != nil {
		t.Errorf("non-browser client without an Origin: %v", err)
	}
}
