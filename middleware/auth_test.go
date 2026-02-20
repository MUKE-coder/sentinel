package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/gin-gonic/gin"
)

func setupAuthShieldRouter(config sentinel.AuthShieldConfig, pipe *pipeline.Pipeline) (*gin.Engine, *AuthShield) {
	shield := NewAuthShield(config, nil, pipe)

	r := gin.New()
	r.Use(shield.Middleware())
	r.POST("/api/login", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		c.ShouldBindJSON(&req)
		c.Set("sentinel_username", req.Username)

		if req.Username == "admin" && req.Password == "secret" {
			c.JSON(http.StatusOK, gin.H{"token": "test123"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid"})
		}
	})
	r.GET("/api/data", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "ok"})
	})
	return r, shield
}

func loginRequest(username, password string) *http.Request {
	body := `{"username":"` + username + `","password":"` + password + `"}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAuthShield_LockAfterMaxAttempts(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
	}

	r, _ := setupAuthShieldRouter(config, pipe)

	// 5 failed attempts
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, loginRequest("admin", "wrong"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	// 6th attempt should be blocked by auth shield
	w := httptest.NewRecorder()
	r.ServeHTTP(w, loginRequest("admin", "wrong"))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after lockout, got %d", w.Code)
	}

	// Even correct credentials should be blocked
	w = httptest.NewRecorder()
	r.ServeHTTP(w, loginRequest("admin", "secret"))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 even with correct credentials during lockout, got %d", w.Code)
	}
}

func TestAuthShield_SuccessResetsCounter(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
	}

	r, shield := setupAuthShieldRouter(config, pipe)

	// 3 failed attempts
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, loginRequest("admin", "wrong"))
	}

	attempts, locked := shield.GetIPStatus("192.0.2.1")
	if locked {
		t.Fatal("should not be locked after 3 attempts")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}

	// Successful login resets counter
	w := httptest.NewRecorder()
	r.ServeHTTP(w, loginRequest("admin", "secret"))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for correct login, got %d", w.Code)
	}

	attempts, locked = shield.GetIPStatus("192.0.2.1")
	if locked {
		t.Error("should not be locked after successful login")
	}
	if attempts != 0 {
		t.Errorf("expected 0 attempts after reset, got %d", attempts)
	}
}

func TestAuthShield_DoesNotInterfereWithOtherRoutes(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
	}

	r, _ := setupAuthShieldRouter(config, pipe)

	// Other routes should work fine
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/data", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for non-login route, got %d", w.Code)
	}
}

func TestAuthShield_DisabledPassesThrough(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:    false,
		LoginRoute: "/api/login",
	}

	r, _ := setupAuthShieldRouter(config, pipe)

	// Even many failed logins should pass through when disabled
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, loginRequest("admin", "wrong"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 when shield disabled, got %d", w.Code)
		}
	}
}

func TestAuthShield_UnblockUser(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 3,
		LockoutDuration:   15 * time.Minute,
	}

	_, shield := setupAuthShieldRouter(config, pipe)

	// Simulate failures to lock a user
	for i := 0; i < 5; i++ {
		shield.recordFailure("1.2.3.4", "testuser")
	}

	if !shield.IsUserLocked("testuser") {
		t.Error("expected user to be locked")
	}

	shield.UnblockUser("testuser")

	if shield.IsUserLocked("testuser") {
		t.Error("expected user to be unlocked after UnblockUser")
	}
}
