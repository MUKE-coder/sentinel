package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
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

	// UnblockUser lifts an account lockout, which only LockoutAccount sets.
	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 3,
		LockoutDuration:   15 * time.Minute,
		LockoutKey:        sentinel.LockoutAccount,
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

// Regression test for issue #8: an upstream middleware that rewrites
// c.Request.URL.Path must not disable AuthShield — the registered route
// pattern (FullPath) still identifies the login route.
func TestAuthShield_SurvivesPathRewrite(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 3,
		LockoutDuration:   15 * time.Minute,
	}
	shield := NewAuthShield(config, nil, pipe)

	r := gin.New()
	// Simulate a host app that rewrites the path before AuthShield sees it.
	r.Use(func(c *gin.Context) {
		if c.Request.URL.Path == "/api/login" {
			c.Request.URL.Path = "/__rewritten/api/login"
		}
		c.Next()
	})
	r.Use(shield.Middleware())
	r.POST("/api/login", func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid"})
	})

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, loginRequest("admin", "wrong"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, loginRequest("admin", "wrong"))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 lockout despite path rewrite, got %d", w.Code)
	}
}

// Behind NAT one address is an office, a campus, or a mobile carrier.
// Locking the address barred everyone sharing it, and anyone who knew a
// target's egress address could do it on purpose (issue #36). The default
// lockout key is the (address, account) pair: the person who failed is
// stopped, their neighbours are not.
func TestAuthShield_PairLockoutSparesOthersBehindOneAddress(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 3,
		LockoutDuration:   15 * time.Minute,
		LockoutKey:        sentinel.LockoutPair,
		UsernameFields:    sentinel.DefaultUsernameFields,
	}
	r, _ := setupAuthShieldRouter(config, pipe)

	attempt := func(user, pass string) int {
		req := loginRequest(user, pass)
		req.RemoteAddr = "198.51.100.7:5000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := 0; i < 3; i++ {
		if code := attempt("alice", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: got %d, want 401", i+1, code)
		}
	}
	if code := attempt("alice", "wrong"); code != http.StatusTooManyRequests {
		t.Errorf("the account that failed must be locked from this address: got %d, want 429", code)
	}

	// The colleagues on the same egress address are unaffected: another
	// account can still fail, and the right password still works.
	if code := attempt("bob", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("another account from the same address must not be locked out: got %d, want 401", code)
	}
	if code := attempt("admin", "secret"); code != http.StatusOK {
		t.Errorf("a correct sign-in from the same address must succeed: got %d, want 200", code)
	}
}

// LockoutKey "ip" keeps the pre-v2.7 behavior for anyone who wants it, and
// ExemptIPs spares known shared egress from it.
func TestAuthShield_LockoutKeyIPAndExemptions(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	run := func(t *testing.T, exempt []string) int {
		config := sentinel.AuthShieldConfig{
			Enabled:           true,
			LoginRoute:        "/api/login",
			MaxFailedAttempts: 3,
			LockoutDuration:   15 * time.Minute,
			LockoutKey:        sentinel.LockoutIP,
			ExemptIPs:         exempt,
		}
		r, _ := setupAuthShieldRouter(config, pipe)
		attempt := func(user string) int {
			req := loginRequest(user, "wrong")
			req.RemoteAddr = "203.0.113.20:5000"
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			return w.Code
		}
		for i := 0; i < 3; i++ {
			attempt("alice")
		}
		// A different account from the same address: locked only when the
		// address itself is locked.
		return attempt("bob")
	}

	if code := run(t, nil); code != http.StatusTooManyRequests {
		t.Errorf(`LockoutKey "ip" must lock the address: got %d, want 429`, code)
	}
	if code := run(t, []string{"203.0.113.0/24"}); code != http.StatusUnauthorized {
		t.Errorf("an exempt CIDR must never be locked: got %d, want 401", code)
	}
}

// A lockout keyed on the account has to be visible before the handler runs,
// which means AuthShield reads the account from the request itself — and
// must put the body back for the login handler.
func TestAuthShield_ReadsAccountWithoutConsumingTheBody(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 2,
		LockoutDuration:   15 * time.Minute,
		UsernameFields:    []string{"email"},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	shield := NewAuthShield(config, nil, pipe)
	r.Use(shield.Middleware())
	var seen []string
	r.POST("/api/login", func(c *gin.Context) {
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		// The handler must still see the body AuthShield peeked at.
		seen = append(seen, body.Email)
		c.Status(http.StatusUnauthorized)
	})

	post := func() int {
		req := httptest.NewRequest("POST", "/api/login",
			strings.NewReader(`{"email":"Carol@example.com","password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.30:5000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := 0; i < 2; i++ {
		if code := post(); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401 (the handler must read the body)", i+1, code)
		}
	}
	if len(seen) != 2 || seen[0] != "Carol@example.com" {
		t.Errorf("the handler saw %v, want the email twice", seen)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Errorf("the account read from the body must be locked after 2 failures: got %d, want 429", code)
	}

	// Case folding: the same account in another case is the same lockout.
	req := httptest.NewRequest("POST", "/api/login",
		strings.NewReader(`{"email":"carol@EXAMPLE.com","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.30:5000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("the lockout must fold case: got %d, want 429", w.Code)
	}
}

// The dashboard reads Snapshot. Under the pair default it showed nobody
// locked while sign-ins were being refused, so the locked accounts belong
// in it.
func TestAuthShield_SnapshotListsLockedAccounts(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	config := sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 2,
		LockoutDuration:   15 * time.Minute,
	}
	_, shield := setupAuthShieldRouter(config, pipe)

	for i := 0; i < 2; i++ {
		shield.recordFailure("203.0.113.40", "dave")
	}

	snap := shield.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot has %d rows, want 1: %+v", len(snap), snap)
	}
	if snap[0].Locked {
		t.Error("the address itself must not be locked under the pair default")
	}
	if len(snap[0].LockedAccounts) != 1 || snap[0].LockedAccounts[0] != "dave" {
		t.Errorf("locked accounts = %v, want [dave]", snap[0].LockedAccounts)
	}
}

// An application whose login reports no account name — nothing in the
// request fields and no c.Set("sentinel_username") — has nothing to key a
// pair lockout on. Doing nothing there would leave it with no lockout at
// all, so the address is locked, which is what every application got before
// v2.7.0. ExemptIPs still spares shared egress.
func TestAuthShield_FallsBackToAddressWhenAccountIsUnknown(t *testing.T) {
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	run := func(exempt []string) int {
		config := sentinel.AuthShieldConfig{
			Enabled:           true,
			LoginRoute:        "/api/login",
			MaxFailedAttempts: 3,
			LockoutDuration:   15 * time.Minute,
			ExemptIPs:         exempt,
		}
		shield := NewAuthShield(config, nil, pipe)
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(shield.Middleware())
		// No body to read an account from, and the handler reports none.
		r.POST("/api/login", func(c *gin.Context) { c.Status(http.StatusUnauthorized) })

		post := func() int {
			req := httptest.NewRequest("POST", "/api/login", nil)
			req.RemoteAddr = "203.0.113.60:5000"
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			return w.Code
		}
		for i := 0; i < 3; i++ {
			post()
		}
		return post()
	}

	if code := run(nil); code != http.StatusTooManyRequests {
		t.Errorf("with no account to key on, the address must be locked: got %d, want 429", code)
	}
	if code := run([]string{"203.0.113.60"}); code != http.StatusUnauthorized {
		t.Errorf("an exempt address must not be locked even as a fallback: got %d, want 401", code)
	}
}
