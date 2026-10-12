package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// Issue #18: the dashboard's login budget lived in process memory, so an
// attacker spreading guesses over N replicas behind a load balancer got 10N
// attempts at the dashboard password. With a shared counter store, ten
// attempts means ten in total.
func TestLogin_RateLimitHoldsAcrossReplicas(t *testing.T) {
	middleware.ConfigureTrustedProxies(nil)
	defer middleware.ConfigureTrustedProxies(nil)

	shared := middleware.NewMemoryCounterStore()
	defer shared.Close()

	replica := func() *gin.Engine {
		s := &Server{
			config:  sentinel.Config{Dashboard: sentinel.DashboardConfig{Username: "admin", Password: "correct-horse"}},
			loginRL: NewLoginRateLimiter(),
		}
		s.SetCounters(shared)
		r := gin.New()
		r.POST("/login", s.handleLogin)
		return r
	}
	replicas := []*gin.Engine{replica(), replica()}

	attempt := func(i int) int {
		req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.77:40000"
		rr := httptest.NewRecorder()
		replicas[i%len(replicas)].ServeHTTP(rr, req)
		return rr.Code
	}

	for i := 0; i < 10; i++ {
		if code := attempt(i); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d across replicas: got %d, want 401", i+1, code)
		}
	}
	if code := attempt(10); code != http.StatusTooManyRequests {
		t.Errorf("the 11th attempt split across replicas must be refused: got %d, want 429", code)
	}
	// The other replica agrees, rather than keeping its own budget.
	if code := attempt(11); code != http.StatusTooManyRequests {
		t.Errorf("the other replica must honour the same budget: got %d, want 429", code)
	}
}

// A counter-store outage must not lock everyone out of the dashboard: the
// password is still required, and attempts are allowed until it recovers.
func TestLogin_RateLimitFailsOpen(t *testing.T) {
	middleware.ConfigureTrustedProxies(nil)
	defer middleware.ConfigureTrustedProxies(nil)

	s := &Server{
		config:  sentinel.Config{Dashboard: sentinel.DashboardConfig{Username: "admin", Password: "correct-horse"}},
		loginRL: NewLoginRateLimiter(),
	}
	s.SetCounters(brokenCounterStore{})
	r := gin.New()
	r.POST("/login", s.handleLogin)

	for i := 0; i < 12; i++ {
		req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.78:40000"
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d with a broken counter store: got %d, want 401", i+1, rr.Code)
		}
	}

	// And the right password still works.
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"correct-horse"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.78:40000"
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("a correct sign-in must still work: got %d %s", rr.Code, rr.Body.String())
	}
}

// brokenCounterStore stands in for a Redis that is down.
type brokenCounterStore struct{}

func (brokenCounterStore) Take(context.Context, string, int, time.Duration, sentinel.RateLimitStrategy, time.Time) (bool, error) {
	return false, errors.New("counter store unavailable")
}

func (brokenCounterStore) Usage(context.Context, string, sentinel.RateLimitStrategy, time.Time) (sentinel.CounterUsage, bool, error) {
	return sentinel.CounterUsage{}, false, errors.New("counter store unavailable")
}

func (brokenCounterStore) Record(context.Context, string, string, time.Duration, time.Time) (int, error) {
	return 0, errors.New("counter store unavailable")
}

func (brokenCounterStore) Count(context.Context, string, time.Duration, time.Time) (int, error) {
	return 0, errors.New("counter store unavailable")
}

func (brokenCounterStore) SetUntil(context.Context, string, time.Time) error {
	return errors.New("counter store unavailable")
}

func (brokenCounterStore) Until(context.Context, string, time.Time) (time.Time, error) {
	return time.Time{}, errors.New("counter store unavailable")
}

func (brokenCounterStore) Delete(context.Context, ...string) (bool, error) {
	return false, errors.New("counter store unavailable")
}

func (brokenCounterStore) Keys(context.Context, string) ([]string, error) {
	return nil, errors.New("counter store unavailable")
}
