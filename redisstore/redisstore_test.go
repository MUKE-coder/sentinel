package redisstore

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/countertest"
	"github.com/MUKE-coder/sentinel/v2/middleware"
)

func newClient(t *testing.T, mr *miniredis.Miniredis, opts *redis.Options) *redis.Client {
	t.Helper()
	if opts == nil {
		opts = &redis.Options{}
	}
	opts.Addr = mr.Addr()
	client := redis.NewClient(opts)
	t.Cleanup(func() { client.Close() })
	return client
}

func TestConformance(t *testing.T) {
	countertest.Run(t, func(t *testing.T) sentinel.CounterStore {
		return New(newClient(t, miniredis.RunT(t), nil))
	})
}

// rateLimitedReplica is one instance of a horizontally scaled app: its own
// router and limiter, sharing only the counter store.
func rateLimitedReplica(store sentinel.CounterStore, requests int) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	cfg := sentinel.RateLimitConfig{Enabled: true, ByIP: &sentinel.Limit{Requests: requests, Window: time.Minute}}
	r.Use(middleware.RateLimitMiddleware(cfg, middleware.NewRateLimiterWithStore(store), nil))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func send(r *gin.Engine, method, path, ip string) int {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = ip + ":5000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// A client spreading requests over two replicas gets the limit once, not
// once per replica.
func TestReplicasShareRateLimits(t *testing.T) {
	store := New(newClient(t, miniredis.RunT(t), nil))
	replicas := []*gin.Engine{rateLimitedReplica(store, 5), rateLimitedReplica(store, 5)}

	allowed := 0
	for i := 0; i < 10; i++ {
		if send(replicas[i%2], "GET", "/", "192.0.2.1") == http.StatusOK {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("10 requests across 2 replicas under a shared 5/minute limit: %d allowed, want 5", allowed)
	}
}

// Failed logins on one replica count toward a lockout on the other.
func TestReplicasShareLockouts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := New(newClient(t, miniredis.RunT(t), nil))
	cfg := sentinel.AuthShieldConfig{Enabled: true, LoginRoute: "/login", MaxFailedAttempts: 3, LockoutDuration: time.Minute}
	replica := func() *gin.Engine {
		shield := middleware.NewAuthShield(cfg, nil, nil)
		shield.SetCounters(store)
		r := gin.New()
		r.Use(shield.Middleware())
		r.POST("/login", func(c *gin.Context) { c.Status(http.StatusUnauthorized) })
		return r
	}
	a, b := replica(), replica()

	for i, r := range []*gin.Engine{a, b, a} {
		if code := send(r, "POST", "/login", "192.0.2.9"); code != http.StatusUnauthorized {
			t.Fatalf("failed login %d: got %d, want 401", i+1, code)
		}
	}
	if code := send(b, "POST", "/login", "192.0.2.9"); code != http.StatusTooManyRequests {
		t.Errorf("after 3 failures split across replicas: got %d, want 429", code)
	}
}

// Two applications sharing one Redis keep separate counters.
func TestPrefixesSeparateApplications(t *testing.T) {
	client := newClient(t, miniredis.RunT(t), nil)
	app1 := rateLimitedReplica(New(client, WithPrefix("app1:")), 5)
	app2 := rateLimitedReplica(New(client, WithPrefix("app2:")), 5)

	allowed := 0
	for i := 0; i < 5; i++ {
		for _, app := range []*gin.Engine{app1, app2} {
			if send(app, "GET", "/", "192.0.2.1") == http.StatusOK {
				allowed++
			}
		}
	}
	if allowed != 10 {
		t.Errorf("5 requests to each of two apps with their own prefix: %d allowed, want 10", allowed)
	}
}

// With Redis down, requests are allowed rather than failed.
func TestRedisDownFailsOpen(t *testing.T) {
	mr := miniredis.RunT(t)
	store := New(newClient(t, mr, &redis.Options{MaxRetries: -1, DialTimeout: 200 * time.Millisecond}))
	r := rateLimitedReplica(store, 1)
	mr.Close()

	for i := 0; i < 3; i++ {
		if code := send(r, "GET", "/", "192.0.2.1"); code != http.StatusOK {
			t.Errorf("request %d with Redis down: got %d, want 200", i+1, code)
		}
	}
}
