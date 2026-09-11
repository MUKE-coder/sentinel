package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/gin-gonic/gin"
)

// fakeClock drives a limiter's notion of now.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestLimiter(t *testing.T, strategy sentinel.RateLimitStrategy) (*RateLimiter, *fakeClock) {
	t.Helper()
	rl := NewRateLimiter()
	t.Cleanup(rl.Stop)
	rl.SetStrategy(strategy)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	rl.now = clock.now
	return rl, clock
}

// allowN makes n requests and returns how many were allowed.
func allowN(rl *RateLimiter, n, limit int, window time.Duration) int {
	allowed := 0
	for i := 0; i < n; i++ {
		if rl.check("k", limit, window) {
			allowed++
		}
	}
	return allowed
}

func TestFixedWindow_ResetsAtBoundary(t *testing.T) {
	rl, clock := newTestLimiter(t, sentinel.FixedWindow)

	if got := allowN(rl, 11, 10, time.Minute); got != 10 {
		t.Fatalf("first window: allowed %d, want 10", got)
	}
	clock.advance(time.Minute)
	if got := allowN(rl, 10, 10, time.Minute); got != 10 {
		t.Errorf("a fixed window resets completely at the boundary: allowed %d, want 10", got)
	}
}

// TestSlidingWindow_SmoothsBoundary is the reason sliding is the default: a
// fixed window lets 2x the limit through in a moment either side of a
// boundary; a sliding window does not.
func TestSlidingWindow_SmoothsBoundary(t *testing.T) {
	rl, clock := newTestLimiter(t, sentinel.SlidingWindow)

	if got := allowN(rl, 11, 10, time.Minute); got != 10 {
		t.Fatalf("first window: allowed %d, want 10", got)
	}
	clock.advance(time.Minute) // start of next window: all 10 still inside the sliding window
	if got := allowN(rl, 10, 10, time.Minute); got != 0 {
		t.Errorf("at the boundary: allowed %d, want 0", got)
	}
	clock.advance(30 * time.Second) // half the previous window has slid out
	if got := allowN(rl, 10, 10, time.Minute); got != 5 {
		t.Errorf("half a window later: allowed %d, want 5", got)
	}
	clock.advance(2 * time.Minute) // well past both windows
	if got := allowN(rl, 10, 10, time.Minute); got != 10 {
		t.Errorf("after two idle windows: allowed %d, want 10", got)
	}
}

func TestTokenBucket_RefillsGradually(t *testing.T) {
	rl, clock := newTestLimiter(t, sentinel.TokenBucket)

	if got := allowN(rl, 11, 10, time.Minute); got != 10 {
		t.Fatalf("initial burst: allowed %d, want 10", got)
	}
	clock.advance(6 * time.Second) // 10 per minute = one token every 6s
	if got := allowN(rl, 3, 10, time.Minute); got != 1 {
		t.Errorf("after 6s: allowed %d, want 1", got)
	}
	clock.advance(10 * time.Minute) // refills to capacity, no further
	if got := allowN(rl, 11, 10, time.Minute); got != 10 {
		t.Errorf("after a long idle: allowed %d, want 10 (capacity)", got)
	}
}

func TestSetStrategy_UnknownFallsBackToSliding(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	rl.SetStrategy("leaky_bucket")
	if rl.Strategy() != sentinel.SlidingWindow {
		t.Errorf("unknown strategy should fall back to sliding_window, got %s", rl.Strategy())
	}
}

func TestRemaining_TracksStrategy(t *testing.T) {
	rl, _ := newTestLimiter(t, sentinel.TokenBucket)
	allowN(rl, 4, 10, time.Minute)
	if got := rl.remaining("k", 10); got != 6 {
		t.Errorf("token bucket remaining: got %d, want 6", got)
	}
}

// TestRouteLimits_ChangeWhileRunning pins the fix for dashboard edits that
// never reached the middleware: route limits used to be compiled once at
// mount, so PUT /rate-limits changed nothing that was enforced.
func TestRouteLimits_ChangeWhileRunning(t *testing.T) {
	limiter := NewRateLimiter()
	defer limiter.Stop()

	r := gin.New()
	r.Use(RateLimitMiddleware(sentinel.RateLimitConfig{
		Enabled: true,
		ByRoute: map[string]sentinel.Limit{"/api/login": {Requests: 2, Window: time.Minute}},
	}, limiter, nil))
	r.POST("/api/login", func(c *gin.Context) { c.Status(http.StatusOK) })

	login := func() int {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/api/login", nil))
		return w.Code
	}
	login()
	login()
	if code := login(); code != http.StatusTooManyRequests {
		t.Fatalf("3rd login under a 2/min limit: got %d, want 429", code)
	}

	limiter.SetRouteLimits(map[string]sentinel.Limit{"/api/login": {Requests: 5, Window: time.Minute}})
	if code := login(); code != http.StatusOK {
		t.Errorf("after raising the limit to 5: got %d, want 200", code)
	}

	limiter.SetRouteLimits(nil)
	for i := 0; i < 10; i++ {
		if code := login(); code != http.StatusOK {
			t.Fatalf("with the route limit removed: got %d, want 200", code)
		}
	}
	if len(limiter.RouteLimits()) != 0 {
		t.Errorf("RouteLimits should be empty, got %v", limiter.RouteLimits())
	}
}
