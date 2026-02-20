package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/MUKE-coder/sentinel/storage/memory"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupWAFRouter(mode sentinel.WAFMode, store *memory.Store, pipe *pipeline.Pipeline) *gin.Engine {
	r := gin.New()
	r.Use(WAFMiddleware(sentinel.WAFConfig{
		Enabled: true,
		Mode:    mode,
	}, store, pipe))
	r.GET("/api/products", func(c *gin.Context) {
		c.JSON(200, gin.H{"products": []string{"a", "b", "c"}})
	})
	r.POST("/api/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"token": "abc123"})
	})
	return r
}

func TestWAFBlocksSQLi(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	var threatCount atomic.Int64

	pipe.AddHandler(pipeline.HandlerFunc(func(ctx context.Context, event pipeline.Event) error {
		if event.Type == pipeline.EventThreat {
			threatCount.Add(1)
		}
		return nil
	}))
	pipe.Start(1)

	r := setupWAFRouter(sentinel.ModeBlock, store, pipe)

	// SQLi attempt
	req := httptest.NewRequest("GET", "/api/products?id=1'+OR+1=1--", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	pipe.Stop()

	if threatCount.Load() != 1 {
		t.Errorf("expected 1 threat event, got %d", threatCount.Load())
	}
}

func TestWAFBlocksXSS(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)

	r := setupWAFRouter(sentinel.ModeBlock, store, pipe)

	req := httptest.NewRequest("GET", "/api/products?q=<script>alert('xss')</script>", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	pipe.Stop()
}

func TestWAFAllowsLegitimateRequests(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)

	r := setupWAFRouter(sentinel.ModeBlock, store, pipe)

	req := httptest.NewRequest("GET", "/api/products?page=1&limit=20", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	pipe.Stop()
}

func TestWAFModeLog(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	var threatCount atomic.Int64

	pipe.AddHandler(pipeline.HandlerFunc(func(ctx context.Context, event pipeline.Event) error {
		if event.Type == pipeline.EventThreat {
			threatCount.Add(1)
		}
		return nil
	}))
	pipe.Start(1)

	r := setupWAFRouter(sentinel.ModeLog, store, pipe)

	// SQLi attempt — should log but NOT block
	req := httptest.NewRequest("GET", "/api/products?id=1'+OR+1=1--", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should pass through (not blocked)
	if w.Code != http.StatusOK {
		t.Errorf("ModeLog should not block; expected 200, got %d", w.Code)
	}

	pipe.Stop()

	if threatCount.Load() != 1 {
		t.Errorf("expected 1 threat event logged, got %d", threatCount.Load())
	}
}

func TestWAFModeChallenge(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)

	r := setupWAFRouter(sentinel.ModeChallenge, store, pipe)

	req := httptest.NewRequest("GET", "/api/products?id=1'+OR+1=1--", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "30" {
		t.Errorf("expected Retry-After header")
	}

	pipe.Stop()
}

func TestWAFBlockedIP(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)

	// Block an IP
	store.BlockIP(context.Background(), "192.168.1.100", "test block", nil)

	r := setupWAFRouter(sentinel.ModeBlock, store, pipe)

	req := httptest.NewRequest("GET", "/api/products?page=1", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked IP, got %d", w.Code)
	}

	pipe.Stop()
}

func TestWAFExcludedRoute(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)

	r := gin.New()
	r.Use(WAFMiddleware(sentinel.WAFConfig{
		Enabled:       true,
		Mode:          sentinel.ModeBlock,
		ExcludeRoutes: []string{"/health"},
	}, store, pipe))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Attack on excluded route should pass through
	req := httptest.NewRequest("GET", "/health?id=1'+OR+1=1--", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for excluded route, got %d", w.Code)
	}

	pipe.Stop()
}

func TestWAFDisabled(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)

	r := gin.New()
	r.Use(WAFMiddleware(sentinel.WAFConfig{
		Enabled: false,
		Mode:    sentinel.ModeBlock,
	}, store, pipe))
	r.GET("/api/products", func(c *gin.Context) {
		c.JSON(200, gin.H{"products": []string{"a"}})
	})

	req := httptest.NewRequest("GET", "/api/products?id=1'+OR+1=1--", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when WAF is disabled, got %d", w.Code)
	}

	pipe.Stop()
}

func TestWAFLatencyOverhead(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(10000)
	pipe.Start(2)

	r := setupWAFRouter(sentinel.ModeBlock, store, pipe)

	// Measure latency for legitimate requests
	iterations := 100
	start := time.Now()
	for i := 0; i < iterations; i++ {
		req := httptest.NewRequest("GET", "/api/products?page=1&limit=20", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
	elapsed := time.Since(start)
	avgLatency := elapsed / time.Duration(iterations)

	pipe.Stop()

	if avgLatency > 5*time.Millisecond {
		t.Errorf("WAF overhead too high: avg %v per request (should be <5ms)", avgLatency)
	}
	t.Logf("WAF avg latency overhead: %v per request", avgLatency)
}
