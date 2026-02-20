package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/gin-gonic/gin"
)

func TestRateLimitByIP(t *testing.T) {
	limiter := NewRateLimiter()
	defer limiter.Stop()

	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	r := gin.New()
	r.Use(RateLimitMiddleware(sentinel.RateLimitConfig{
		Enabled: true,
		ByIP:    &sentinel.Limit{Requests: 5, Window: time.Minute},
	}, limiter, pipe))
	r.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// First 5 requests should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("request 6: expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

func TestRateLimitConcurrent(t *testing.T) {
	limiter := NewRateLimiter()
	defer limiter.Stop()

	pipe := pipeline.New(1000)
	pipe.Start(2)
	defer pipe.Stop()

	r := gin.New()
	r.Use(RateLimitMiddleware(sentinel.RateLimitConfig{
		Enabled: true,
		ByIP:    &sentinel.Limit{Requests: 5, Window: time.Minute},
	}, limiter, pipe))
	r.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	var succeeded atomic.Int64
	var rateLimited atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/api/test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				succeeded.Add(1)
			} else if w.Code == http.StatusTooManyRequests {
				rateLimited.Add(1)
			}
		}()
	}

	wg.Wait()

	if succeeded.Load() != 5 {
		t.Errorf("expected exactly 5 successes, got %d", succeeded.Load())
	}
	if rateLimited.Load() != 95 {
		t.Errorf("expected 95 rate limited, got %d", rateLimited.Load())
	}
}

func TestRateLimitDisabled(t *testing.T) {
	limiter := NewRateLimiter()
	defer limiter.Stop()

	r := gin.New()
	r.Use(RateLimitMiddleware(sentinel.RateLimitConfig{
		Enabled: false,
		ByIP:    &sentinel.Limit{Requests: 1, Window: time.Minute},
	}, limiter, nil))
	r.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 when disabled, got %d", w.Code)
		}
	}
}

func TestRateLimitPerRoute(t *testing.T) {
	limiter := NewRateLimiter()
	defer limiter.Stop()

	r := gin.New()
	r.Use(RateLimitMiddleware(sentinel.RateLimitConfig{
		Enabled: true,
		ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
		ByRoute: map[string]sentinel.Limit{
			"/api/login": {Requests: 3, Window: time.Minute},
		},
	}, limiter, nil))
	r.POST("/api/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"token": "abc"})
	})
	r.GET("/api/products", func(c *gin.Context) {
		c.JSON(200, gin.H{"products": []string{}})
	})

	// Login: 3 allowed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/api/login", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("login %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 4th login: blocked
	req := httptest.NewRequest("POST", "/api/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("login 4: expected 429, got %d", w.Code)
	}

	// Products: still works (different route)
	req = httptest.NewRequest("GET", "/api/products", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("products: expected 200, got %d", w.Code)
	}
}
