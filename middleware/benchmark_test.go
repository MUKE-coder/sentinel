package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/MUKE-coder/sentinel/storage/memory"
	"github.com/gin-gonic/gin"
)

func BenchmarkRateLimiter_Check(b *testing.B) {
	rl := NewRateLimiter()
	defer rl.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.check("bench:192.168.1.1", 1000, time.Minute)
	}
}

func BenchmarkRateLimiter_CheckParallel(b *testing.B) {
	rl := NewRateLimiter()
	defer rl.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.check("bench:parallel", 100000, time.Minute)
		}
	})
}

func BenchmarkRateLimiter_MultipleKeys(b *testing.B) {
	rl := NewRateLimiter()
	defer rl.Stop()

	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = "bench:" + string(rune(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.check(keys[i%len(keys)], 1000, time.Minute)
	}
}

func BenchmarkWAFMiddleware_CleanRequest(b *testing.B) {
	gin.SetMode(gin.TestMode)
	store := memory.New()
	pipe := pipeline.New(10000)
	pipe.Start(1)
	defer pipe.Stop()

	r := gin.New()
	r.Use(WAFMiddleware(sentinel.WAFConfig{
		Enabled: true,
		Mode:    sentinel.ModeBlock,
	}, store, pipe, nil))
	r.GET("/api/users", func(c *gin.Context) {
		c.String(200, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users?page=1&limit=20", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}

func BenchmarkWAFMiddleware_MaliciousRequest(b *testing.B) {
	gin.SetMode(gin.TestMode)
	store := memory.New()
	pipe := pipeline.New(10000)
	pipe.Start(1)
	defer pipe.Stop()

	r := gin.New()
	r.Use(WAFMiddleware(sentinel.WAFConfig{
		Enabled: true,
		Mode:    sentinel.ModeBlock,
	}, store, pipe, nil))
	r.GET("/api/users", func(c *gin.Context) {
		c.String(200, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users?id=1'+OR+'1'='1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}

func BenchmarkHeadersMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(HeadersMiddleware(sentinel.HeaderConfig{
		StrictTransportSecurity: true,
		ContentSecurityPolicy:   "default-src 'self'",
	}))
	r.GET("/api/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}
