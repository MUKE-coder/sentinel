package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/middleware"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware creates JWT authentication middleware for API routes.
func AuthMiddleware(secretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
				"code":  "UNAUTHORIZED",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
				"code":  "UNAUTHORIZED",
			})
			return
		}

		tokenStr := parts[1]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secretKey), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
				"code":  "UNAUTHORIZED",
			})
			return
		}

		c.Next()
	}
}

// GenerateToken creates a JWT token for dashboard access.
func GenerateToken(secretKey string) (string, error) {
	claims := jwt.MapClaims{
		"iss": "sentinel",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

// Dashboard login budget: ten attempts per address per quarter hour. Enough
// for someone who mistypes, little enough that guessing the dashboard
// password is pointless.
const (
	loginAttemptLimit  = 10
	loginAttemptWindow = 15 * time.Minute
	loginCounterPrefix = "api:login:"
)

// LoginRateLimiter bounds dashboard login attempts per client address.
//
// The counters live in a sentinel.CounterStore. With the per-process default
// each replica allowed its own ten attempts, so an attacker behind a load
// balancer with N replicas got 10N guesses at the dashboard password (issue
// #18). Mount passes the shared store when Config.Counters is set, and then
// the budget holds across every replica.
type LoginRateLimiter struct {
	mu       sync.Mutex
	counters sentinel.CounterStore
	ownStore *middleware.MemoryCounterStore // closed when SetCounters replaces it
	now      func() time.Time
	lastLog  time.Time
}

// NewLoginRateLimiter creates a login rate limiter with per-process
// counters.
func NewLoginRateLimiter() *LoginRateLimiter {
	mem := middleware.NewMemoryCounterStore()
	return &LoginRateLimiter{counters: mem, ownStore: mem, now: time.Now}
}

// SetCounters moves the login budget onto cs. Give every replica the same
// shared store and ten attempts means ten in total, not ten each. Call it
// before serving requests.
func (l *LoginRateLimiter) SetCounters(cs sentinel.CounterStore) {
	if cs == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ownStore != nil {
		l.ownStore.Close()
		l.ownStore = nil
	}
	l.counters = cs
}

// Check counts one attempt from ip and reports whether it is within the
// budget.
func (l *LoginRateLimiter) Check(ip string) bool {
	l.mu.Lock()
	counters, now := l.counters, l.now()
	l.mu.Unlock()

	ok, err := counters.Take(context.Background(), loginCounterPrefix+ip,
		loginAttemptLimit, loginAttemptWindow, sentinel.FixedWindow, now)
	if err != nil {
		// Fail open: a counter-store outage must not lock everyone out of
		// the dashboard. The dashboard password is still required.
		l.logThrottled("login rate limiter counter store: %v (attempts allowed until it recovers)", err)
		return true
	}
	return ok
}

// RecordFailure records a failed login attempt.
func (l *LoginRateLimiter) RecordFailure(ip string) {
	// Already counted in Check: the budget covers attempts, not just
	// failures, so a flood of guesses cannot outrun it.
}

// logThrottled logs at most once a minute, so a sustained store outage
// doesn't fill the log.
func (l *LoginRateLimiter) logThrottled(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.now(); now.Sub(l.lastLog) >= time.Minute {
		l.lastLog = now
		log.Printf("[sentinel] "+format, args...)
	}
}
