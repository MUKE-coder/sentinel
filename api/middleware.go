package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

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

// LoginRateLimiter tracks failed login attempts per IP.
type LoginRateLimiter struct {
	mu       sync.RWMutex
	attempts map[string]*loginAttempt
}

type loginAttempt struct {
	count     int
	firstSeen time.Time
}

// NewLoginRateLimiter creates a new login rate limiter.
func NewLoginRateLimiter() *LoginRateLimiter {
	return &LoginRateLimiter{
		attempts: make(map[string]*loginAttempt),
	}
}

// Check returns true if login attempt is allowed, false if rate limited.
func (l *LoginRateLimiter) Check(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	attempt, exists := l.attempts[ip]

	if !exists || now.Sub(attempt.firstSeen) > 15*time.Minute {
		l.attempts[ip] = &loginAttempt{count: 1, firstSeen: now}
		return true
	}

	attempt.count++
	return attempt.count <= 10 // Allow 10 attempts per 15 minutes
}

// RecordFailure records a failed login attempt.
func (l *LoginRateLimiter) RecordFailure(ip string) {
	// Already counted in Check
}
