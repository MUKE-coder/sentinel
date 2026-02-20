package middleware

import (
	"net/http"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/MUKE-coder/sentinel/storage"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthShield tracks failed login attempts per IP and per username,
// and enforces lockouts and credential stuffing detection.
type AuthShield struct {
	config    sentinel.AuthShieldConfig
	store     storage.Store
	pipe      *pipeline.Pipeline
	mu        sync.Mutex
	ipFails   map[string]*failTracker
	userFails map[string]*failTracker
	ipUsers   map[string]*stuffingTracker // credential stuffing detection
}

type failTracker struct {
	attempts []time.Time
	locked   bool
	lockUntil time.Time
}

type stuffingTracker struct {
	usernames map[string]bool
	window    []time.Time
}

// NewAuthShield creates a new authentication shield middleware.
func NewAuthShield(config sentinel.AuthShieldConfig, store storage.Store, pipe *pipeline.Pipeline) *AuthShield {
	as := &AuthShield{
		config:    config,
		store:     store,
		pipe:      pipe,
		ipFails:   make(map[string]*failTracker),
		userFails: make(map[string]*failTracker),
		ipUsers:   make(map[string]*stuffingTracker),
	}
	return as
}

// Middleware returns a Gin middleware that wraps the configured login route.
// It observes responses: 2xx = success, 4xx = failure, and acts accordingly.
func (as *AuthShield) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !as.config.Enabled {
			c.Next()
			return
		}

		// Only intercept the login route
		if c.Request.URL.Path != as.config.LoginRoute {
			c.Next()
			return
		}

		// Only intercept POST requests to login
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		clientIP := extractClientIP(c)

		// Check if IP is locked out
		if as.isIPLocked(clientIP) {
			as.emitThreat(clientIP, "", "BruteForce", "IP locked out due to too many failed attempts")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many failed login attempts. Please try again later.",
				"code":  "AUTH_SHIELD_LOCKED",
			})
			return
		}

		// Use a response writer wrapper to capture status code
		rw := &authResponseWriter{ResponseWriter: c.Writer, statusCode: 200}
		c.Writer = rw

		c.Next()

		// After handler runs, observe the response
		statusCode := rw.statusCode
		username := c.GetString("sentinel_username")

		if statusCode >= 200 && statusCode < 300 {
			// Successful login — reset IP failures
			as.recordSuccess(clientIP, username)
		} else if statusCode >= 400 && statusCode < 500 {
			// Failed login attempt
			as.recordFailure(clientIP, username)
		}
	}
}

// isIPLocked checks if the IP is currently locked out.
func (as *AuthShield) isIPLocked(ip string) bool {
	as.mu.Lock()
	defer as.mu.Unlock()

	tracker := as.ipFails[ip]
	if tracker == nil {
		return false
	}

	if tracker.locked {
		if time.Now().After(tracker.lockUntil) {
			// Lockout expired
			tracker.locked = false
			tracker.attempts = nil
			return false
		}
		return true
	}
	return false
}

// IsUserLocked checks if a specific username is locked.
func (as *AuthShield) IsUserLocked(username string) bool {
	as.mu.Lock()
	defer as.mu.Unlock()

	tracker := as.userFails[username]
	if tracker == nil {
		return false
	}
	if tracker.locked {
		if time.Now().After(tracker.lockUntil) {
			tracker.locked = false
			tracker.attempts = nil
			return false
		}
		return true
	}
	return false
}

// UnblockUser removes the lockout on a specific username.
func (as *AuthShield) UnblockUser(username string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	delete(as.userFails, username)
}

// recordFailure records a failed login attempt and enforces lockouts.
func (as *AuthShield) recordFailure(ip, username string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	now := time.Now()
	window := as.config.LockoutDuration

	// Track IP failures
	ipTracker := as.ipFails[ip]
	if ipTracker == nil {
		ipTracker = &failTracker{}
		as.ipFails[ip] = ipTracker
	}
	ipTracker.attempts = pruneOld(ipTracker.attempts, now, window)
	ipTracker.attempts = append(ipTracker.attempts, now)

	if len(ipTracker.attempts) >= as.config.MaxFailedAttempts {
		ipTracker.locked = true
		ipTracker.lockUntil = now.Add(window)
	}

	// Track username failures
	if username != "" {
		userTracker := as.userFails[username]
		if userTracker == nil {
			userTracker = &failTracker{}
			as.userFails[username] = userTracker
		}
		userTracker.attempts = pruneOld(userTracker.attempts, now, window)
		userTracker.attempts = append(userTracker.attempts, now)

		if len(userTracker.attempts) >= as.config.MaxFailedAttempts {
			userTracker.locked = true
			userTracker.lockUntil = now.Add(window)
		}
	}

	// Credential stuffing detection
	if as.config.CredentialStuffingDetection && username != "" {
		st := as.ipUsers[ip]
		if st == nil {
			st = &stuffingTracker{usernames: make(map[string]bool)}
			as.ipUsers[ip] = st
		}
		st.window = pruneOld(st.window, now, window)
		st.window = append(st.window, now)
		st.usernames[username] = true

		if len(st.usernames) > 10 {
			// Credential stuffing detected — emit threat outside lock
			go as.emitThreat(ip, username, "CredentialStuffing",
				"Same IP tried >10 different usernames")
		}
	}
}

// recordSuccess resets failure counters on successful login.
func (as *AuthShield) recordSuccess(ip, username string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	delete(as.ipFails, ip)
	if username != "" {
		delete(as.userFails, username)
	}
	delete(as.ipUsers, ip)
}

// emitThreat sends a ThreatEvent to the pipeline.
func (as *AuthShield) emitThreat(ip, username, threatType, detail string) {
	if as.pipe == nil {
		return
	}
	te := &sentinel.ThreatEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		IP:          ip,
		Method:      "POST",
		Path:        as.config.LoginRoute,
		ThreatTypes: []string{threatType},
		Severity:    sentinel.SeverityHigh,
		Confidence:  90,
		Blocked:     true,
		Evidence: []sentinel.Evidence{
			{
				Pattern:  threatType,
				Matched:  detail,
				Location: "auth_shield",
			},
		},
	}
	as.pipe.EmitThreat(te)
}

// GetIPStatus returns the current failure count and lock status for an IP.
func (as *AuthShield) GetIPStatus(ip string) (attempts int, locked bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	tracker := as.ipFails[ip]
	if tracker == nil {
		return 0, false
	}
	tracker.attempts = pruneOld(tracker.attempts, time.Now(), as.config.LockoutDuration)
	if tracker.locked && time.Now().After(tracker.lockUntil) {
		tracker.locked = false
	}
	return len(tracker.attempts), tracker.locked
}

// pruneOld removes timestamps older than the window.
func pruneOld(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	var result []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			result = append(result, t)
		}
	}
	return result
}

// authResponseWriter wraps gin.ResponseWriter to capture the status code.
type authResponseWriter struct {
	gin.ResponseWriter
	statusCode int
}

func (w *authResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
