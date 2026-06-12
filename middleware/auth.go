package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/MUKE-coder/sentinel/v2/captcha"
	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthShield tracks failed login attempts per IP and per username,
// and enforces lockouts, credential stuffing detection, and the CAPTCHA
// challenge tier between "fine" and "locked out".
type AuthShield struct {
	config         sentinel.AuthShieldConfig
	store          storage.Store
	pipe           *pipeline.Pipeline
	mu             sync.Mutex
	ipFails        map[string]*failTracker
	userFails      map[string]*failTracker
	ipUsers        map[string]*stuffingTracker // credential stuffing detection
	captchaProvider captcha.Provider
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

// SetCAPTCHAProvider installs a CAPTCHA provider used for the
// suspicious-but-not-locked tier. When set, AuthShield requires a valid
// CAPTCHA token on login attempts from an IP that has crossed
// CAPTCHAThreshold failures but not yet MaxFailedAttempts.
func (as *AuthShield) SetCAPTCHAProvider(p captcha.Provider) {
	as.captchaProvider = p
}

// captchaRequired returns true if the given IP is currently in the CAPTCHA
// tier — past the soft threshold but not yet locked out.
func (as *AuthShield) captchaRequired(ip string) bool {
	if as.captchaProvider == nil || as.config.CAPTCHAThreshold <= 0 {
		return false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	t := as.ipFails[ip]
	if t == nil || t.locked {
		return false
	}
	t.attempts = pruneOld(t.attempts, time.Now(), as.config.LockoutDuration)
	return len(t.attempts) >= as.config.CAPTCHAThreshold
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

		// CAPTCHA tier — past the soft threshold but not yet locked. Real
		// users solve it in seconds; credential-stuffing bots typically can't.
		if as.captchaRequired(clientIP) {
			token := extractCAPTCHAToken(c, as.config.CAPTCHATokenField)
			if token == "" {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":            "CAPTCHA required",
					"code":             "AUTH_SHIELD_CAPTCHA_REQUIRED",
					"captcha_provider": as.captchaProvider.Name(),
				})
				return
			}
			if err := as.captchaProvider.Verify(c.Request.Context(), token, clientIP); err != nil {
				as.recordFailure(clientIP, c.GetString("sentinel_username"))
				as.emitThreat(clientIP, "", "BruteForce", "CAPTCHA verification failed")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":            "CAPTCHA verification failed",
					"code":             "AUTH_SHIELD_CAPTCHA_INVALID",
					"captcha_provider": as.captchaProvider.Name(),
				})
				return
			}
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

// AuthShieldStatus is a snapshot of one IP's current AuthShield state,
// returned by Snapshot for the dashboard.
type AuthShieldStatus struct {
	IP              string    `json:"ip"`
	FailedAttempts  int       `json:"failed_attempts"`
	Locked          bool      `json:"locked"`
	LockUntil       time.Time `json:"lock_until,omitempty"`
	CAPTCHARequired bool      `json:"captcha_required"`
}

// Snapshot returns the current per-IP AuthShield state — useful for the
// dashboard panel that visualizes who's in the lockout / CAPTCHA tier
// without having to chase ThreatEvents.
func (as *AuthShield) Snapshot() []AuthShieldStatus {
	as.mu.Lock()
	defer as.mu.Unlock()
	now := time.Now()
	captchaThreshold := as.config.CAPTCHAThreshold
	out := make([]AuthShieldStatus, 0, len(as.ipFails))
	for ip, t := range as.ipFails {
		t.attempts = pruneOld(t.attempts, now, as.config.LockoutDuration)
		if t.locked && now.After(t.lockUntil) {
			t.locked = false
		}
		row := AuthShieldStatus{
			IP:             ip,
			FailedAttempts: len(t.attempts),
			Locked:         t.locked,
		}
		if t.locked {
			row.LockUntil = t.lockUntil
		}
		if as.captchaProvider != nil && captchaThreshold > 0 && !t.locked && len(t.attempts) >= captchaThreshold {
			row.CAPTCHARequired = true
		}
		out = append(out, row)
	}
	return out
}

// CAPTCHAProviderName returns the configured CAPTCHA provider's name, or
// "" if none. Used by the dashboard to label the AuthShield panel.
func (as *AuthShield) CAPTCHAProviderName() string {
	if as.captchaProvider == nil {
		return ""
	}
	return as.captchaProvider.Name()
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

// extractCAPTCHAToken pulls the CAPTCHA token from the request. Checks
// (in order): the X-Captcha-Token header, the named form field, and the
// named field inside a JSON body. The body is consumed and restored so
// downstream handlers still see it.
func extractCAPTCHAToken(c *gin.Context, fieldName string) string {
	if v := c.GetHeader("X-Captcha-Token"); v != "" {
		return v
	}
	if fieldName == "" {
		fieldName = "captcha_token"
	}
	if v := c.PostForm(fieldName); v != "" {
		return v
	}
	if c.Request.Body == nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 64*1024))
	if err != nil {
		return ""
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	if v, ok := payload[fieldName].(string); ok {
		return v
	}
	return ""
}
