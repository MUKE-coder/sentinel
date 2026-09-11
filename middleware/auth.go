package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
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
// challenge tier between "fine" and "locked out". Its counters live in a
// sentinel.CounterStore — in memory by default; SetCounters shares them
// across replicas.
type AuthShield struct {
	config          sentinel.AuthShieldConfig
	store           storage.Store
	pipe            *pipeline.Pipeline
	counters        sentinel.CounterStore
	ownCounters     *MemoryCounterStore // closed when SetCounters replaces it
	now             func() time.Time
	errLog          rateLimitedLog
	captchaProvider captcha.Provider
}

// Counter keys. A failure is recorded as a unique attempt ID in a set, so
// each attempt counts once however many replicas share the store.
const (
	authFailIPPrefix   = "as:fail:ip:"
	authFailUserPrefix = "as:fail:user:"
	authLockIPPrefix   = "as:lock:ip:"
	authLockUserPrefix = "as:lock:user:"
	authStuffingPrefix = "as:stuff:"
)

// NewAuthShield creates a new authentication shield middleware.
func NewAuthShield(config sentinel.AuthShieldConfig, store storage.Store, pipe *pipeline.Pipeline) *AuthShield {
	mem := NewMemoryCounterStore()
	return &AuthShield{
		config:      config,
		store:       store,
		pipe:        pipe,
		counters:    mem,
		ownCounters: mem,
		now:         time.Now,
	}
}

// SetCounters moves AuthShield's failure counts and lockouts to cs. Pass a
// shared store (redisstore) so a lockout on one replica holds on all of
// them. Call it before serving requests.
func (as *AuthShield) SetCounters(cs sentinel.CounterStore) {
	if cs == nil {
		return
	}
	if as.ownCounters != nil {
		as.ownCounters.Close()
		as.ownCounters = nil
	}
	as.counters = cs
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
	now := as.now()
	if !as.lockedUntil(authLockIPPrefix+ip, now).IsZero() {
		return false
	}
	return as.failures(authFailIPPrefix+ip, now) >= as.config.CAPTCHAThreshold
}

// Middleware returns a Gin middleware that wraps the configured login route.
// It observes responses: 2xx = success, 4xx = failure, and acts accordingly.
func (as *AuthShield) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !as.config.Enabled {
			c.Next()
			return
		}

		// Only intercept the login route. Match the registered route pattern
		// (FullPath) as well as the raw URL path: an upstream middleware that
		// rewrites URL.Path would otherwise disable AuthShield entirely and
		// silently — brute-force protection just stops existing (issue #8).
		// FullPath also makes parameterized login routes ("/login/:tenant")
		// configurable by their registered pattern.
		if c.Request.URL.Path != as.config.LoginRoute && c.FullPath() != as.config.LoginRoute {
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
			as.emitLoginAudit(c, clientIP, username, true, "")
		} else if statusCode >= 400 && statusCode < 500 {
			// Failed login attempt
			as.recordFailure(clientIP, username)
			as.emitLoginAudit(c, clientIP, username, false, http.StatusText(statusCode))
		}
	}
}

// emitLoginAudit records a login attempt that reached the login handler as
// an audit entry under sentinel.AuditResourceAuth — the evidence the PCI-DSS
// report's authentication section counts. Attempts AuthShield rejected
// before the handler (lockout, CAPTCHA) are recorded as threat events.
func (as *AuthShield) emitLoginAudit(c *gin.Context, ip, username string, success bool, errText string) {
	if as.pipe == nil {
		return
	}
	as.pipe.EmitAudit(&sentinel.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		UserID:     clipField(username, 128),
		Action:     "LOGIN",
		Resource:   sentinel.AuditResourceAuth,
		ResourceID: as.config.LoginRoute,
		IP:         ip,
		UserAgent:  c.Request.UserAgent(),
		Success:    success,
		Error:      errText,
	})
}

// clipField bounds a client-supplied string before it is stored.
func clipField(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// lockedUntil returns the lockout deadline stored at key. A store error
// counts as not locked — AuthShield fails open rather than locking every
// user out — and is logged.
func (as *AuthShield) lockedUntil(key string, now time.Time) time.Time {
	until, err := as.counters.Until(context.Background(), key, now)
	if err != nil {
		as.errLog.log("AuthShield counter store: %v (lockouts not enforced until it recovers)", err)
		return time.Time{}
	}
	return until
}

// failures counts the failed attempts at key within the lockout window.
func (as *AuthShield) failures(key string, now time.Time) int {
	n, err := as.counters.Count(context.Background(), key, as.config.LockoutDuration, now)
	if err != nil {
		as.errLog.log("AuthShield counter store: %v", err)
		return 0
	}
	return n
}

// isIPLocked checks if the IP is currently locked out.
func (as *AuthShield) isIPLocked(ip string) bool {
	return !as.lockedUntil(authLockIPPrefix+ip, as.now()).IsZero()
}

// IsUserLocked checks if a specific username is locked.
func (as *AuthShield) IsUserLocked(username string) bool {
	return !as.lockedUntil(authLockUserPrefix+username, as.now()).IsZero()
}

// UnblockUser removes the lockout on a specific username.
func (as *AuthShield) UnblockUser(username string) {
	if _, err := as.counters.Delete(context.Background(), authFailUserPrefix+username, authLockUserPrefix+username); err != nil {
		as.errLog.log("AuthShield counter store: %v", err)
	}
}

// recordFailure records a failed login attempt and enforces lockouts.
func (as *AuthShield) recordFailure(ip, username string) {
	ctx := context.Background()
	now := as.now()
	window := as.config.LockoutDuration
	attempt := uuid.NewString()

	// fail counts the attempt against key and sets the lockout at lockKey
	// once MaxFailedAttempts land within the window.
	fail := func(key, lockKey string) {
		n, err := as.counters.Record(ctx, key, attempt, window, now)
		if err != nil {
			as.errLog.log("AuthShield counter store: %v (failed logins not counted until it recovers)", err)
			return
		}
		if n >= as.config.MaxFailedAttempts {
			if err := as.counters.SetUntil(ctx, lockKey, now.Add(window)); err != nil {
				as.errLog.log("AuthShield counter store: %v", err)
			}
		}
	}
	fail(authFailIPPrefix+ip, authLockIPPrefix+ip)
	if username != "" {
		fail(authFailUserPrefix+username, authLockUserPrefix+username)
	}

	// Credential stuffing: many different usernames from one IP within the
	// window.
	if as.config.CredentialStuffingDetection && username != "" {
		n, err := as.counters.Record(ctx, authStuffingPrefix+ip, username, window, now)
		if err == nil && n > 10 {
			go as.emitThreat(ip, username, "CredentialStuffing",
				"Same IP tried >10 different usernames")
		}
	}
}

// recordSuccess resets failure counters on successful login.
func (as *AuthShield) recordSuccess(ip, username string) {
	keys := []string{authFailIPPrefix + ip, authLockIPPrefix + ip, authStuffingPrefix + ip}
	if username != "" {
		keys = append(keys, authFailUserPrefix+username, authLockUserPrefix+username)
	}
	if _, err := as.counters.Delete(context.Background(), keys...); err != nil {
		as.errLog.log("AuthShield counter store: %v", err)
	}
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
// without having to chase ThreatEvents. With a shared store it covers every
// replica.
func (as *AuthShield) Snapshot() []AuthShieldStatus {
	ctx := context.Background()
	now := as.now()
	ips := make(map[string]bool)
	for _, prefix := range []string{authFailIPPrefix, authLockIPPrefix} {
		keys, err := as.counters.Keys(ctx, prefix)
		if err != nil {
			as.errLog.log("AuthShield counter store: %v", err)
			continue
		}
		for _, k := range keys {
			ips[strings.TrimPrefix(k, prefix)] = true
		}
	}

	out := make([]AuthShieldStatus, 0, len(ips))
	for ip := range ips {
		attempts := as.failures(authFailIPPrefix+ip, now)
		until := as.lockedUntil(authLockIPPrefix+ip, now)
		if attempts == 0 && until.IsZero() {
			continue
		}
		row := AuthShieldStatus{
			IP:             ip,
			FailedAttempts: attempts,
			Locked:         !until.IsZero(),
			LockUntil:      until,
		}
		if as.captchaProvider != nil && as.config.CAPTCHAThreshold > 0 && !row.Locked && attempts >= as.config.CAPTCHAThreshold {
			row.CAPTCHARequired = true
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
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
	now := as.now()
	return as.failures(authFailIPPrefix+ip, now), !as.lockedUntil(authLockIPPrefix+ip, now).IsZero()
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
