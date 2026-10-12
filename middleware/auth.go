package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
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
	exemptIPs       *IPMatcher
}

// Counter keys. A failure is recorded as a unique attempt ID in a set, so
// each attempt counts once however many replicas share the store.
const (
	authFailIPPrefix   = "as:fail:ip:"
	authFailUserPrefix = "as:fail:user:"
	authFailPairPrefix = "as:fail:pair:"
	authLockIPPrefix   = "as:lock:ip:"
	authLockUserPrefix = "as:lock:user:"
	authLockPairPrefix = "as:lock:pair:"
	authCooldownPrefix = "as:cool:ip:"
	authStuffingPrefix = "as:stuff:"
)

// pairKey identifies one account's attempts from one address. The account is
// normalised so "Admin" and "admin" share a lockout.
func pairKey(ip, account string) string { return ip + "|" + normalizeAccount(account) }

// normalizeAccount folds an account name for use as a counter key. The value
// stored in the audit log is the one the application reported, untouched.
func normalizeAccount(account string) string {
	return clipField(strings.ToLower(strings.TrimSpace(account)), 128)
}

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
		exemptIPs:   NewIPMatcher(config.ExemptIPs),
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

		// The account is read from the request so a lockout can be keyed on
		// it before the login handler runs. The handler's own
		// c.Set("sentinel_username") is authoritative afterwards.
		account := as.extractAccount(c)

		// Check whatever the configured key locks. By default that is the
		// (address, account) pair: locking the address alone barred everyone
		// sharing it, which behind NAT or CGNAT is an office, a campus, or a
		// mobile carrier (#36).
		if locked, detail := as.locked(clientIP, account); locked {
			as.emitThreat(clientIP, account, "BruteForce", detail)
			if retry := as.retryAfter(clientIP, account); retry > 0 {
				c.Header("Retry-After", strconv.Itoa(retry))
			}
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
				as.recordFailure(clientIP, account)
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
		if username == "" {
			// The application didn't report one, so use what the request
			// carried: without an account there is no pair to lock.
			username = account
		}

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

// isIPLocked reports whether the address itself is locked. Only
// LockoutIP sets that lock.
func (as *AuthShield) isIPLocked(ip string) bool {
	return !as.lockedUntil(authLockIPPrefix+ip, as.now()).IsZero()
}

// lockoutKey is the configured key, defaulting to the pair. An unrecognised
// value behaves as the pair rather than as the address, so a typo cannot
// turn on collective lockouts; ValidateConfig reports it.
func (as *AuthShield) lockoutKey() sentinel.AuthShieldLockoutKey {
	if sentinel.ValidAuthShieldLockoutKey(as.config.LockoutKey) {
		return as.config.LockoutKey
	}
	return sentinel.LockoutPair
}

// locked reports whether this attempt is barred, and why, for the audit
// trail and the threat event.
func (as *AuthShield) locked(ip, account string) (bool, string) {
	now := as.now()

	// The address throttle runs under every lockout key: it is what catches
	// one machine working through many accounts, which a per-account
	// lockout never sees. It is short on purpose — an address may be
	// thousands of people.
	if until := as.lockedUntil(authCooldownPrefix+ip, now); !until.IsZero() {
		return true, "too many failed sign-ins from this address in a short time"
	}

	// The address lock is set either by LockoutKey "ip" or by the
	// unknown-account fallback below, so it applies whatever the key is.
	if !as.lockedUntil(authLockIPPrefix+ip, now).IsZero() {
		return true, "address locked out after too many failed sign-ins"
	}

	switch as.lockoutKey() {
	case sentinel.LockoutIP:
		// Already checked above.
	case sentinel.LockoutAccount:
		if account != "" && !as.lockedUntil(authLockUserPrefix+normalizeAccount(account), now).IsZero() {
			return true, "account locked out after too many failed sign-ins"
		}
	default: // pair
		if account != "" && !as.lockedUntil(authLockPairPrefix+pairKey(ip, account), now).IsZero() {
			return true, "this account is locked out from this address after too many failed sign-ins"
		}
	}
	return false, ""
}

// lockAddressFallback locks the address when no account could be
// determined. A pair or account lockout has nothing to key on then, and
// doing nothing would leave an application whose login handler reports no
// username with no lockout at all — so the address is what is left, which is
// what AuthShield did for every application before v2.7.0. Set
// UsernameFields, or call c.Set("sentinel_username") in the login handler,
// to get account-scoped lockouts. An exempt address is never locked.
func (as *AuthShield) lockAddressFallback(ip string, addressFailures int, lock func(string)) {
	if addressFailures >= as.config.MaxFailedAttempts && !as.exemptIPs.Matches(ip) {
		lock(authLockIPPrefix + ip)
	}
}

// retryAfter is how many seconds until the refusal that applies to this
// attempt lifts, for the Retry-After header. 0 when it cannot be worked out.
func (as *AuthShield) retryAfter(ip, account string) int {
	now := as.now()
	keys := []string{authCooldownPrefix + ip, authLockIPPrefix + ip}
	if account != "" {
		keys = append(keys,
			authLockPairPrefix+pairKey(ip, account),
			authLockUserPrefix+normalizeAccount(account))
	}
	var soonest time.Time
	for _, key := range keys {
		until := as.lockedUntil(key, now)
		if until.IsZero() {
			continue
		}
		if soonest.IsZero() || until.Before(soonest) {
			soonest = until
		}
	}
	if soonest.IsZero() {
		return 0
	}
	if seconds := int(soonest.Sub(now).Seconds()) + 1; seconds > 0 {
		return seconds
	}
	return 0
}

// extractAccount reads the account name from the request, trying each of
// UsernameFields in turn as a form value and then as a JSON field. The body
// is restored, so the login handler still reads it.
func (as *AuthShield) extractAccount(c *gin.Context) string {
	fields := as.config.UsernameFields
	if len(fields) == 0 {
		fields = sentinel.DefaultUsernameFields
	}
	for _, field := range fields {
		if v := c.PostForm(field); v != "" {
			return clipField(v, 128)
		}
	}
	payload := peekJSONBody(c)
	for _, field := range fields {
		if v, ok := payload[field].(string); ok && v != "" {
			return clipField(v, 128)
		}
	}
	return ""
}

// IsUserLocked checks if a specific username is locked.
func (as *AuthShield) IsUserLocked(username string) bool {
	return !as.lockedUntil(authLockUserPrefix+normalizeAccount(username), as.now()).IsZero()
}

// UnblockUser removes the lockout on a specific username.
func (as *AuthShield) UnblockUser(username string) {
	account := normalizeAccount(username)
	if _, err := as.counters.Delete(context.Background(), authFailUserPrefix+account, authLockUserPrefix+account); err != nil {
		as.errLog.log("AuthShield counter store: %v", err)
	}
}

// recordFailure records a failed login attempt and enforces lockouts.
func (as *AuthShield) recordFailure(ip, username string) {
	ctx := context.Background()
	now := as.now()
	window := as.config.LockoutDuration
	attempt := uuid.NewString()

	count := func(key string) int {
		n, err := as.counters.Record(ctx, key, attempt, window, now)
		if err != nil {
			as.errLog.log("AuthShield counter store: %v (failed logins not counted until it recovers)", err)
			return 0
		}
		return n
	}
	lockFor := func(key string, d time.Duration) {
		if err := as.counters.SetUntil(ctx, key, now.Add(d)); err != nil {
			as.errLog.log("AuthShield counter store: %v", err)
		}
	}
	lock := func(key string) { lockFor(key, window) }

	// Count per address and per account whatever the lockout key is: the
	// CAPTCHA tier and credential-stuffing detection both read the address
	// counter, and the dashboard shows both numbers.
	addressFailures := count(authFailIPPrefix + ip)
	accountFailures := 0
	account := normalizeAccount(username)
	if account != "" {
		accountFailures = count(authFailUserPrefix + account)
	}

	// One address, many accounts: refuse everything from it for a short
	// while. The per-account lockout cannot see that attack, and a long ban
	// would land on everyone behind the address.
	if budget := as.config.AddressFailureBudget; budget > 0 && addressFailures >= budget && as.config.AddressCooldown > 0 {
		lockFor(authCooldownPrefix+ip, as.config.AddressCooldown)
	}

	switch as.lockoutKey() {
	case sentinel.LockoutIP:
		// An exempt address is counted and challenged but never locked:
		// locking shared egress bars everyone behind it.
		if addressFailures >= as.config.MaxFailedAttempts && !as.exemptIPs.Matches(ip) {
			lock(authLockIPPrefix + ip)
		}
	case sentinel.LockoutAccount:
		if account == "" {
			as.lockAddressFallback(ip, addressFailures, lock)
			break
		}
		if accountFailures >= as.config.MaxFailedAttempts {
			lock(authLockUserPrefix + account)
		}
	default: // pair
		if account == "" {
			as.lockAddressFallback(ip, addressFailures, lock)
			break
		}
		if n := count(authFailPairPrefix + pairKey(ip, account)); n >= as.config.MaxFailedAttempts {
			lock(authLockPairPrefix + pairKey(ip, account))
		}
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
	keys := []string{authFailIPPrefix + ip, authLockIPPrefix + ip, authCooldownPrefix + ip, authStuffingPrefix + ip}
	if account := normalizeAccount(username); account != "" {
		keys = append(keys,
			authFailUserPrefix+account, authLockUserPrefix+account,
			authFailPairPrefix+pairKey(ip, account), authLockPairPrefix+pairKey(ip, account))
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
	IP             string `json:"ip"`
	FailedAttempts int    `json:"failed_attempts"`

	// Locked is true when the address itself is barred, which only
	// LockoutKey "ip" does.
	Locked    bool      `json:"locked"`
	LockUntil time.Time `json:"lock_until,omitempty"`

	// LockedAccounts are the accounts barred from this address under the
	// default pair lockout. Without this the dashboard showed nobody locked
	// while sign-ins were in fact being refused.
	LockedAccounts  []string `json:"locked_accounts,omitempty"`
	CAPTCHARequired bool     `json:"captcha_required"`
}

// lockedAccountsFor lists the accounts currently barred from one address by
// a pair lockout.
func (as *AuthShield) lockedAccountsFor(ctx context.Context, ip string, now time.Time) []string {
	keys, err := as.counters.Keys(ctx, authLockPairPrefix+ip+"|")
	if err != nil {
		return nil
	}
	var accounts []string
	for _, key := range keys {
		if as.lockedUntil(key, now).IsZero() {
			continue
		}
		if _, account, ok := strings.Cut(strings.TrimPrefix(key, authLockPairPrefix), "|"); ok && account != "" {
			accounts = append(accounts, account)
		}
	}
	sort.Strings(accounts)
	return accounts
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
	// Addresses that only have a pair lockout belong in the list too.
	if keys, err := as.counters.Keys(ctx, authLockPairPrefix); err == nil {
		for _, k := range keys {
			if ip, _, ok := strings.Cut(strings.TrimPrefix(k, authLockPairPrefix), "|"); ok {
				ips[ip] = true
			}
		}
	}

	out := make([]AuthShieldStatus, 0, len(ips))
	for ip := range ips {
		attempts := as.failures(authFailIPPrefix+ip, now)
		until := as.lockedUntil(authLockIPPrefix+ip, now)
		if attempts == 0 && until.IsZero() && len(as.lockedAccountsFor(ctx, ip, now)) == 0 {
			continue
		}
		row := AuthShieldStatus{
			IP:             ip,
			FailedAttempts: attempts,
			Locked:         !until.IsZero(),
			LockUntil:      until,
			LockedAccounts: as.lockedAccountsFor(ctx, ip, now),
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
	if v, ok := peekJSONBody(c)[fieldName].(string); ok {
		return v
	}
	return ""
}

// peekJSONBody decodes a JSON request body and puts it back, so a handler
// downstream still reads it. A body that isn't JSON, or is larger than the
// cap, decodes to nothing rather than an error: this is only used to find
// fields AuthShield keys on.
func peekJSONBody(c *gin.Context) map[string]any {
	if c.Request.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 64*1024))
	if err != nil {
		return nil
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	return payload
}
