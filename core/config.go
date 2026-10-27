package core

import (
	"time"

	"github.com/gin-gonic/gin"
)

// Config is the main configuration struct for Sentinel.
// All fields have sensible defaults — core.Config{} works out of the box.
type Config struct {
	Dashboard    DashboardConfig
	Storage      StorageConfig
	WAF          WAFConfig
	RateLimit    RateLimitConfig
	AuthShield   AuthShieldConfig
	Headers      HeaderConfig
	Anomaly      AnomalyConfig
	IPReputation IPReputationConfig
	AutoBlock    AutoBlockConfig
	Geo          GeoConfig
	Alerts       AlertConfig
	AI           *AIConfig
	// UserExtractor identifies the authenticated user behind a request. When
	// set, Sentinel records one UserActivity per authenticated request — the
	// data behind the Users page, the GDPR report's per-user section, and
	// anomaly detection. It runs after the handler, so it can read whatever
	// your auth middleware put on the context; return nil for anonymous
	// requests.
	UserExtractor func(c *gin.Context) *UserContext
	Performance   PerformanceConfig
	CAPTCHA       CAPTCHAConfig

	// Counters holds the counters behind rate limiting and AuthShield. Nil
	// keeps them in process memory, so each replica counts on its own; set a
	// shared store such as redisstore.New(client) and limits and lockouts
	// hold across every replica.
	Counters CounterStore
}

// CAPTCHAConfig configures the CAPTCHA tier used by AuthShield. Pick exactly
// one provider — set the matching SecretKey to enable. SelfHostedSecret
// activates the built-in arithmetic challenge for projects that don't want
// a third-party CAPTCHA.
type CAPTCHAConfig struct {
	HCaptchaSecret   string
	TurnstileSecret  string
	RecaptchaSecret  string
	SelfHostedSecret string
}

// configured reports whether any provider secret is set, which is what
// decides whether AuthShield's CAPTCHA tier can do anything.
func (c CAPTCHAConfig) configured() bool {
	return c.HCaptchaSecret != "" || c.TurnstileSecret != "" ||
		c.RecaptchaSecret != "" || c.SelfHostedSecret != ""
}

// Providers counts the configured CAPTCHA provider secrets.
func (c CAPTCHAConfig) Providers() int {
	n := 0
	for _, secret := range []string{c.HCaptchaSecret, c.TurnstileSecret, c.RecaptchaSecret, c.SelfHostedSecret} {
		if secret != "" {
			n++
		}
	}
	return n
}

// DashboardConfig configures the embedded security dashboard.
type DashboardConfig struct {
	Enabled   *bool
	Prefix    string
	Username  string
	Password  string
	SecretKey string

	// AllowInsecureDefaults must be set to true to start with the built-in
	// default password ("sentinel") or default JWT secret. In release mode
	// (GIN_MODE=release) Mount will refuse to start unless this is true,
	// preventing accidental deployment with forgeable admin tokens.
	AllowInsecureDefaults bool
}

// StorageConfig configures the storage backend.
type StorageConfig struct {
	Driver StorageDriver
	DSN    string

	// RetentionDays is how long threat, user-activity, and performance
	// records are kept. Default: 90.
	RetentionDays int

	// AuditRetentionDays is how long audit log entries are kept. Separate
	// from RetentionDays because audit history is evidence: PCI-DSS 10.5.1
	// requires 12 months of it. Default: 365.
	AuditRetentionDays int

	// AuditKey, when set, makes the audit log's hash chain an HMAC-SHA256
	// chain: someone with write access to the database but not this key
	// cannot rewrite entries and recompute the chain undetectably. Keep it
	// outside the database (an env var or secrets manager) and stable —
	// entries hashed under a different key fail verification. Without it the
	// chain is plain SHA-256, which catches accidental damage and naive edits.
	AuditKey string

	// SyncInterval is how often this replica picks up changes made
	// elsewhere: IP blocks and whitelist entries written by another replica,
	// and dashboard settings changed on one. Default: 5s. A negative value
	// turns polling off, leaving this process to see only its own changes.
	SyncInterval time.Duration

	MaxOpenConns int
	MaxIdleConns int
}

// WAFConfig configures the Web Application Firewall.
type WAFConfig struct {
	Enabled     bool
	Mode        WAFMode
	Rules       RuleSet
	CustomRules []WAFRule

	// ExcludeRoutes lists paths the WAF will not inspect. Entries may be
	// exact ("/health"), trailing-wildcard prefixes ("/v1/*" or "/v1/**" —
	// both match "/v1" and everything under "/v1/"), segment globs
	// ("/api/apps/*/products", path.Match semantics), or a combination of
	// segment wildcards with a trailing globstar
	// ("/api/apps/*/products/**" — the parameterised subtree and any depth
	// below it).
	ExcludeRoutes []string
	ExcludeIPs    []string

	// AllowedRedirectHosts lists the hosts this application owns, so an
	// absolute URL in a redirect parameter can be told apart from an open
	// redirect. Sentinel cannot know your hostnames, and the two look the
	// same: "callback=https://app.example.com/oauth" is both the attack and
	// an ordinary OAuth callback, so without this every absolute redirect
	// target is reported. Entries are hosts ("example.com", port ignored) or
	// wildcards ("*.example.com", any subdomain but not the bare domain).
	AllowedRedirectHosts []string

	// MaxBodyBytes is the maximum number of bytes the WAF will read and inspect
	// from a request body. Default: 65536 (64 KB). Requests with bodies larger
	// than this are inspected up to the limit; set RejectOversizedBody to true
	// to refuse them instead.
	MaxBodyBytes int64

	// RejectOversizedBody, when true, causes the WAF to reject any request
	// whose Content-Length exceeds MaxBodyBytes with 413 Payload Too Large,
	// closing the inspection-bypass hole where attackers pad large bodies.
	RejectOversizedBody bool

	// TrustedProxies is a list of IPs or CIDRs whose X-Forwarded-For /
	// X-Real-IP headers should be trusted. If empty, those headers are
	// ignored and only the direct connection IP is used. Strongly
	// recommended in production behind a known reverse proxy.
	TrustedProxies []string
}

// RuleSet configures the sensitivity of each built-in WAF rule.
type RuleSet struct {
	SQLInjection     RuleSensitivity
	XSS              RuleSensitivity
	PathTraversal    RuleSensitivity
	CommandInjection RuleSensitivity
	SSRF             RuleSensitivity
	XXE              RuleSensitivity
	LFI              RuleSensitivity
	OpenRedirect     RuleSensitivity
}

// WAFRule defines a custom WAF detection rule.
type WAFRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Pattern   string   `json:"pattern"`
	AppliesTo []string `json:"applies_to"`
	Severity  Severity `json:"severity"`
	Action    string   `json:"action"`
	Enabled   bool     `json:"enabled"`
}

// Limit defines a rate limit with requests per time window.
type Limit struct {
	Requests int
	Window   time.Duration
}

// RateLimitConfig configures multi-dimensional rate limiting.
type RateLimitConfig struct {
	Enabled bool
	ByIP    *Limit
	ByUser  *Limit

	// ByRoute maps a path to its limit. Keys may be exact ("/api/auth/login")
	// or wildcard patterns ("/v1/*", "/api/apps/*/products"). All paths
	// matching one pattern share that pattern's counter (per client IP), so
	// rotating sub-paths cannot reset the budget. When both an exact key and
	// a pattern match, the exact key wins.
	ByRoute map[string]Limit

	Global   *Limit
	Strategy RateLimitStrategy

	// ExcludeRoutes lists paths exempt from rate limiting. Plain entries
	// match by prefix ("/static" also exempts "/static/app.js" — historical
	// behavior, kept for compatibility); entries containing wildcards use
	// the same pattern shapes as WAFConfig.ExcludeRoutes.
	ExcludeRoutes   []string
	UserIDExtractor func(c *gin.Context) string
}

// AuthShieldConfig configures authentication protection.
type AuthShieldConfig struct {
	Enabled                     bool
	LoginRoute                  string
	MaxFailedAttempts           int
	LockoutDuration             time.Duration
	CredentialStuffingDetection bool
	BruteForceDetection         bool

	// CAPTCHAThreshold is the failure count after which a CAPTCHA token is
	// required on the next login attempt — the suspicious-but-not-locked
	// middle tier. Must be lower than MaxFailedAttempts. Default in
	// ApplyDefaults: MaxFailedAttempts / 2 (rounded down, minimum 2).
	// Set to 0 to disable the CAPTCHA tier.
	CAPTCHAThreshold int

	// CAPTCHATokenField is the form / JSON field name the middleware reads
	// the CAPTCHA token from. Header "X-Captcha-Token" is always also
	// accepted. Default: "captcha_token".
	CAPTCHATokenField string

	// LockoutKey decides what MaxFailedAttempts locks: the (client address,
	// account) pair (LockoutPair, the default), the client address alone
	// (LockoutIP, the behavior before v2.7.0), or the account wherever the
	// attempts come from (LockoutAccount). Failures are counted per address
	// and per account whichever it is, so credential-stuffing detection and
	// the CAPTCHA tier are unaffected.
	LockoutKey AuthShieldLockoutKey

	// ExemptIPs are addresses and CIDRs that are never locked by address —
	// shared egress such as an office NAT, CGNAT, or a VPN gateway, where
	// one person's five mistakes would bar everybody behind it. Failures
	// from them are still counted, the CAPTCHA tier still applies, and pair
	// and account lockouts still apply.
	ExemptIPs []string

	// UsernameFields are the request fields AuthShield reads the account
	// name from, in order, so a lockout can be keyed on the account before
	// the login handler runs. JSON bodies and form posts are both read.
	// Default: "username", "email", "login", "user".
	UsernameFields []string

	// AddressFailureBudget is how many failed sign-ins one client address
	// may accumulate within LockoutDuration before every attempt from it is
	// refused for AddressCooldown. This is what catches one machine working
	// through many accounts, which no per-account lockout sees: with the
	// default pair lockout each account fails only a few times.
	//
	// Default: MaxFailedAttempts * 4. Negative disables the throttle.
	AddressFailureBudget int

	// AddressCooldown is how long an address is refused once it passes
	// AddressFailureBudget. It is deliberately short: an address is not a
	// person, and a long ban behind NAT or CGNAT bars everyone sharing it.
	// An attacker's throughput still collapses. Default: 1 minute.
	AddressCooldown time.Duration
}

// AuthShieldLockoutKey decides what an AuthShield lockout bars.
type AuthShieldLockoutKey string

const (
	// LockoutPair locks the (client address, account) combination. One
	// person failing five times stops their own attempts from that address
	// and leaves everybody else sharing it alone. The default since v2.7.0.
	LockoutPair AuthShieldLockoutKey = "pair"

	// LockoutIP locks the client address, which is what AuthShield did
	// before v2.7.0. Behind NAT or CGNAT an address is not a person: five
	// failures by one user bar everybody sharing that egress address, and
	// anyone who knows a target's egress address can do it on purpose.
	// Pair with ExemptIPs if you choose this.
	LockoutIP AuthShieldLockoutKey = "ip"

	// LockoutAccount locks the account wherever the attempts come from. It
	// stops a distributed attack on one account, and lets anyone who knows
	// an account name keep its owner locked out, so it suits internal
	// applications more than public sign-in.
	LockoutAccount AuthShieldLockoutKey = "account"
)

// ValidAuthShieldLockoutKey reports whether k is a lockout key AuthShield
// understands. Anything else is treated as LockoutPair.
func ValidAuthShieldLockoutKey(k AuthShieldLockoutKey) bool {
	switch k {
	case LockoutPair, LockoutIP, LockoutAccount:
		return true
	}
	return false
}

// DefaultUsernameFields are the request fields AuthShield reads an account
// name from when UsernameFields is unset.
var DefaultUsernameFields = []string{"username", "email", "login", "user"}

// AutoBlockConfig blocks an address that keeps attacking.
//
// This is behaviour, not reputation: IPReputation.AutoBlock acts on what a
// third party says about an address, and this acts on what the address has
// just done to this application. Mass scanners walking a list of paths
// (.env, .git/config, wp-login.php) trip it in seconds, which is the point
// — otherwise every one of their requests is inspected, recorded, and
// answered one at a time, for hours.
//
// Counting runs through Config.Counters, so the threats an address racks up
// across every replica count towards one total.
type AutoBlockConfig struct {
	Enabled bool

	// Threats is how many threats from one address within Window before it
	// is blocked. Default: 10.
	Threats int

	// Window is how long threats are counted over. Default: 10 minutes.
	Window time.Duration

	// Duration is how long the block lasts. Zero means until someone lifts
	// it. Default: 24 hours.
	Duration time.Duration

	// MinSeverity is the lowest severity that counts towards Threats.
	// Default: High — which is what the scanner patterns (LFI, SQLi, path
	// traversal) score, while a lone medium-severity oddity does not
	// accumulate towards a block.
	MinSeverity Severity

	// ExemptIPs are addresses and CIDRs that are never auto-blocked: your
	// own monitoring, an office range, a partner's integration. Whitelisted
	// IPs are already exempt.
	ExemptIPs []string
}

// HeaderConfig configures security header injection.
type HeaderConfig struct {
	Enabled                 *bool
	ContentSecurityPolicy   string
	StrictTransportSecurity bool
	XFrameOptions           string
	XContentTypeOptions     bool
	ReferrerPolicy          string
	PermissionsPolicy       string
}

// AnomalyConfig configures behavioral anomaly detection.
type AnomalyConfig struct {
	Enabled        bool
	LearningPeriod time.Duration
	Sensitivity    AnomalySensitivity
	Checks         []AnomalyCheckType
}

// IPReputationConfig configures IP reputation checking.
type IPReputationConfig struct {
	Enabled       bool
	AbuseIPDBKey  string
	AutoBlock     bool
	MinAbuseScore int

	// MaxChecksPerDay caps live AbuseIPDB checks of attacking IPs; cached
	// results don't count. Default: 900, under the free plan's 1,000 a day.
	MaxChecksPerDay int

	// Feeds are URLs of public IP blocklists: plain text with one IP or CIDR
	// per line (Spamhaus DROP, FireHOL netsets) or NDJSON with a "cidr" field
	// (Spamhaus drop_v4.json). Listed addresses are blocked like IPs blocked
	// from the dashboard. Feeds work without an AbuseIPDB key or Enabled.
	Feeds []string

	// FeedRefresh is how often feeds are downloaded again. Default: 24h.
	FeedRefresh time.Duration
}

// GeoConfig configures IP geolocation.
type GeoConfig struct {
	Enabled  bool
	Provider GeoProvider
}

// AlertConfig configures the alerting system.
type AlertConfig struct {
	MinSeverity Severity
	Slack       *SlackConfig
	Email       *EmailConfig
	Webhook     *WebhookConfig
	PagerDuty   *PagerDutyConfig
}

// PagerDutyConfig configures PagerDuty Events API v2 routing. Use when
// security findings should page the oncall, not just appear in a dashboard.
type PagerDutyConfig struct {
	// IntegrationKey is the PagerDuty Events API v2 routing key (32 hex chars).
	IntegrationKey string

	// MinSeverity overrides AlertConfig.MinSeverity for PagerDuty specifically.
	// Empty = inherit. Common pattern: AlertConfig.MinSeverity=High to fill the
	// dashboard, PagerDuty.MinSeverity=Critical to page only on critical.
	MinSeverity Severity

	// MinCVSS, if non-zero, filters findings by CVSS score in addition to
	// severity — e.g. set 9.0 to page only on the worst.
	MinCVSS float64
}

// SlackConfig configures Slack webhook alerts.
type SlackConfig struct {
	WebhookURL string
}

// EmailConfig configures email alerts.
type EmailConfig struct {
	SMTPHost   string
	SMTPPort   int
	Username   string
	Password   string
	Recipients []string
}

// WebhookConfig configures generic webhook alerts.
type WebhookConfig struct {
	URL     string
	Headers map[string]string
}

// AIConfig configures optional AI-powered analysis.
type AIConfig struct {
	Provider AIProvider
	APIKey   string
	Model    string
	// Deprecated: DailySummary has no effect. Nothing runs on a schedule; the
	// daily summary is generated on demand from the dashboard's AI page.
	DailySummary bool

	// MaxCallsPerDay caps the total number of upstream LLM calls per UTC day
	// across all AI features (threat analysis, NL queries, summaries, etc).
	// 0 disables the cap. Default applied in ApplyDefaults: 500.
	MaxCallsPerDay int64

	// Redaction controls what threat data is masked before anything is sent
	// to the provider. The zero value is the most private setting.
	Redaction AIRedaction
}

// AIRedaction controls what leaves the process when an AI feature runs. The
// zero value redacts: query-string values are masked (parameter names are
// kept), request-body snippets are dropped, client IPs are truncated, and
// emails, tokens, card numbers, and secret-looking values are scrubbed from
// every text field. The attack fragments the WAF matched are kept (scrubbed),
// so an analysis still sees the payload that triggered the detection.
type AIRedaction struct {
	// SendPayloads sends query strings and request-body snippets as recorded
	// (still scrubbed unless DisableScrubbing is set).
	SendPayloads bool

	// SendFullIPs sends client IP addresses and cities unmasked.
	SendFullIPs bool

	// DisableScrubbing turns off the email, token, card-number, and secret
	// scrubbing applied to every text field.
	DisableScrubbing bool
}

// UserContext represents an authenticated user extracted from a request.
type UserContext struct {
	ID    string
	Email string
	Role  string
}

// PerformanceConfig configures performance monitoring.
type PerformanceConfig struct {
	Enabled              *bool
	SlowQueryThreshold   time.Duration
	SlowRequestThreshold time.Duration
	TrackMemory          bool
	TrackGoroutines      bool
}

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (c *Config) ApplyDefaults() {
	if c.Dashboard.Enabled == nil {
		enabled := true
		c.Dashboard.Enabled = &enabled
	}
	if c.Dashboard.Prefix == "" {
		c.Dashboard.Prefix = "/sentinel"
	}
	if c.Dashboard.Username == "" {
		c.Dashboard.Username = "admin"
	}
	if c.Dashboard.Password == "" {
		c.Dashboard.Password = DefaultInsecurePassword
	}
	if c.Dashboard.SecretKey == "" {
		c.Dashboard.SecretKey = randomSecretKey()
	}

	if c.Storage.Driver == "" {
		c.Storage.Driver = SQLite
	}
	// Only the file-based driver has a sensible default DSN. Giving every
	// driver "sentinel.db" meant a Postgres or MySQL config with no DSN
	// looked complete and failed at connect time instead of in
	// ValidateConfig.
	if c.Storage.DSN == "" && c.Storage.Driver == SQLite {
		c.Storage.DSN = "sentinel.db"
	}
	if c.Storage.RetentionDays == 0 {
		c.Storage.RetentionDays = 90
	}
	if c.Storage.AuditRetentionDays == 0 {
		c.Storage.AuditRetentionDays = 365
	}
	if c.Storage.SyncInterval == 0 {
		c.Storage.SyncInterval = 5 * time.Second
	}
	if c.Storage.MaxOpenConns == 0 {
		c.Storage.MaxOpenConns = 10
	}
	if c.Storage.MaxIdleConns == 0 {
		c.Storage.MaxIdleConns = 5
	}

	if c.WAF.Mode == "" {
		c.WAF.Mode = ModeLog
	}
	if c.WAF.Rules.SQLInjection == "" {
		c.WAF.Rules.SQLInjection = RuleStrict
	}
	if c.WAF.Rules.XSS == "" {
		c.WAF.Rules.XSS = RuleStrict
	}
	if c.WAF.Rules.PathTraversal == "" {
		c.WAF.Rules.PathTraversal = RuleStrict
	}
	if c.WAF.Rules.CommandInjection == "" {
		c.WAF.Rules.CommandInjection = RuleStrict
	}
	if c.WAF.Rules.SSRF == "" {
		c.WAF.Rules.SSRF = RuleMedium
	}
	if c.WAF.Rules.XXE == "" {
		c.WAF.Rules.XXE = RuleStrict
	}
	if c.WAF.Rules.LFI == "" {
		c.WAF.Rules.LFI = RuleStrict
	}
	if c.WAF.Rules.OpenRedirect == "" {
		c.WAF.Rules.OpenRedirect = RuleMedium
	}

	if c.RateLimit.Strategy == "" {
		c.RateLimit.Strategy = SlidingWindow
	}

	if c.AuthShield.MaxFailedAttempts == 0 {
		c.AuthShield.MaxFailedAttempts = 5
	}
	if c.AuthShield.LockoutDuration == 0 {
		c.AuthShield.LockoutDuration = 15 * time.Minute
	}
	// The CAPTCHA tier only exists when a provider can answer it. Giving
	// CAPTCHAThreshold a value regardless meant every deployment that
	// enabled AuthShield without CAPTCHA had a tier between "allow" and
	// "locked out" that could never fire, and read like a defence (#35).
	if c.AuthShield.CAPTCHAThreshold == 0 && c.AuthShield.MaxFailedAttempts >= 4 && c.CAPTCHA.configured() {
		c.AuthShield.CAPTCHAThreshold = c.AuthShield.MaxFailedAttempts / 2
		if c.AuthShield.CAPTCHAThreshold < 2 {
			c.AuthShield.CAPTCHAThreshold = 2
		}
	}
	if c.AuthShield.LockoutKey == "" {
		c.AuthShield.LockoutKey = LockoutPair
	}
	if len(c.AuthShield.UsernameFields) == 0 {
		c.AuthShield.UsernameFields = DefaultUsernameFields
	}
	if c.AuthShield.AddressFailureBudget == 0 {
		c.AuthShield.AddressFailureBudget = c.AuthShield.MaxFailedAttempts * 4
	}
	if c.AuthShield.AddressCooldown == 0 {
		c.AuthShield.AddressCooldown = time.Minute
	}
	if c.AutoBlock.Threats == 0 {
		c.AutoBlock.Threats = 10
	}
	if c.AutoBlock.Window == 0 {
		c.AutoBlock.Window = 10 * time.Minute
	}
	if c.AutoBlock.Duration == 0 {
		c.AutoBlock.Duration = 24 * time.Hour
	}
	if c.AutoBlock.MinSeverity == "" {
		c.AutoBlock.MinSeverity = SeverityHigh
	}
	if c.AuthShield.CAPTCHATokenField == "" {
		c.AuthShield.CAPTCHATokenField = "captcha_token"
	}

	if c.Headers.Enabled == nil {
		enabled := true
		c.Headers.Enabled = &enabled
	}
	if c.Headers.XFrameOptions == "" {
		c.Headers.XFrameOptions = "DENY"
	}
	if c.Headers.ReferrerPolicy == "" {
		c.Headers.ReferrerPolicy = "strict-origin-when-cross-origin"
	}
	c.Headers.XContentTypeOptions = true

	if c.Anomaly.LearningPeriod == 0 {
		c.Anomaly.LearningPeriod = 7 * 24 * time.Hour
	}
	if c.Anomaly.Sensitivity == "" {
		c.Anomaly.Sensitivity = AnomalySensitivityMedium
	}

	if c.IPReputation.MinAbuseScore == 0 {
		c.IPReputation.MinAbuseScore = 80
	}
	if c.IPReputation.MaxChecksPerDay == 0 {
		c.IPReputation.MaxChecksPerDay = 900
	}
	if c.IPReputation.FeedRefresh == 0 {
		c.IPReputation.FeedRefresh = 24 * time.Hour
	}

	if c.Geo.Provider == "" {
		c.Geo.Provider = GeoIPFree
	}

	if c.Alerts.MinSeverity == "" {
		c.Alerts.MinSeverity = SeverityHigh
	}

	if c.AI != nil && c.AI.MaxCallsPerDay == 0 {
		c.AI.MaxCallsPerDay = 500
	}

	if c.Performance.Enabled == nil {
		enabled := true
		c.Performance.Enabled = &enabled
	}
	if c.Performance.SlowQueryThreshold == 0 {
		c.Performance.SlowQueryThreshold = 500 * time.Millisecond
	}
	if c.Performance.SlowRequestThreshold == 0 {
		c.Performance.SlowRequestThreshold = 2 * time.Second
	}
}
