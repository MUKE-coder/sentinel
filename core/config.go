package core

import (
	"time"

	"github.com/gin-gonic/gin"
)

// Config is the main configuration struct for Sentinel.
// All fields have sensible defaults — core.Config{} works out of the box.
type Config struct {
	Dashboard   DashboardConfig
	Storage     StorageConfig
	WAF         WAFConfig
	RateLimit   RateLimitConfig
	AuthShield  AuthShieldConfig
	Headers     HeaderConfig
	Anomaly     AnomalyConfig
	IPReputation IPReputationConfig
	Geo         GeoConfig
	Alerts      AlertConfig
	AI          *AIConfig
	UserExtractor func(c *gin.Context) *UserContext
	Performance PerformanceConfig
}

// DashboardConfig configures the embedded security dashboard.
type DashboardConfig struct {
	Enabled   *bool
	Prefix    string
	Username  string
	Password  string
	SecretKey string
}

// StorageConfig configures the storage backend.
type StorageConfig struct {
	Driver        StorageDriver
	DSN           string
	RetentionDays int
	MaxOpenConns  int
	MaxIdleConns  int
}

// WAFConfig configures the Web Application Firewall.
type WAFConfig struct {
	Enabled       bool
	Mode          WAFMode
	Rules         RuleSet
	CustomRules   []WAFRule
	ExcludeRoutes []string
	ExcludeIPs    []string
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
	Enabled         bool
	ByIP            *Limit
	ByUser          *Limit
	ByRoute         map[string]Limit
	Global          *Limit
	Strategy        RateLimitStrategy
	UserIDExtractor func(c *gin.Context) string
}

// AuthShieldConfig configures authentication protection.
type AuthShieldConfig struct {
	Enabled                    bool
	LoginRoute                 string
	MaxFailedAttempts          int
	LockoutDuration            time.Duration
	CredentialStuffingDetection bool
	BruteForceDetection        bool
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
	Provider     AIProvider
	APIKey       string
	Model        string
	DailySummary bool
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
		c.Dashboard.Password = "sentinel"
	}
	if c.Dashboard.SecretKey == "" {
		c.Dashboard.SecretKey = "sentinel-default-secret-change-me"
	}

	if c.Storage.Driver == "" {
		c.Storage.Driver = SQLite
	}
	if c.Storage.DSN == "" {
		c.Storage.DSN = "sentinel.db"
	}
	if c.Storage.RetentionDays == 0 {
		c.Storage.RetentionDays = 90
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

	if c.Geo.Provider == "" {
		c.Geo.Provider = GeoIPFree
	}

	if c.Alerts.MinSeverity == "" {
		c.Alerts.MinSeverity = SeverityHigh
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
