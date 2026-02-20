// Package core contains all shared types, constants, and models for Sentinel.
// Sub-packages import this package instead of the root sentinel package,
// allowing the root package to import sub-packages without import cycles.
package core

// Severity represents the severity level of a security event.
type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

// WAFMode defines how the WAF handles detected threats.
type WAFMode string

const (
	ModeLog       WAFMode = "log"
	ModeBlock     WAFMode = "block"
	ModeChallenge WAFMode = "challenge"
)

// StorageDriver specifies the storage backend to use.
type StorageDriver string

const (
	SQLite   StorageDriver = "sqlite"
	Postgres StorageDriver = "postgres"
	MySQL    StorageDriver = "mysql"
	Memory   StorageDriver = "memory"
)

// ActorStatus represents the current status of a threat actor.
type ActorStatus string

const (
	ActorActive      ActorStatus = "Active"
	ActorBlocked     ActorStatus = "Blocked"
	ActorWhitelisted ActorStatus = "Whitelisted"
)

// RateLimitStrategy defines the algorithm used for rate limiting.
type RateLimitStrategy string

const (
	FixedWindow   RateLimitStrategy = "fixed_window"
	SlidingWindow RateLimitStrategy = "sliding_window"
	TokenBucket   RateLimitStrategy = "token_bucket"
)

// RuleSensitivity defines how aggressively a WAF rule matches.
type RuleSensitivity string

const (
	RuleOff    RuleSensitivity = "off"
	RuleLow    RuleSensitivity = "low"
	RuleMedium RuleSensitivity = "medium"
	RuleStrict RuleSensitivity = "strict"
)

// Shorthand aliases for rule sensitivity used in config.
var (
	Strict = RuleStrict
	Medium = RuleMedium
)

// AnomalyCheckType defines the type of behavioral anomaly to check.
type AnomalyCheckType string

const (
	CheckImpossibleTravel  AnomalyCheckType = "impossible_travel"
	CheckUnusualAccess     AnomalyCheckType = "unusual_access"
	CheckDataExfiltration  AnomalyCheckType = "data_exfiltration"
	CheckOffHoursAccess    AnomalyCheckType = "off_hours_access"
	CheckVelocityAnomaly   AnomalyCheckType = "velocity_anomaly"
	CheckCredentialStuffing AnomalyCheckType = "credential_stuffing"
)

// AnomalySensitivity defines the sensitivity level for anomaly detection.
type AnomalySensitivity string

const (
	AnomalySensitivityLow    AnomalySensitivity = "low"
	AnomalySensitivityMedium AnomalySensitivity = "medium"
	AnomalySensitivityHigh   AnomalySensitivity = "high"
)

// AIProvider specifies which AI provider to use.
type AIProvider string

const (
	Claude AIProvider = "claude"
	OpenAI AIProvider = "openai"
	Gemini AIProvider = "gemini"
)

// GeoProvider specifies the geolocation provider.
type GeoProvider string

const (
	GeoIPFree GeoProvider = "geolite2"
	GeoIPPaid GeoProvider = "geoip2"
)

// ThreatType defines the category of a detected threat.
type ThreatType string

const (
	ThreatSQLi               ThreatType = "SQLi"
	ThreatXSS                ThreatType = "XSS"
	ThreatPathTraversal      ThreatType = "PathTraversal"
	ThreatCommandInjection   ThreatType = "CommandInjection"
	ThreatSSRF               ThreatType = "SSRF"
	ThreatXXE                ThreatType = "XXE"
	ThreatLFI                ThreatType = "LFI"
	ThreatOpenRedirect       ThreatType = "OpenRedirect"
	ThreatPrototypePollution ThreatType = "PrototypePollution"
	ThreatRateLimitExceeded  ThreatType = "RateLimitExceeded"
	ThreatBruteForce         ThreatType = "BruteForce"
	ThreatAnomalyDetected    ThreatType = "AnomalyDetected"
	ThreatScanning           ThreatType = "Scanning"
)
