package sentinel

import "github.com/MUKE-coder/sentinel/core"

// Type aliases — re-export all types from core so users can use sentinel.X directly.
type (
	Severity           = core.Severity
	WAFMode            = core.WAFMode
	StorageDriver      = core.StorageDriver
	ActorStatus        = core.ActorStatus
	RateLimitStrategy  = core.RateLimitStrategy
	RuleSensitivity    = core.RuleSensitivity
	AnomalyCheckType   = core.AnomalyCheckType
	AnomalySensitivity = core.AnomalySensitivity
	AIProvider         = core.AIProvider
	GeoProvider        = core.GeoProvider
	ThreatType         = core.ThreatType
)

// Constant re-exports.
const (
	SeverityLow      = core.SeverityLow
	SeverityMedium   = core.SeverityMedium
	SeverityHigh     = core.SeverityHigh
	SeverityCritical = core.SeverityCritical

	ModeLog       = core.ModeLog
	ModeBlock     = core.ModeBlock
	ModeChallenge = core.ModeChallenge

	SQLite   = core.SQLite
	Postgres = core.Postgres
	MySQL    = core.MySQL
	Memory   = core.Memory

	ActorActive      = core.ActorActive
	ActorBlocked     = core.ActorBlocked
	ActorWhitelisted = core.ActorWhitelisted

	FixedWindow   = core.FixedWindow
	SlidingWindow = core.SlidingWindow
	TokenBucket   = core.TokenBucket

	RuleOff    = core.RuleOff
	RuleLow    = core.RuleLow
	RuleMedium = core.RuleMedium
	RuleStrict = core.RuleStrict

	CheckImpossibleTravel   = core.CheckImpossibleTravel
	CheckUnusualAccess      = core.CheckUnusualAccess
	CheckDataExfiltration   = core.CheckDataExfiltration
	CheckOffHoursAccess     = core.CheckOffHoursAccess
	CheckVelocityAnomaly    = core.CheckVelocityAnomaly
	CheckCredentialStuffing = core.CheckCredentialStuffing

	AnomalySensitivityLow    = core.AnomalySensitivityLow
	AnomalySensitivityMedium = core.AnomalySensitivityMedium
	AnomalySensitivityHigh   = core.AnomalySensitivityHigh

	Claude = core.Claude
	OpenAI = core.OpenAI
	Gemini = core.Gemini

	GeoIPFree = core.GeoIPFree
	GeoIPPaid = core.GeoIPPaid

	ThreatSQLi               = core.ThreatSQLi
	ThreatXSS                = core.ThreatXSS
	ThreatPathTraversal      = core.ThreatPathTraversal
	ThreatCommandInjection   = core.ThreatCommandInjection
	ThreatSSRF               = core.ThreatSSRF
	ThreatXXE                = core.ThreatXXE
	ThreatLFI                = core.ThreatLFI
	ThreatOpenRedirect       = core.ThreatOpenRedirect
	ThreatPrototypePollution = core.ThreatPrototypePollution
	ThreatRateLimitExceeded  = core.ThreatRateLimitExceeded
	ThreatBruteForce         = core.ThreatBruteForce
	ThreatAnomalyDetected    = core.ThreatAnomalyDetected
	ThreatScanning           = core.ThreatScanning
)

// Var re-exports.
var (
	Strict = core.Strict
	Medium = core.Medium
)
