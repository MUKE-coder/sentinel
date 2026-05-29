package sentinel

import "github.com/MUKE-coder/sentinel/core"

// Type aliases — re-export all config types from core.
type (
	Config             = core.Config
	DashboardConfig    = core.DashboardConfig
	StorageConfig      = core.StorageConfig
	WAFConfig          = core.WAFConfig
	RuleSet            = core.RuleSet
	WAFRule            = core.WAFRule
	Limit              = core.Limit
	RateLimitConfig    = core.RateLimitConfig
	AuthShieldConfig   = core.AuthShieldConfig
	HeaderConfig       = core.HeaderConfig
	AnomalyConfig      = core.AnomalyConfig
	IPReputationConfig = core.IPReputationConfig
	GeoConfig          = core.GeoConfig
	AlertConfig        = core.AlertConfig
	SlackConfig        = core.SlackConfig
	EmailConfig        = core.EmailConfig
	WebhookConfig      = core.WebhookConfig
	PagerDutyConfig    = core.PagerDutyConfig
	AIConfig           = core.AIConfig
	UserContext        = core.UserContext
	PerformanceConfig  = core.PerformanceConfig
	CAPTCHAConfig      = core.CAPTCHAConfig
)
