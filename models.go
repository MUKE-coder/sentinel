package sentinel

import "github.com/MUKE-coder/sentinel/core"

// Type aliases — re-export all model types from core.
type (
	JSONMap             = core.JSONMap
	InspectedRequest    = core.InspectedRequest
	Evidence            = core.Evidence
	ThreatEvent         = core.ThreatEvent
	ThreatActor         = core.ThreatActor
	AuditLog            = core.AuditLog
	UserActivity        = core.UserActivity
	SubScore            = core.SubScore
	Recommendation      = core.Recommendation
	SecurityScore       = core.SecurityScore
	PerformanceMetric   = core.PerformanceMetric
	PerformanceOverview = core.PerformanceOverview
	RouteMetric         = core.RouteMetric
	BlockedIP           = core.BlockedIP
	WhitelistedIP       = core.WhitelistedIP
	ThreatStats         = core.ThreatStats
	AttackTypeStat      = core.AttackTypeStat
	ThreatFilter        = core.ThreatFilter
	ActorFilter         = core.ActorFilter
	ActivityFilter      = core.ActivityFilter
	AuditFilter         = core.AuditFilter
	ThreatUpdate        = core.ThreatUpdate
	ReputationResult    = core.ReputationResult
	GeoResult           = core.GeoResult
	AlertHistory        = core.AlertHistory
	UserSummary         = core.UserSummary
	AttackTrend         = core.AttackTrend
	GeoStats            = core.GeoStats
	TopTarget           = core.TopTarget
)
