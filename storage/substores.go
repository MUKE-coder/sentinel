package storage

import (
	"context"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// ThreatStore handles persistence and retrieval of threat events.
// Split out of Store so callers that only consume threats — for example a
// Redis-backed sink or a read-only API server — can depend on the minimum
// interface they actually need.
type ThreatStore interface {
	SaveThreat(ctx context.Context, event *sentinel.ThreatEvent) error
	GetThreat(ctx context.Context, id string) (*sentinel.ThreatEvent, error)
	ListThreats(ctx context.Context, filter sentinel.ThreatFilter) ([]*sentinel.ThreatEvent, int64, error)
	UpdateThreat(ctx context.Context, id string, update sentinel.ThreatUpdate) error
	GetThreatStats(ctx context.Context, window time.Duration) (*sentinel.ThreatStats, error)
}

// ActorStore handles persistence and retrieval of threat actor profiles.
type ActorStore interface {
	UpsertActor(ctx context.Context, actor *sentinel.ThreatActor) error
	GetActor(ctx context.Context, ip string) (*sentinel.ThreatActor, error)
	ListActors(ctx context.Context, filter sentinel.ActorFilter) ([]*sentinel.ThreatActor, int64, error)
}

// IPStore handles IP block / whitelist state. Splitting this out lets users
// back the hot-path block check with Redis while keeping threat history in
// SQLite/Postgres.
type IPStore interface {
	BlockIP(ctx context.Context, ip string, reason string, expiry *time.Time) error
	UnblockIP(ctx context.Context, ip string) error
	WhitelistIP(ctx context.Context, ip string) error
	IsIPBlocked(ctx context.Context, ip string) (bool, error)
	IsIPWhitelisted(ctx context.Context, ip string) (bool, error)
	ListBlockedIPs(ctx context.Context) ([]*sentinel.BlockedIP, error)
}

// AuditStore handles immutable audit log persistence and retrieval.
type AuditStore interface {
	SaveAuditLog(ctx context.Context, log *sentinel.AuditLog) error
	ListAuditLogs(ctx context.Context, filter sentinel.AuditFilter) ([]*sentinel.AuditLog, int64, error)
}

// MetricStore handles performance metric persistence and aggregation.
type MetricStore interface {
	SavePerformanceMetric(ctx context.Context, metric *sentinel.PerformanceMetric) error
	GetPerformanceOverview(ctx context.Context) (*sentinel.PerformanceOverview, error)
	GetRouteMetrics(ctx context.Context) ([]*sentinel.RouteMetric, error)
}

// UserActivityStore handles per-user activity persistence and retrieval.
type UserActivityStore interface {
	SaveUserActivity(ctx context.Context, event *sentinel.UserActivity) error
	ListUserActivity(ctx context.Context, userID string, filter sentinel.ActivityFilter) ([]*sentinel.UserActivity, int64, error)
	ListUsers(ctx context.Context) ([]*sentinel.UserSummary, error)
}

// AnalyticsStore handles aggregated analytics queries.
type AnalyticsStore interface {
	GetAttackTrends(ctx context.Context, window time.Duration, interval string) ([]*sentinel.AttackTrend, error)
	GetGeoStats(ctx context.Context, window time.Duration) ([]*sentinel.GeoStats, error)
	GetTopTargets(ctx context.Context, window time.Duration, limit int) ([]*sentinel.TopTarget, error)
}

// ScoreStore handles security-score persistence.
type ScoreStore interface {
	GetSecurityScore(ctx context.Context) (*sentinel.SecurityScore, error)
	SaveSecurityScore(ctx context.Context, score *sentinel.SecurityScore) error
}

// LifecycleStore handles backend lifecycle: migrations, cleanup, shutdown.
type LifecycleStore interface {
	Migrate(ctx context.Context) error
	Cleanup(ctx context.Context, olderThan time.Duration) error
	Close() error
}
