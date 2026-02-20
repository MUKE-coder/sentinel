// Package storage defines the storage interface for Sentinel.
// Implementations include in-memory (dev/test), SQLite (default),
// and PostgreSQL (production).
package storage

import (
	"context"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// Store is the storage interface for all Sentinel data.
type Store interface {
	// SaveThreat persists a threat event.
	SaveThreat(ctx context.Context, event *sentinel.ThreatEvent) error

	// GetThreat retrieves a single threat event by ID.
	GetThreat(ctx context.Context, id string) (*sentinel.ThreatEvent, error)

	// ListThreats returns a paginated, filtered list of threat events.
	ListThreats(ctx context.Context, filter sentinel.ThreatFilter) ([]*sentinel.ThreatEvent, int64, error)

	// UpdateThreat updates specific fields of a threat event.
	UpdateThreat(ctx context.Context, id string, update sentinel.ThreatUpdate) error

	// UpsertActor creates or updates a threat actor profile.
	UpsertActor(ctx context.Context, actor *sentinel.ThreatActor) error

	// GetActor retrieves a threat actor by IP address.
	GetActor(ctx context.Context, ip string) (*sentinel.ThreatActor, error)

	// ListActors returns a paginated, filtered list of threat actors.
	ListActors(ctx context.Context, filter sentinel.ActorFilter) ([]*sentinel.ThreatActor, int64, error)

	// SaveUserActivity persists a user activity record.
	SaveUserActivity(ctx context.Context, event *sentinel.UserActivity) error

	// ListUserActivity returns paginated user activity for a specific user.
	ListUserActivity(ctx context.Context, userID string, filter sentinel.ActivityFilter) ([]*sentinel.UserActivity, int64, error)

	// SaveAuditLog persists an audit log entry.
	SaveAuditLog(ctx context.Context, log *sentinel.AuditLog) error

	// ListAuditLogs returns a paginated, filtered list of audit logs.
	ListAuditLogs(ctx context.Context, filter sentinel.AuditFilter) ([]*sentinel.AuditLog, int64, error)

	// SavePerformanceMetric persists a performance measurement.
	SavePerformanceMetric(ctx context.Context, metric *sentinel.PerformanceMetric) error

	// GetPerformanceOverview returns a snapshot of current system performance.
	GetPerformanceOverview(ctx context.Context) (*sentinel.PerformanceOverview, error)

	// GetRouteMetrics returns per-route performance metrics.
	GetRouteMetrics(ctx context.Context) ([]*sentinel.RouteMetric, error)

	// BlockIP blocks an IP address with a reason and optional expiry.
	BlockIP(ctx context.Context, ip string, reason string, expiry *time.Time) error

	// UnblockIP removes a block on an IP address.
	UnblockIP(ctx context.Context, ip string) error

	// WhitelistIP adds an IP address to the whitelist.
	WhitelistIP(ctx context.Context, ip string) error

	// IsIPBlocked checks if an IP address is blocked.
	IsIPBlocked(ctx context.Context, ip string) (bool, error)

	// IsIPWhitelisted checks if an IP address is whitelisted.
	IsIPWhitelisted(ctx context.Context, ip string) (bool, error)

	// ListBlockedIPs returns all blocked IP addresses.
	ListBlockedIPs(ctx context.Context) ([]*sentinel.BlockedIP, error)

	// ListUsers returns a summary of all users with activity.
	ListUsers(ctx context.Context) ([]*sentinel.UserSummary, error)

	// GetAttackTrends returns time-series attack data.
	GetAttackTrends(ctx context.Context, window time.Duration, interval string) ([]*sentinel.AttackTrend, error)

	// GetGeoStats returns geographic attack statistics.
	GetGeoStats(ctx context.Context, window time.Duration) ([]*sentinel.GeoStats, error)

	// GetTopTargets returns the most targeted routes.
	GetTopTargets(ctx context.Context, window time.Duration, limit int) ([]*sentinel.TopTarget, error)

	// GetThreatStats returns aggregated threat statistics for the given time window.
	GetThreatStats(ctx context.Context, window time.Duration) (*sentinel.ThreatStats, error)

	// GetSecurityScore returns the current security score.
	GetSecurityScore(ctx context.Context) (*sentinel.SecurityScore, error)

	// SaveSecurityScore persists a computed security score.
	SaveSecurityScore(ctx context.Context, score *sentinel.SecurityScore) error

	// Migrate runs database schema migrations.
	Migrate(ctx context.Context) error

	// Cleanup removes events older than the specified duration.
	Cleanup(ctx context.Context, olderThan time.Duration) error

	// Close closes the storage backend and releases resources.
	Close() error
}
