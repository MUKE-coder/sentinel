// Package sqlite provides a SQLite storage adapter for Sentinel
// using the pure-Go modernc.org/sqlite driver (no CGo required).
package sqlite

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/storage"
	gsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Ensure Store implements storage.Store.
var _ storage.Store = (*Store)(nil)

// Store is a SQLite implementation of the storage.Store interface.
type Store struct {
	db *gorm.DB
}

// New creates a new SQLite store with the given DSN (database file path).
func New(dsn string) (*Store, error) {
	db, err := gorm.Open(gsqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1) // SQLite supports only one writer
	sqlDB.SetMaxIdleConns(1)

	// Enable WAL mode for better concurrent read performance
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA synchronous=NORMAL")
	db.Exec("PRAGMA foreign_keys=ON")

	return &Store{db: db}, nil
}

// --- GORM models ---

type threatEventRow struct {
	ID            string    `gorm:"primaryKey;column:id"`
	Timestamp     time.Time `gorm:"index;column:timestamp"`
	IP            string    `gorm:"index;column:ip"`
	ActorID       string    `gorm:"column:actor_id"`
	UserID        string    `gorm:"column:user_id"`
	Method        string    `gorm:"column:method"`
	Path          string    `gorm:"column:path"`
	StatusCode    int       `gorm:"column:status_code"`
	UserAgent     string    `gorm:"column:user_agent"`
	Referer       string    `gorm:"column:referer"`
	QueryParams   string    `gorm:"column:query_params"`
	BodySnippet   string    `gorm:"column:body_snippet"`
	Headers       string    `gorm:"column:headers"`
	ThreatTypes   string    `gorm:"column:threat_types"`
	Severity      string    `gorm:"index;column:severity"`
	Confidence    int       `gorm:"column:confidence"`
	Evidence      string    `gorm:"column:evidence"`
	Blocked       bool      `gorm:"column:blocked"`
	Country       string    `gorm:"column:country"`
	City          string    `gorm:"column:city"`
	Lat           float64   `gorm:"column:lat"`
	Lng           float64   `gorm:"column:lng"`
	Resolved      bool      `gorm:"column:resolved"`
	FalsePositive bool      `gorm:"column:false_positive"`
}

func (threatEventRow) TableName() string { return "sentinel_threats" }

type threatActorRow struct {
	ID              string    `gorm:"primaryKey;column:id"`
	IP              string    `gorm:"uniqueIndex;column:ip"`
	FirstSeen       time.Time `gorm:"column:first_seen"`
	LastSeen        time.Time `gorm:"index;column:last_seen"`
	TotalRequests   int       `gorm:"column:total_requests"`
	ThreatCount     int       `gorm:"column:threat_count"`
	AttackTypes     string    `gorm:"column:attack_types"`
	TargetedRoutes  string    `gorm:"column:targeted_routes"`
	RiskScore       int       `gorm:"index;column:risk_score"`
	Status          string    `gorm:"column:status"`
	Country         string    `gorm:"column:country"`
	City            string    `gorm:"column:city"`
	ISP             string    `gorm:"column:isp"`
	IsKnownBadActor bool      `gorm:"column:is_known_bad_actor"`
	AbuseScore      int       `gorm:"column:abuse_score"`
	Lat             float64   `gorm:"column:lat"`
	Lng             float64   `gorm:"column:lng"`
}

func (threatActorRow) TableName() string { return "sentinel_actors" }

type userActivityRow struct {
	ID         string    `gorm:"primaryKey;column:id"`
	Timestamp  time.Time `gorm:"index;column:timestamp"`
	UserID     string    `gorm:"index;column:user_id"`
	UserEmail  string    `gorm:"column:user_email"`
	Action     string    `gorm:"column:action"`
	Path       string    `gorm:"column:path"`
	Method     string    `gorm:"column:method"`
	IP         string    `gorm:"column:ip"`
	UserAgent  string    `gorm:"column:user_agent"`
	StatusCode int       `gorm:"column:status_code"`
	Duration   int64     `gorm:"column:duration"`
	ThreatID   string    `gorm:"column:threat_id"`
	Country    string    `gorm:"column:country"`
}

func (userActivityRow) TableName() string { return "sentinel_user_activities" }

type auditLogRow struct {
	ID         string    `gorm:"primaryKey;column:id"`
	Timestamp  time.Time `gorm:"index;column:timestamp"`
	UserID     string    `gorm:"index;column:user_id"`
	UserEmail  string    `gorm:"column:user_email"`
	UserRole   string    `gorm:"column:user_role"`
	Action     string    `gorm:"index;column:action"`
	Resource   string    `gorm:"index;column:resource"`
	ResourceID string    `gorm:"column:resource_id"`
	Before     string    `gorm:"column:before_state"`
	After      string    `gorm:"column:after_state"`
	IP         string    `gorm:"column:ip"`
	UserAgent  string    `gorm:"column:user_agent"`
	Success    bool      `gorm:"column:success"`
	Error      string    `gorm:"column:error"`
	RequestID  string    `gorm:"column:request_id"`
}

func (auditLogRow) TableName() string { return "sentinel_audit_logs" }

type performanceMetricRow struct {
	ID           string    `gorm:"primaryKey;column:id"`
	Timestamp    time.Time `gorm:"index;column:timestamp"`
	Route        string    `gorm:"index;column:route"`
	Method       string    `gorm:"column:method"`
	StatusCode   int       `gorm:"column:status_code"`
	Duration     int64     `gorm:"column:duration"`
	ResponseSize int64     `gorm:"column:response_size"`
	IP           string    `gorm:"column:ip"`
	Error        string    `gorm:"column:error"`
}

func (performanceMetricRow) TableName() string { return "sentinel_performance" }

type blockedIPRow struct {
	IP        string     `gorm:"primaryKey;column:ip"`
	Reason    string     `gorm:"column:reason"`
	BlockedAt time.Time  `gorm:"column:blocked_at"`
	ExpiresAt *time.Time `gorm:"column:expires_at"`
	CIDR      bool       `gorm:"column:cidr"`
}

func (blockedIPRow) TableName() string { return "sentinel_blocked_ips" }

type whitelistedIPRow struct {
	IP          string    `gorm:"primaryKey;column:ip"`
	WhitelistAt time.Time `gorm:"column:whitelisted_at"`
}

func (whitelistedIPRow) TableName() string { return "sentinel_whitelisted_ips" }

type securityScoreRow struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	Score     string    `gorm:"column:score"` // JSON blob
	ComputedAt time.Time `gorm:"index;column:computed_at"`
}

func (securityScoreRow) TableName() string { return "sentinel_security_scores" }

// Migrate runs database schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(
		&threatEventRow{},
		&threatActorRow{},
		&userActivityRow{},
		&auditLogRow{},
		&performanceMetricRow{},
		&blockedIPRow{},
		&whitelistedIPRow{},
		&securityScoreRow{},
	)
}

// SaveThreat persists a threat event.
func (s *Store) SaveThreat(ctx context.Context, event *sentinel.ThreatEvent) error {
	row := threatToRow(event)
	return s.db.WithContext(ctx).Create(&row).Error
}

// GetThreat retrieves a single threat event by ID.
func (s *Store) GetThreat(ctx context.Context, id string) (*sentinel.ThreatEvent, error) {
	var row threatEventRow
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return rowToThreat(&row), nil
}

// ListThreats returns a paginated, filtered list of threat events.
func (s *Store) ListThreats(ctx context.Context, filter sentinel.ThreatFilter) ([]*sentinel.ThreatEvent, int64, error) {
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	query := s.db.WithContext(ctx).Model(&threatEventRow{})

	if filter.Severity != "" {
		query = query.Where("severity = ?", string(filter.Severity))
	}
	if filter.Type != "" {
		query = query.Where("threat_types LIKE ?", "%"+filter.Type+"%")
	}
	if filter.IP != "" {
		query = query.Where("ip = ?", filter.IP)
	}
	if filter.StartTime != nil {
		query = query.Where("timestamp >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("timestamp <= ?", *filter.EndTime)
	}
	if filter.Resolved != nil {
		query = query.Where("resolved = ?", *filter.Resolved)
	}
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		query = query.Where("path LIKE ? OR ip LIKE ? OR user_agent LIKE ?", search, search, search)
	}

	var total int64
	query.Count(&total)

	sortBy := "timestamp"
	if filter.SortBy != "" {
		sortBy = filter.SortBy
	}
	sortOrder := "DESC"
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}
	query = query.Order(sortBy + " " + sortOrder)

	offset := (filter.Page - 1) * filter.PageSize
	var rows []threatEventRow
	err := query.Offset(offset).Limit(filter.PageSize).Find(&rows).Error
	if err != nil {
		return nil, 0, err
	}

	var events []*sentinel.ThreatEvent
	for _, row := range rows {
		events = append(events, rowToThreat(&row))
	}

	return events, total, nil
}

// UpdateThreat updates specific fields of a threat event.
func (s *Store) UpdateThreat(ctx context.Context, id string, update sentinel.ThreatUpdate) error {
	updates := map[string]interface{}{}
	if update.Resolved != nil {
		updates["resolved"] = *update.Resolved
	}
	if update.FalsePositive != nil {
		updates["false_positive"] = *update.FalsePositive
	}
	if len(updates) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Model(&threatEventRow{}).Where("id = ?", id).Updates(updates).Error
}

// UpsertActor creates or updates a threat actor profile.
func (s *Store) UpsertActor(ctx context.Context, actor *sentinel.ThreatActor) error {
	row := actorToRow(actor)
	return s.db.WithContext(ctx).Save(&row).Error
}

// GetActor retrieves a threat actor by IP address.
func (s *Store) GetActor(ctx context.Context, ip string) (*sentinel.ThreatActor, error) {
	var row threatActorRow
	err := s.db.WithContext(ctx).Where("ip = ?", ip).First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return rowToActor(&row), nil
}

// ListActors returns a paginated, filtered list of threat actors.
func (s *Store) ListActors(ctx context.Context, filter sentinel.ActorFilter) ([]*sentinel.ThreatActor, int64, error) {
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	query := s.db.WithContext(ctx).Model(&threatActorRow{})

	if filter.Status != "" {
		query = query.Where("status = ?", string(filter.Status))
	}
	if filter.MinRisk > 0 {
		query = query.Where("risk_score >= ?", filter.MinRisk)
	}
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		query = query.Where("ip LIKE ? OR country LIKE ?", search, search)
	}

	var total int64
	query.Count(&total)

	query = query.Order("last_seen DESC")
	offset := (filter.Page - 1) * filter.PageSize
	var rows []threatActorRow
	err := query.Offset(offset).Limit(filter.PageSize).Find(&rows).Error
	if err != nil {
		return nil, 0, err
	}

	var actors []*sentinel.ThreatActor
	for _, row := range rows {
		actors = append(actors, rowToActor(&row))
	}

	return actors, total, nil
}

// SaveUserActivity persists a user activity record.
func (s *Store) SaveUserActivity(ctx context.Context, event *sentinel.UserActivity) error {
	row := activityToRow(event)
	return s.db.WithContext(ctx).Create(&row).Error
}

// ListUserActivity returns paginated user activity for a specific user.
func (s *Store) ListUserActivity(ctx context.Context, userID string, filter sentinel.ActivityFilter) ([]*sentinel.UserActivity, int64, error) {
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	query := s.db.WithContext(ctx).Model(&userActivityRow{}).Where("user_id = ?", userID)

	if filter.StartTime != nil {
		query = query.Where("timestamp >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("timestamp <= ?", *filter.EndTime)
	}
	if filter.Path != "" {
		query = query.Where("path LIKE ?", "%"+filter.Path+"%")
	}

	var total int64
	query.Count(&total)

	query = query.Order("timestamp DESC")
	offset := (filter.Page - 1) * filter.PageSize
	var rows []userActivityRow
	err := query.Offset(offset).Limit(filter.PageSize).Find(&rows).Error
	if err != nil {
		return nil, 0, err
	}

	var activities []*sentinel.UserActivity
	for _, row := range rows {
		activities = append(activities, rowToActivity(&row))
	}

	return activities, total, nil
}

// SaveAuditLog persists an audit log entry.
func (s *Store) SaveAuditLog(ctx context.Context, log *sentinel.AuditLog) error {
	row := auditToRow(log)
	return s.db.WithContext(ctx).Create(&row).Error
}

// ListAuditLogs returns a paginated, filtered list of audit logs.
func (s *Store) ListAuditLogs(ctx context.Context, filter sentinel.AuditFilter) ([]*sentinel.AuditLog, int64, error) {
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	query := s.db.WithContext(ctx).Model(&auditLogRow{})

	if filter.UserID != "" {
		query = query.Where("user_id = ?", filter.UserID)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if filter.Resource != "" {
		query = query.Where("resource = ?", filter.Resource)
	}
	if filter.StartTime != nil {
		query = query.Where("timestamp >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("timestamp <= ?", *filter.EndTime)
	}

	var total int64
	query.Count(&total)

	query = query.Order("timestamp DESC")
	offset := (filter.Page - 1) * filter.PageSize
	var rows []auditLogRow
	err := query.Offset(offset).Limit(filter.PageSize).Find(&rows).Error
	if err != nil {
		return nil, 0, err
	}

	var logs []*sentinel.AuditLog
	for _, row := range rows {
		logs = append(logs, rowToAudit(&row))
	}

	return logs, total, nil
}

// SavePerformanceMetric persists a performance measurement.
func (s *Store) SavePerformanceMetric(ctx context.Context, metric *sentinel.PerformanceMetric) error {
	row := perfToRow(metric)
	return s.db.WithContext(ctx).Create(&row).Error
}

// GetPerformanceOverview returns a snapshot of current system performance.
func (s *Store) GetPerformanceOverview(ctx context.Context) (*sentinel.PerformanceOverview, error) {
	var result struct {
		AvgDuration float64
		ErrorCount  int64
		Total       int64
	}

	s.db.WithContext(ctx).Model(&performanceMetricRow{}).
		Select("AVG(duration) as avg_duration, COUNT(*) as total, SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count").
		Scan(&result)

	errorRate := float64(0)
	if result.Total > 0 {
		errorRate = float64(result.ErrorCount) / float64(result.Total)
	}

	return &sentinel.PerformanceOverview{
		AvgResponseTime: result.AvgDuration,
		ErrorRate:       errorRate,
		TotalRequests:   result.Total,
		ComputedAt:      time.Now(),
	}, nil
}

// GetRouteMetrics returns per-route performance metrics.
func (s *Store) GetRouteMetrics(ctx context.Context) ([]*sentinel.RouteMetric, error) {
	var rows []performanceMetricRow
	s.db.WithContext(ctx).Find(&rows)

	type routeKey struct {
		Route  string
		Method string
	}

	grouped := make(map[routeKey][]int64)
	errorCounts := make(map[routeKey]int64)

	for _, m := range rows {
		key := routeKey{Route: m.Route, Method: m.Method}
		grouped[key] = append(grouped[key], m.Duration)
		if m.StatusCode >= 400 {
			errorCounts[key]++
		}
	}

	var metrics []*sentinel.RouteMetric
	for key, durations := range grouped {
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		total := int64(len(durations))
		metrics = append(metrics, &sentinel.RouteMetric{
			Route:        key.Route,
			Method:       key.Method,
			P50:          float64(percentile(durations, 50)),
			P95:          float64(percentile(durations, 95)),
			P99:          float64(percentile(durations, 99)),
			ErrorRate:    float64(errorCounts[key]) / float64(total),
			RequestCount: total,
		})
	}

	return metrics, nil
}

// BlockIP blocks an IP address with a reason and optional expiry.
func (s *Store) BlockIP(ctx context.Context, ip string, reason string, expiry *time.Time) error {
	row := blockedIPRow{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		ExpiresAt: expiry,
		CIDR:      strings.Contains(ip, "/"),
	}
	return s.db.WithContext(ctx).Save(&row).Error
}

// UnblockIP removes a block on an IP address.
func (s *Store) UnblockIP(ctx context.Context, ip string) error {
	return s.db.WithContext(ctx).Where("ip = ?", ip).Delete(&blockedIPRow{}).Error
}

// WhitelistIP adds an IP address to the whitelist.
func (s *Store) WhitelistIP(ctx context.Context, ip string) error {
	row := whitelistedIPRow{
		IP:          ip,
		WhitelistAt: time.Now(),
	}
	return s.db.WithContext(ctx).Save(&row).Error
}

// IsIPBlocked checks if an IP address is blocked.
func (s *Store) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	var count int64
	s.db.WithContext(ctx).Model(&blockedIPRow{}).
		Where("ip = ? AND (expires_at IS NULL OR expires_at > ?)", ip, time.Now()).
		Count(&count)
	return count > 0, nil
}

// IsIPWhitelisted checks if an IP address is whitelisted.
func (s *Store) IsIPWhitelisted(ctx context.Context, ip string) (bool, error) {
	var count int64
	s.db.WithContext(ctx).Model(&whitelistedIPRow{}).Where("ip = ?", ip).Count(&count)
	return count > 0, nil
}

// ListBlockedIPs returns all blocked IP addresses.
func (s *Store) ListBlockedIPs(ctx context.Context) ([]*sentinel.BlockedIP, error) {
	var rows []blockedIPRow
	err := s.db.WithContext(ctx).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}

	var result []*sentinel.BlockedIP
	for _, row := range rows {
		result = append(result, &sentinel.BlockedIP{
			IP:        row.IP,
			Reason:    row.Reason,
			BlockedAt: row.BlockedAt,
			ExpiresAt: row.ExpiresAt,
			CIDR:      row.CIDR,
		})
	}
	return result, nil
}

// GetThreatStats returns aggregated threat statistics for the given time window.
func (s *Store) GetThreatStats(ctx context.Context, window time.Duration) (*sentinel.ThreatStats, error) {
	cutoff := time.Now().Add(-window)
	stats := &sentinel.ThreatStats{}

	s.db.WithContext(ctx).Model(&threatEventRow{}).Where("timestamp >= ?", cutoff).Count(&stats.TotalThreats)

	s.db.WithContext(ctx).Model(&threatEventRow{}).
		Where("timestamp >= ? AND severity = ?", cutoff, string(sentinel.SeverityCritical)).
		Count(&stats.CriticalCount)
	s.db.WithContext(ctx).Model(&threatEventRow{}).
		Where("timestamp >= ? AND severity = ?", cutoff, string(sentinel.SeverityHigh)).
		Count(&stats.HighCount)
	s.db.WithContext(ctx).Model(&threatEventRow{}).
		Where("timestamp >= ? AND severity = ?", cutoff, string(sentinel.SeverityMedium)).
		Count(&stats.MediumCount)
	s.db.WithContext(ctx).Model(&threatEventRow{}).
		Where("timestamp >= ? AND severity = ?", cutoff, string(sentinel.SeverityLow)).
		Count(&stats.LowCount)
	s.db.WithContext(ctx).Model(&threatEventRow{}).
		Where("timestamp >= ? AND blocked = ?", cutoff, true).
		Count(&stats.BlockedCount)

	var uniqueCount int64
	s.db.WithContext(ctx).Model(&threatEventRow{}).
		Where("timestamp >= ?", cutoff).
		Distinct("ip").Count(&uniqueCount)
	stats.UniqueIPs = uniqueCount

	return stats, nil
}

// GetSecurityScore returns the current security score.
func (s *Store) GetSecurityScore(ctx context.Context) (*sentinel.SecurityScore, error) {
	var row securityScoreRow
	err := s.db.WithContext(ctx).Order("computed_at DESC").First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	var score sentinel.SecurityScore
	if err := json.Unmarshal([]byte(row.Score), &score); err != nil {
		return nil, err
	}
	return &score, nil
}

// SaveSecurityScore persists a computed security score.
func (s *Store) SaveSecurityScore(ctx context.Context, score *sentinel.SecurityScore) error {
	data, err := json.Marshal(score)
	if err != nil {
		return err
	}
	row := securityScoreRow{
		Score:      string(data),
		ComputedAt: score.ComputedAt,
	}
	return s.db.WithContext(ctx).Create(&row).Error
}

// Cleanup removes events older than the specified duration.
func (s *Store) Cleanup(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	s.db.WithContext(ctx).Where("timestamp < ?", cutoff).Delete(&threatEventRow{})
	s.db.WithContext(ctx).Where("timestamp < ?", cutoff).Delete(&userActivityRow{})
	s.db.WithContext(ctx).Where("timestamp < ?", cutoff).Delete(&performanceMetricRow{})
	s.db.WithContext(ctx).Where("timestamp < ?", cutoff).Delete(&auditLogRow{})
	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// ListUsers returns a summary of all users (stub).
func (s *Store) ListUsers(ctx context.Context) ([]*sentinel.UserSummary, error) {
	return []*sentinel.UserSummary{}, nil
}

// GetAttackTrends returns attack trend data for the given window and interval (stub).
func (s *Store) GetAttackTrends(ctx context.Context, window time.Duration, interval string) ([]*sentinel.AttackTrend, error) {
	return []*sentinel.AttackTrend{}, nil
}

// GetGeoStats returns geographic statistics for threats in the given window (stub).
func (s *Store) GetGeoStats(ctx context.Context, window time.Duration) ([]*sentinel.GeoStats, error) {
	return []*sentinel.GeoStats{}, nil
}

// GetTopTargets returns the most targeted routes in the given window (stub).
func (s *Store) GetTopTargets(ctx context.Context, window time.Duration, limit int) ([]*sentinel.TopTarget, error) {
	return []*sentinel.TopTarget{}, nil
}

// --- conversion helpers ---

func threatToRow(e *sentinel.ThreatEvent) threatEventRow {
	headers, _ := json.Marshal(e.Headers)
	types, _ := json.Marshal(e.ThreatTypes)
	evidence, _ := json.Marshal(e.Evidence)

	return threatEventRow{
		ID:            e.ID,
		Timestamp:     e.Timestamp,
		IP:            e.IP,
		ActorID:       e.ActorID,
		UserID:        e.UserID,
		Method:        e.Method,
		Path:          e.Path,
		StatusCode:    e.StatusCode,
		UserAgent:     e.UserAgent,
		Referer:       e.Referer,
		QueryParams:   e.QueryParams,
		BodySnippet:   e.BodySnippet,
		Headers:       string(headers),
		ThreatTypes:   string(types),
		Severity:      string(e.Severity),
		Confidence:    e.Confidence,
		Evidence:      string(evidence),
		Blocked:       e.Blocked,
		Country:       e.Country,
		City:          e.City,
		Lat:           e.Lat,
		Lng:           e.Lng,
		Resolved:      e.Resolved,
		FalsePositive: e.FalsePositive,
	}
}

func rowToThreat(r *threatEventRow) *sentinel.ThreatEvent {
	var headers sentinel.JSONMap
	json.Unmarshal([]byte(r.Headers), &headers)

	var types []string
	json.Unmarshal([]byte(r.ThreatTypes), &types)

	var evidence []sentinel.Evidence
	json.Unmarshal([]byte(r.Evidence), &evidence)

	return &sentinel.ThreatEvent{
		ID:            r.ID,
		Timestamp:     r.Timestamp,
		IP:            r.IP,
		ActorID:       r.ActorID,
		UserID:        r.UserID,
		Method:        r.Method,
		Path:          r.Path,
		StatusCode:    r.StatusCode,
		UserAgent:     r.UserAgent,
		Referer:       r.Referer,
		QueryParams:   r.QueryParams,
		BodySnippet:   r.BodySnippet,
		Headers:       headers,
		ThreatTypes:   types,
		Severity:      sentinel.Severity(r.Severity),
		Confidence:    r.Confidence,
		Evidence:      evidence,
		Blocked:       r.Blocked,
		Country:       r.Country,
		City:          r.City,
		Lat:           r.Lat,
		Lng:           r.Lng,
		Resolved:      r.Resolved,
		FalsePositive: r.FalsePositive,
	}
}

func actorToRow(a *sentinel.ThreatActor) threatActorRow {
	types, _ := json.Marshal(a.AttackTypes)
	routes, _ := json.Marshal(a.TargetedRoutes)

	return threatActorRow{
		ID:              a.ID,
		IP:              a.IP,
		FirstSeen:       a.FirstSeen,
		LastSeen:        a.LastSeen,
		TotalRequests:   a.TotalRequests,
		ThreatCount:     a.ThreatCount,
		AttackTypes:     string(types),
		TargetedRoutes:  string(routes),
		RiskScore:       a.RiskScore,
		Status:          string(a.Status),
		Country:         a.Country,
		City:            a.City,
		ISP:             a.ISP,
		IsKnownBadActor: a.IsKnownBadActor,
		AbuseScore:      a.AbuseScore,
		Lat:             a.Lat,
		Lng:             a.Lng,
	}
}

func rowToActor(r *threatActorRow) *sentinel.ThreatActor {
	var types []string
	json.Unmarshal([]byte(r.AttackTypes), &types)

	var routes []string
	json.Unmarshal([]byte(r.TargetedRoutes), &routes)

	return &sentinel.ThreatActor{
		ID:              r.ID,
		IP:              r.IP,
		FirstSeen:       r.FirstSeen,
		LastSeen:        r.LastSeen,
		TotalRequests:   r.TotalRequests,
		ThreatCount:     r.ThreatCount,
		AttackTypes:     types,
		TargetedRoutes:  routes,
		RiskScore:       r.RiskScore,
		Status:          sentinel.ActorStatus(r.Status),
		Country:         r.Country,
		City:            r.City,
		ISP:             r.ISP,
		IsKnownBadActor: r.IsKnownBadActor,
		AbuseScore:      r.AbuseScore,
		Lat:             r.Lat,
		Lng:             r.Lng,
	}
}

func activityToRow(a *sentinel.UserActivity) userActivityRow {
	return userActivityRow{
		ID:         a.ID,
		Timestamp:  a.Timestamp,
		UserID:     a.UserID,
		UserEmail:  a.UserEmail,
		Action:     a.Action,
		Path:       a.Path,
		Method:     a.Method,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
		StatusCode: a.StatusCode,
		Duration:   a.Duration,
		ThreatID:   a.ThreatID,
		Country:    a.Country,
	}
}

func rowToActivity(r *userActivityRow) *sentinel.UserActivity {
	return &sentinel.UserActivity{
		ID:         r.ID,
		Timestamp:  r.Timestamp,
		UserID:     r.UserID,
		UserEmail:  r.UserEmail,
		Action:     r.Action,
		Path:       r.Path,
		Method:     r.Method,
		IP:         r.IP,
		UserAgent:  r.UserAgent,
		StatusCode: r.StatusCode,
		Duration:   r.Duration,
		ThreatID:   r.ThreatID,
		Country:    r.Country,
	}
}

func auditToRow(a *sentinel.AuditLog) auditLogRow {
	before, _ := json.Marshal(a.Before)
	after, _ := json.Marshal(a.After)

	return auditLogRow{
		ID:         a.ID,
		Timestamp:  a.Timestamp,
		UserID:     a.UserID,
		UserEmail:  a.UserEmail,
		UserRole:   a.UserRole,
		Action:     a.Action,
		Resource:   a.Resource,
		ResourceID: a.ResourceID,
		Before:     string(before),
		After:      string(after),
		IP:         a.IP,
		UserAgent:  a.UserAgent,
		Success:    a.Success,
		Error:      a.Error,
		RequestID:  a.RequestID,
	}
}

func rowToAudit(r *auditLogRow) *sentinel.AuditLog {
	var before, after sentinel.JSONMap
	json.Unmarshal([]byte(r.Before), &before)
	json.Unmarshal([]byte(r.After), &after)

	return &sentinel.AuditLog{
		ID:         r.ID,
		Timestamp:  r.Timestamp,
		UserID:     r.UserID,
		UserEmail:  r.UserEmail,
		UserRole:   r.UserRole,
		Action:     r.Action,
		Resource:   r.Resource,
		ResourceID: r.ResourceID,
		Before:     before,
		After:      after,
		IP:         r.IP,
		UserAgent:  r.UserAgent,
		Success:    r.Success,
		Error:      r.Error,
		RequestID:  r.RequestID,
	}
}

func perfToRow(m *sentinel.PerformanceMetric) performanceMetricRow {
	return performanceMetricRow{
		ID:           m.ID,
		Timestamp:    m.Timestamp,
		Route:        m.Route,
		Method:       m.Method,
		StatusCode:   m.StatusCode,
		Duration:     m.Duration,
		ResponseSize: m.ResponseSize,
		IP:           m.IP,
		Error:        m.Error,
	}
}

func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
