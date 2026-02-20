// Package memory provides an in-memory storage adapter for Sentinel.
// It is thread-safe and intended for development and testing.
package memory

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/storage"
)

// Ensure Store implements storage.Store.
var _ storage.Store = (*Store)(nil)

// Store is an in-memory implementation of the storage.Store interface.
type Store struct {
	mu             sync.RWMutex
	threats        map[string]*sentinel.ThreatEvent
	actors         map[string]*sentinel.ThreatActor
	userActivities map[string][]*sentinel.UserActivity
	auditLogs      []*sentinel.AuditLog
	perfMetrics    []*sentinel.PerformanceMetric
	blockedIPs     map[string]*sentinel.BlockedIP
	whitelistedIPs map[string]*sentinel.WhitelistedIP
	securityScore  *sentinel.SecurityScore
	threatList     []string // ordered threat IDs by timestamp desc
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		threats:        make(map[string]*sentinel.ThreatEvent),
		actors:         make(map[string]*sentinel.ThreatActor),
		userActivities: make(map[string][]*sentinel.UserActivity),
		blockedIPs:     make(map[string]*sentinel.BlockedIP),
		whitelistedIPs: make(map[string]*sentinel.WhitelistedIP),
	}
}

// SaveThreat persists a threat event.
func (s *Store) SaveThreat(ctx context.Context, event *sentinel.ThreatEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.threats[event.ID] = event
	s.threatList = append([]string{event.ID}, s.threatList...)
	return nil
}

// GetThreat retrieves a single threat event by ID.
func (s *Store) GetThreat(ctx context.Context, id string) (*sentinel.ThreatEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.threats[id]
	if !ok {
		return nil, nil
	}
	return t, nil
}

// ListThreats returns a paginated, filtered list of threat events.
func (s *Store) ListThreats(ctx context.Context, filter sentinel.ThreatFilter) ([]*sentinel.ThreatEvent, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	var filtered []*sentinel.ThreatEvent
	for _, id := range s.threatList {
		t := s.threats[id]
		if t == nil {
			continue
		}
		if !matchesThreatFilter(t, filter) {
			continue
		}
		filtered = append(filtered, t)
	}

	sortThreats(filtered, filter.SortBy, filter.SortOrder)

	total := int64(len(filtered))
	start := (filter.Page - 1) * filter.PageSize
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + filter.PageSize
	if end > int(total) {
		end = int(total)
	}

	return filtered[start:end], total, nil
}

// UpdateThreat updates specific fields of a threat event.
func (s *Store) UpdateThreat(ctx context.Context, id string, update sentinel.ThreatUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.threats[id]
	if !ok {
		return nil
	}
	if update.Resolved != nil {
		t.Resolved = *update.Resolved
	}
	if update.FalsePositive != nil {
		t.FalsePositive = *update.FalsePositive
	}
	return nil
}

// UpsertActor creates or updates a threat actor profile.
func (s *Store) UpsertActor(ctx context.Context, actor *sentinel.ThreatActor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actors[actor.IP] = actor
	return nil
}

// GetActor retrieves a threat actor by IP address.
func (s *Store) GetActor(ctx context.Context, ip string) (*sentinel.ThreatActor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.actors[ip]
	if !ok {
		return nil, nil
	}
	return a, nil
}

// ListActors returns a paginated, filtered list of threat actors.
func (s *Store) ListActors(ctx context.Context, filter sentinel.ActorFilter) ([]*sentinel.ThreatActor, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	var filtered []*sentinel.ThreatActor
	for _, a := range s.actors {
		if filter.Status != "" && a.Status != filter.Status {
			continue
		}
		if filter.MinRisk > 0 && a.RiskScore < filter.MinRisk {
			continue
		}
		if filter.Search != "" && !strings.Contains(a.IP, filter.Search) &&
			!strings.Contains(a.Country, filter.Search) {
			continue
		}
		filtered = append(filtered, a)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].LastSeen.After(filtered[j].LastSeen)
	})

	total := int64(len(filtered))
	start := (filter.Page - 1) * filter.PageSize
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + filter.PageSize
	if end > int(total) {
		end = int(total)
	}

	return filtered[start:end], total, nil
}

// SaveUserActivity persists a user activity record.
func (s *Store) SaveUserActivity(ctx context.Context, event *sentinel.UserActivity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userActivities[event.UserID] = append(s.userActivities[event.UserID], event)
	return nil
}

// ListUserActivity returns paginated user activity for a specific user.
func (s *Store) ListUserActivity(ctx context.Context, userID string, filter sentinel.ActivityFilter) ([]*sentinel.UserActivity, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	activities := s.userActivities[userID]
	var filtered []*sentinel.UserActivity
	for _, a := range activities {
		if filter.StartTime != nil && a.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && a.Timestamp.After(*filter.EndTime) {
			continue
		}
		if filter.Path != "" && !strings.Contains(a.Path, filter.Path) {
			continue
		}
		filtered = append(filtered, a)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	total := int64(len(filtered))
	start := (filter.Page - 1) * filter.PageSize
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + filter.PageSize
	if end > int(total) {
		end = int(total)
	}

	return filtered[start:end], total, nil
}

// SaveAuditLog persists an audit log entry.
func (s *Store) SaveAuditLog(ctx context.Context, log *sentinel.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs = append([]*sentinel.AuditLog{log}, s.auditLogs...)
	return nil
}

// ListAuditLogs returns a paginated, filtered list of audit logs.
func (s *Store) ListAuditLogs(ctx context.Context, filter sentinel.AuditFilter) ([]*sentinel.AuditLog, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	var filtered []*sentinel.AuditLog
	for _, l := range s.auditLogs {
		if filter.UserID != "" && l.UserID != filter.UserID {
			continue
		}
		if filter.Action != "" && l.Action != filter.Action {
			continue
		}
		if filter.Resource != "" && l.Resource != filter.Resource {
			continue
		}
		if filter.StartTime != nil && l.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && l.Timestamp.After(*filter.EndTime) {
			continue
		}
		filtered = append(filtered, l)
	}

	total := int64(len(filtered))
	start := (filter.Page - 1) * filter.PageSize
	if start >= int(total) {
		return nil, total, nil
	}
	end := start + filter.PageSize
	if end > int(total) {
		end = int(total)
	}

	return filtered[start:end], total, nil
}

// SavePerformanceMetric persists a performance measurement.
func (s *Store) SavePerformanceMetric(ctx context.Context, metric *sentinel.PerformanceMetric) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perfMetrics = append(s.perfMetrics, metric)
	return nil
}

// GetPerformanceOverview returns a snapshot of current system performance.
func (s *Store) GetPerformanceOverview(ctx context.Context) (*sentinel.PerformanceOverview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.perfMetrics) == 0 {
		return &sentinel.PerformanceOverview{ComputedAt: time.Now()}, nil
	}

	var totalDuration int64
	var errorCount int64
	for _, m := range s.perfMetrics {
		totalDuration += m.Duration
		if m.StatusCode >= 400 {
			errorCount++
		}
	}

	total := int64(len(s.perfMetrics))
	return &sentinel.PerformanceOverview{
		AvgResponseTime: float64(totalDuration) / float64(total),
		ErrorRate:       float64(errorCount) / float64(total),
		TotalRequests:   total,
		ComputedAt:      time.Now(),
	}, nil
}

// GetRouteMetrics returns per-route performance metrics.
func (s *Store) GetRouteMetrics(ctx context.Context) ([]*sentinel.RouteMetric, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type routeKey struct {
		Route  string
		Method string
	}

	grouped := make(map[routeKey][]int64)
	errorCounts := make(map[routeKey]int64)

	for _, m := range s.perfMetrics {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockedIPs[ip] = &sentinel.BlockedIP{
		IP:        ip,
		Reason:    reason,
		BlockedAt: time.Now(),
		ExpiresAt: expiry,
	}
	return nil
}

// UnblockIP removes a block on an IP address.
func (s *Store) UnblockIP(ctx context.Context, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blockedIPs, ip)
	return nil
}

// WhitelistIP adds an IP address to the whitelist.
func (s *Store) WhitelistIP(ctx context.Context, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.whitelistedIPs[ip] = &sentinel.WhitelistedIP{
		IP:          ip,
		WhitelistAt: time.Now(),
	}
	return nil
}

// IsIPBlocked checks if an IP address is blocked.
func (s *Store) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.blockedIPs[ip]
	if !ok {
		return false, nil
	}
	if b.ExpiresAt != nil && b.ExpiresAt.Before(time.Now()) {
		return false, nil
	}
	return true, nil
}

// IsIPWhitelisted checks if an IP address is whitelisted.
func (s *Store) IsIPWhitelisted(ctx context.Context, ip string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.whitelistedIPs[ip]
	return ok, nil
}

// ListBlockedIPs returns all blocked IP addresses.
func (s *Store) ListBlockedIPs(ctx context.Context) ([]*sentinel.BlockedIP, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*sentinel.BlockedIP
	now := time.Now()
	for _, b := range s.blockedIPs {
		if b.ExpiresAt != nil && b.ExpiresAt.Before(now) {
			continue
		}
		result = append(result, b)
	}
	return result, nil
}

// GetThreatStats returns aggregated threat statistics for the given time window.
func (s *Store) GetThreatStats(ctx context.Context, window time.Duration) (*sentinel.ThreatStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	stats := &sentinel.ThreatStats{}
	uniqueIPs := make(map[string]bool)
	typeCounts := make(map[string]int64)

	for _, t := range s.threats {
		if t.Timestamp.Before(cutoff) {
			continue
		}
		stats.TotalThreats++
		if t.Blocked {
			stats.BlockedCount++
		}
		uniqueIPs[t.IP] = true

		switch t.Severity {
		case sentinel.SeverityCritical:
			stats.CriticalCount++
		case sentinel.SeverityHigh:
			stats.HighCount++
		case sentinel.SeverityMedium:
			stats.MediumCount++
		case sentinel.SeverityLow:
			stats.LowCount++
		}

		for _, tt := range t.ThreatTypes {
			typeCounts[tt]++
		}
	}

	stats.UniqueIPs = int64(len(uniqueIPs))
	for typ, count := range typeCounts {
		stats.TopAttackTypes = append(stats.TopAttackTypes, sentinel.AttackTypeStat{
			Type:  typ,
			Count: count,
		})
	}
	sort.Slice(stats.TopAttackTypes, func(i, j int) bool {
		return stats.TopAttackTypes[i].Count > stats.TopAttackTypes[j].Count
	})

	return stats, nil
}

// GetSecurityScore returns the current security score.
func (s *Store) GetSecurityScore(ctx context.Context) (*sentinel.SecurityScore, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.securityScore, nil
}

// SaveSecurityScore persists a computed security score.
func (s *Store) SaveSecurityScore(ctx context.Context, score *sentinel.SecurityScore) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.securityScore = score
	return nil
}

// Migrate is a no-op for the memory store.
func (s *Store) Migrate(ctx context.Context) error {
	return nil
}

// Cleanup removes events older than the specified duration.
func (s *Store) Cleanup(ctx context.Context, olderThan time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)

	var newThreatList []string
	for _, id := range s.threatList {
		t := s.threats[id]
		if t != nil && t.Timestamp.Before(cutoff) {
			delete(s.threats, id)
		} else {
			newThreatList = append(newThreatList, id)
		}
	}
	s.threatList = newThreatList

	var newMetrics []*sentinel.PerformanceMetric
	for _, m := range s.perfMetrics {
		if m.Timestamp.After(cutoff) {
			newMetrics = append(newMetrics, m)
		}
	}
	s.perfMetrics = newMetrics

	return nil
}

// Close is a no-op for the memory store.
func (s *Store) Close() error {
	return nil
}

// ListUsers returns a summary of all users with activity.
func (s *Store) ListUsers(ctx context.Context) ([]*sentinel.UserSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build a map of user threat counts from threats.
	threatCounts := make(map[string]int64)
	for _, t := range s.threats {
		if t.UserID != "" {
			threatCounts[t.UserID]++
		}
	}

	var result []*sentinel.UserSummary
	for userID, activities := range s.userActivities {
		if len(activities) == 0 {
			continue
		}

		var email string
		var lastSeen time.Time
		for _, a := range activities {
			if a.UserEmail != "" {
				email = a.UserEmail
			}
			if a.Timestamp.After(lastSeen) {
				lastSeen = a.Timestamp
			}
		}

		result = append(result, &sentinel.UserSummary{
			UserID:        userID,
			Email:         email,
			ActivityCount: int64(len(activities)),
			ThreatCount:   threatCounts[userID],
			LastSeen:      lastSeen,
		})
	}

	// Sort by last seen descending for deterministic output.
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastSeen.After(result[j].LastSeen)
	})

	return result, nil
}

// GetAttackTrends returns time-series attack data grouped by the given interval.
func (s *Store) GetAttackTrends(ctx context.Context, window time.Duration, interval string) ([]*sentinel.AttackTrend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-window)

	// Map from period string to trend data.
	trendMap := make(map[string]*sentinel.AttackTrend)

	for _, t := range s.threats {
		if t.Timestamp.Before(cutoff) {
			continue
		}

		var period string
		switch interval {
		case "hour":
			period = t.Timestamp.UTC().Truncate(time.Hour).Format("2006-01-02T15:00")
		default: // "day" or anything else
			period = t.Timestamp.UTC().Truncate(24 * time.Hour).Format("2006-01-02")
		}

		trend, ok := trendMap[period]
		if !ok {
			trend = &sentinel.AttackTrend{
				Period: period,
				ByType: make(map[string]int64),
			}
			trendMap[period] = trend
		}
		trend.Total++
		for _, tt := range t.ThreatTypes {
			trend.ByType[tt]++
		}
	}

	var result []*sentinel.AttackTrend
	for _, trend := range trendMap {
		result = append(result, trend)
	}

	// Sort by period ascending.
	sort.Slice(result, func(i, j int) bool {
		return result[i].Period < result[j].Period
	})

	return result, nil
}

// GetGeoStats returns geographic attack statistics within the given window.
func (s *Store) GetGeoStats(ctx context.Context, window time.Duration) ([]*sentinel.GeoStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-window)

	type geoKey struct {
		Country     string
		CountryCode string
	}

	geoMap := make(map[geoKey]*sentinel.GeoStats)

	for _, t := range s.threats {
		if t.Timestamp.Before(cutoff) {
			continue
		}
		if t.Country == "" {
			continue
		}

		key := geoKey{Country: t.Country, CountryCode: t.Country}
		gs, ok := geoMap[key]
		if !ok {
			gs = &sentinel.GeoStats{
				Country:     t.Country,
				CountryCode: t.Country,
				Lat:         t.Lat,
				Lng:         t.Lng,
			}
			geoMap[key] = gs
		}
		gs.Count++
	}

	var result []*sentinel.GeoStats
	for _, gs := range geoMap {
		result = append(result, gs)
	}

	// Sort by count descending.
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	return result, nil
}

// GetTopTargets returns the most targeted routes within the given window.
func (s *Store) GetTopTargets(ctx context.Context, window time.Duration, limit int) ([]*sentinel.TopTarget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-window)

	type routeKey struct {
		Route  string
		Method string
	}

	counts := make(map[routeKey]int64)

	for _, t := range s.threats {
		if t.Timestamp.Before(cutoff) {
			continue
		}
		key := routeKey{Route: t.Path, Method: t.Method}
		counts[key]++
	}

	var result []*sentinel.TopTarget
	for key, count := range counts {
		result = append(result, &sentinel.TopTarget{
			Route:  key.Route,
			Method: key.Method,
			Count:  count,
		})
	}

	// Sort by count descending.
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

func matchesThreatFilter(t *sentinel.ThreatEvent, f sentinel.ThreatFilter) bool {
	if f.Severity != "" && t.Severity != f.Severity {
		return false
	}
	if f.Type != "" {
		found := false
		for _, tt := range t.ThreatTypes {
			if tt == f.Type {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.IP != "" && t.IP != f.IP {
		return false
	}
	if f.StartTime != nil && t.Timestamp.Before(*f.StartTime) {
		return false
	}
	if f.EndTime != nil && t.Timestamp.After(*f.EndTime) {
		return false
	}
	if f.UserID != "" && t.UserID != f.UserID {
		return false
	}
	if f.Resolved != nil && t.Resolved != *f.Resolved {
		return false
	}
	if f.Search != "" {
		search := strings.ToLower(f.Search)
		if !strings.Contains(strings.ToLower(t.Path), search) &&
			!strings.Contains(strings.ToLower(t.IP), search) &&
			!strings.Contains(strings.ToLower(t.UserAgent), search) {
			return false
		}
	}
	return true
}

func sortThreats(threats []*sentinel.ThreatEvent, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "timestamp"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}
	desc := sortOrder == "desc"

	sort.Slice(threats, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "severity":
			less = severityOrder(threats[i].Severity) < severityOrder(threats[j].Severity)
		case "ip":
			less = threats[i].IP < threats[j].IP
		default:
			less = threats[i].Timestamp.Before(threats[j].Timestamp)
		}
		if desc {
			return !less
		}
		return less
	})
}

func severityOrder(s sentinel.Severity) int {
	switch s {
	case sentinel.SeverityLow:
		return 1
	case sentinel.SeverityMedium:
		return 2
	case sentinel.SeverityHigh:
		return 3
	case sentinel.SeverityCritical:
		return 4
	default:
		return 0
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
