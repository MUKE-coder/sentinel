// Package reports provides compliance report generation for GDPR, PCI-DSS, and SOC2.
package reports

import (
	"context"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/storage"
)

// Generator produces compliance reports from stored Sentinel data.
type Generator struct {
	store storage.Store
}

// NewGenerator creates a new compliance report generator.
func NewGenerator(store storage.Store) *Generator {
	return &Generator{store: store}
}

// --- GDPR Report ---

// GDPRReport is a GDPR compliance report.
type GDPRReport struct {
	GeneratedAt    time.Time               `json:"generated_at"`
	WindowStart    time.Time               `json:"window_start"`
	WindowEnd      time.Time               `json:"window_end"`
	UserDataAccess []GDPRUserAccess        `json:"user_data_access"`
	DataExports    []*sentinel.AuditLog    `json:"data_exports"`
	DataDeletions  []*sentinel.AuditLog    `json:"data_deletions"`
	UnusualAccess  []*sentinel.ThreatEvent `json:"unusual_access"`
	Summary        GDPRSummary             `json:"summary"`
}

// GDPRUserAccess summarizes data access for a single user.
type GDPRUserAccess struct {
	UserID        string   `json:"user_id"`
	RoutesAccessed []string `json:"routes_accessed"`
	AccessCount   int      `json:"access_count"`
	LastAccess    time.Time `json:"last_access"`
}

// GDPRSummary contains aggregate GDPR metrics.
type GDPRSummary struct {
	TotalUsers         int `json:"total_users"`
	TotalDataAccesses  int `json:"total_data_accesses"`
	TotalExports       int `json:"total_exports"`
	TotalDeletions     int `json:"total_deletions"`
	UnusualAccessCount int `json:"unusual_access_count"`
}

// GenerateGDPR produces a GDPR compliance report for the given time window.
func (g *Generator) GenerateGDPR(ctx context.Context, window time.Duration) (*GDPRReport, error) {
	now := time.Now()
	start := now.Add(-window)

	report := &GDPRReport{
		GeneratedAt: now,
		WindowStart: start,
		WindowEnd:   now,
	}

	// Collect user data access from user activity
	users, err := g.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		activities, _, err := g.store.ListUserActivity(ctx, user.UserID, sentinel.ActivityFilter{
			StartTime: &start,
			EndTime:   &now,
			Page:      1,
			PageSize:  1000,
		})
		if err != nil {
			continue
		}

		if len(activities) == 0 {
			continue
		}

		routeSet := make(map[string]bool)
		var lastAccess time.Time
		for _, a := range activities {
			routeSet[a.Path] = true
			if a.Timestamp.After(lastAccess) {
				lastAccess = a.Timestamp
			}
		}
		routes := make([]string, 0, len(routeSet))
		for r := range routeSet {
			routes = append(routes, r)
		}

		report.UserDataAccess = append(report.UserDataAccess, GDPRUserAccess{
			UserID:         user.UserID,
			RoutesAccessed: routes,
			AccessCount:    len(activities),
			LastAccess:     lastAccess,
		})
	}

	// Data export audit logs (READ actions could be exports)
	exports, _, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		Action:    "READ",
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.DataExports = exports
	}

	// Data deletion audit logs
	deletions, _, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		Action:    "DELETE",
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.DataDeletions = deletions
	}

	// Unusual access (anomaly-related threats)
	unusualThreats, _, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		Type:      "AnomalyDetected",
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.UnusualAccess = unusualThreats
	}

	report.Summary = GDPRSummary{
		TotalUsers:         len(report.UserDataAccess),
		TotalDataAccesses:  sumUserAccess(report.UserDataAccess),
		TotalExports:       len(report.DataExports),
		TotalDeletions:     len(report.DataDeletions),
		UnusualAccessCount: len(report.UnusualAccess),
	}

	return report, nil
}

// --- PCI-DSS Report ---

// PCIDSSReport is a PCI-DSS compliance report.
type PCIDSSReport struct {
	GeneratedAt        time.Time               `json:"generated_at"`
	AuthEvents         PCIAuthEvents           `json:"auth_events"`
	SecurityIncidents  []*sentinel.ThreatEvent `json:"security_incidents"`
	BlockedThreats     []*sentinel.ThreatEvent `json:"blocked_threats"`
	Summary            PCIDSSSummary           `json:"summary"`
}

// PCIAuthEvents contains authentication event metrics.
type PCIAuthEvents struct {
	TotalAttempts int `json:"total_attempts"`
	SuccessCount  int `json:"success_count"`
	FailureCount  int `json:"failure_count"`
	FailureRate   float64 `json:"failure_rate"`
}

// PCIDSSSummary contains aggregate PCI-DSS metrics.
type PCIDSSSummary struct {
	TotalIncidents     int `json:"total_incidents"`
	CriticalIncidents  int `json:"critical_incidents"`
	HighIncidents      int `json:"high_incidents"`
	BlockedCount       int `json:"blocked_count"`
	UniqueAttackerIPs  int `json:"unique_attacker_ips"`
}

// GeneratePCIDSS produces a PCI-DSS compliance report for the last 90 days.
func (g *Generator) GeneratePCIDSS(ctx context.Context) (*PCIDSSReport, error) {
	now := time.Now()
	start := now.Add(-90 * 24 * time.Hour)

	report := &PCIDSSReport{
		GeneratedAt: now,
	}

	// Authentication events from audit logs
	authLogs, _, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		Resource:  "auth",
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  5000,
	})
	if err == nil {
		successCount := 0
		failureCount := 0
		for _, al := range authLogs {
			if al.Success {
				successCount++
			} else {
				failureCount++
			}
		}
		total := successCount + failureCount
		var failRate float64
		if total > 0 {
			failRate = float64(failureCount) / float64(total) * 100
		}
		report.AuthEvents = PCIAuthEvents{
			TotalAttempts: total,
			SuccessCount:  successCount,
			FailureCount:  failureCount,
			FailureRate:   failRate,
		}
	}

	// Security incidents (all threats in 90 days)
	incidents, _, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  5000,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})
	if err == nil {
		report.SecurityIncidents = incidents
	}

	// Blocked threats
	blocked := true
	blockedThreats, _, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		StartTime: &start,
		EndTime:   &now,
		Resolved:  &blocked,
		Page:      1,
		PageSize:  5000,
	})
	if err == nil {
		report.BlockedThreats = blockedThreats
	}

	// Compute summary
	critCount := 0
	highCount := 0
	blockedCount := 0
	ipSet := make(map[string]bool)
	for _, t := range report.SecurityIncidents {
		if t.Severity == sentinel.SeverityCritical {
			critCount++
		}
		if t.Severity == sentinel.SeverityHigh {
			highCount++
		}
		if t.Blocked {
			blockedCount++
		}
		ipSet[t.IP] = true
	}

	report.Summary = PCIDSSSummary{
		TotalIncidents:    len(report.SecurityIncidents),
		CriticalIncidents: critCount,
		HighIncidents:     highCount,
		BlockedCount:      blockedCount,
		UniqueAttackerIPs: len(ipSet),
	}

	return report, nil
}

// --- SOC2 Report ---

// SOC2Report is a SOC2 compliance report.
type SOC2Report struct {
	GeneratedAt       time.Time               `json:"generated_at"`
	WindowStart       time.Time               `json:"window_start"`
	WindowEnd         time.Time               `json:"window_end"`
	MonitoringEvidence SOC2Monitoring          `json:"monitoring_evidence"`
	IncidentResponse  []*sentinel.ThreatEvent `json:"incident_response"`
	AccessControl     SOC2AccessControl       `json:"access_control"`
	AnomalyEvents     []*sentinel.ThreatEvent `json:"anomaly_events"`
	Summary           SOC2Summary             `json:"summary"`
}

// SOC2Monitoring contains security monitoring evidence.
type SOC2Monitoring struct {
	TotalEventsProcessed int64              `json:"total_events_processed"`
	ThreatStats          *sentinel.ThreatStats `json:"threat_stats"`
	SecurityScore        *sentinel.SecurityScore `json:"security_score"`
}

// SOC2AccessControl contains access control evidence.
type SOC2AccessControl struct {
	TotalUsers    int                    `json:"total_users"`
	AuditLogs     []*sentinel.AuditLog   `json:"audit_logs"`
	BlockedIPs    []*sentinel.BlockedIP  `json:"blocked_ips"`
}

// SOC2Summary contains aggregate SOC2 metrics.
type SOC2Summary struct {
	TotalThreatsDetected int `json:"total_threats_detected"`
	TotalThreatsBlocked  int `json:"total_threats_blocked"`
	TotalAnomalies       int `json:"total_anomalies"`
	TotalAuditEntries    int `json:"total_audit_entries"`
	ActiveBlockedIPs     int `json:"active_blocked_ips"`
}

// GenerateSOC2 produces a SOC2 compliance report for the given time window.
func (g *Generator) GenerateSOC2(ctx context.Context, window time.Duration) (*SOC2Report, error) {
	now := time.Now()
	start := now.Add(-window)

	report := &SOC2Report{
		GeneratedAt: now,
		WindowStart: start,
		WindowEnd:   now,
	}

	// Monitoring evidence
	stats, err := g.store.GetThreatStats(ctx, window)
	if err == nil {
		report.MonitoringEvidence.ThreatStats = stats
		if stats != nil {
			report.MonitoringEvidence.TotalEventsProcessed = stats.TotalThreats +
				stats.BlockedCount + stats.UniqueIPs
		}
	}

	score, err := g.store.GetSecurityScore(ctx)
	if err == nil {
		report.MonitoringEvidence.SecurityScore = score
	}

	// Incident response — resolved threats
	resolved := true
	incidents, _, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		StartTime: &start,
		EndTime:   &now,
		Resolved:  &resolved,
		Page:      1,
		PageSize:  1000,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})
	if err == nil {
		report.IncidentResponse = incidents
	}

	// Access control
	users, err := g.store.ListUsers(ctx)
	if err == nil {
		report.AccessControl.TotalUsers = len(users)
	}

	auditLogs, _, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  1000,
	})
	if err == nil {
		report.AccessControl.AuditLogs = auditLogs
	}

	blockedIPs, err := g.store.ListBlockedIPs(ctx)
	if err == nil {
		report.AccessControl.BlockedIPs = blockedIPs
	}

	// Anomaly events
	anomalies, _, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		Type:      "AnomalyDetected",
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.AnomalyEvents = anomalies
	}

	// Summary
	allThreats, _, _ := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  1,
	})
	blockedCount := 0
	for _, t := range allThreats {
		if t.Blocked {
			blockedCount++
		}
	}

	report.Summary = SOC2Summary{
		TotalThreatsDetected: len(report.IncidentResponse),
		TotalThreatsBlocked:  blockedCount,
		TotalAnomalies:       len(report.AnomalyEvents),
		TotalAuditEntries:    len(report.AccessControl.AuditLogs),
		ActiveBlockedIPs:     len(report.AccessControl.BlockedIPs),
	}

	return report, nil
}

// --- Helpers ---

func sumUserAccess(access []GDPRUserAccess) int {
	total := 0
	for _, a := range access {
		total += a.AccessCount
	}
	return total
}
