// Package reports provides compliance report generation for GDPR, PCI-DSS, and SOC2.
package reports

import (
	"context"
	"fmt"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/storage"
)

// Generator produces compliance reports from stored Sentinel data.
type Generator struct {
	store  storage.Store
	source SourceInfo
}

// NewGenerator creates a new compliance report generator.
func NewGenerator(store storage.Store) *Generator {
	return &Generator{store: store}
}

// SourceInfo describes the store behind a Generator so reports can say how
// durable and complete their data is. Sentinel's API server sets it from the
// mounted config; the zero value means "unknown", and reports say so.
type SourceInfo struct {
	StorageDriver        string
	RetentionDays        int
	AuditRetentionDays   int
	UserActivityRecorded bool
}

// SetSourceInfo tells the generator about the store behind it.
func (g *Generator) SetSourceInfo(info SourceInfo) {
	g.source = info
}

// Provenance is attached to every report: where the data came from, how long
// it is kept, and the ways it can fall short of a complete record. A
// compliance report is only as good as the data under it — these fields
// exist so an empty or short section can't pass for a clean one.
type Provenance struct {
	StorageDriver      string     `json:"storage_driver,omitempty"`
	Durable            bool       `json:"durable"`
	RetentionDays      int        `json:"retention_days,omitempty"`
	AuditRetentionDays int        `json:"audit_retention_days,omitempty"`
	OldestThreatEvent  *time.Time `json:"oldest_threat_event,omitempty"`
	OldestAuditEntry   *time.Time `json:"oldest_audit_entry,omitempty"`
	Warnings           []string   `json:"warnings,omitempty"`
}

func (p *Provenance) warn(format string, args ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, args...))
}

// provenance describes the data behind a report whose window starts at
// windowStart and spans window.
func (g *Generator) provenance(ctx context.Context, windowStart time.Time, window time.Duration) Provenance {
	src := g.source
	p := Provenance{
		StorageDriver:      src.StorageDriver,
		Durable:            src.StorageDriver == string(sentinel.SQLite) || src.StorageDriver == string(sentinel.Postgres),
		RetentionDays:      src.RetentionDays,
		AuditRetentionDays: src.AuditRetentionDays,
		OldestThreatEvent:  g.oldestThreat(ctx),
		OldestAuditEntry:   g.oldestAuditEntry(ctx),
	}

	switch src.StorageDriver {
	case "":
		p.warn("The storage backend was not reported to the report generator, so durability and retention are unknown.")
	case string(sentinel.Memory):
		p.warn("Data is held in memory and lost on every restart — this report covers only activity since the process last started.")
	}

	windowDays := int(window.Hours() / 24)
	if src.RetentionDays > 0 && windowDays > src.RetentionDays {
		p.warn("The report window (%d days) is longer than Storage.RetentionDays (%d): threat and user-activity records older than %d days have been deleted.",
			windowDays, src.RetentionDays, src.RetentionDays)
	}
	if src.AuditRetentionDays > 0 && windowDays > src.AuditRetentionDays {
		p.warn("The report window (%d days) is longer than Storage.AuditRetentionDays (%d): audit entries older than %d days have been deleted.",
			windowDays, src.AuditRetentionDays, src.AuditRetentionDays)
	}

	oldest := p.OldestThreatEvent
	if oldest == nil || (p.OldestAuditEntry != nil && p.OldestAuditEntry.Before(*oldest)) {
		oldest = p.OldestAuditEntry
	}
	switch {
	case oldest == nil:
		p.warn("No threat events or audit entries are stored. Empty sections mean there is no data, not a clean record.")
	case oldest.After(windowStart.Add(24 * time.Hour)):
		p.warn("The oldest stored record is from %s but the report window starts %s: the start of the window has no data (a new install, an in-memory store that restarted, or records removed by retention).",
			oldest.UTC().Format(time.DateOnly), windowStart.UTC().Format(time.DateOnly))
	}
	return p
}

func (g *Generator) oldestThreat(ctx context.Context) *time.Time {
	threats, _, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		Page:      1,
		PageSize:  1,
		SortBy:    "timestamp",
		SortOrder: "asc",
	})
	if err != nil || len(threats) == 0 {
		return nil
	}
	return &threats[0].Timestamp
}

// oldestAuditEntry returns the timestamp of the earliest audit entry.
// ListAuditLogs is newest-first, so the oldest entry is the last page of one.
func (g *Generator) oldestAuditEntry(ctx context.Context) *time.Time {
	_, total, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{Page: 1, PageSize: 1})
	if err != nil || total == 0 {
		return nil
	}
	logs, _, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{Page: int(total), PageSize: 1})
	if err != nil || len(logs) == 0 {
		return nil
	}
	return &logs[0].Timestamp
}

// noteTruncated records a report section whose listing hit its row cap.
// Report sections are evidence, and a silently short list reads as "that is
// everything" — so the report says which lists are partial. Summary counts
// come from totals, not list lengths, and stay exact.
func noteTruncated(sections *[]string, section string, total int64, listed int) {
	if total <= int64(listed) {
		return
	}
	for _, s := range *sections {
		if s == section {
			return
		}
	}
	*sections = append(*sections, section)
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

	// Truncated names the sections whose listing hit its row cap and is not
	// the complete record.
	Truncated []string `json:"truncated,omitempty"`

	// Provenance describes the data behind the report and its limits.
	Provenance Provenance `json:"provenance"`
}

// GDPRUserAccess summarizes data access for a single user.
type GDPRUserAccess struct {
	UserID         string    `json:"user_id"`
	RoutesAccessed []string  `json:"routes_accessed"`
	AccessCount    int       `json:"access_count"`
	LastAccess     time.Time `json:"last_access"`
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
		activities, total, err := g.store.ListUserActivity(ctx, user.UserID, sentinel.ActivityFilter{
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
		noteTruncated(&report.Truncated, "user_data_access", total, len(activities))

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
			AccessCount:    max(int(total), len(activities)),
			LastAccess:     lastAccess,
		})
	}

	// Data export audit logs (READ actions could be exports)
	var exportsTotal, deletionsTotal, unusualTotal int64
	exports, total, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		Action:    "READ",
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.DataExports = exports
		exportsTotal = total
		noteTruncated(&report.Truncated, "data_exports", total, len(exports))
	}

	// Data deletion audit logs
	deletions, total, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		Action:    "DELETE",
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.DataDeletions = deletions
		deletionsTotal = total
		noteTruncated(&report.Truncated, "data_deletions", total, len(deletions))
	}

	// Unusual access (anomaly-related threats)
	unusualThreats, total, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		Type:      string(sentinel.ThreatAnomalyDetected),
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.UnusualAccess = unusualThreats
		unusualTotal = total
		noteTruncated(&report.Truncated, "unusual_access", total, len(unusualThreats))
	}

	report.Summary = GDPRSummary{
		TotalUsers:         len(report.UserDataAccess),
		TotalDataAccesses:  sumUserAccess(report.UserDataAccess),
		TotalExports:       int(exportsTotal),
		TotalDeletions:     int(deletionsTotal),
		UnusualAccessCount: int(unusualTotal),
	}

	report.Provenance = g.provenance(ctx, start, window)
	if g.source.StorageDriver != "" && !g.source.UserActivityRecorded {
		report.Provenance.warn("Config.UserExtractor is not set, so no per-user activity is recorded: user_data_access is empty regardless of what users actually accessed.")
	}
	if exportsTotal == 0 {
		report.Provenance.warn("data_exports lists READ audit entries, which Sentinel's GORM plugin does not record (it records CREATE, UPDATE, and DELETE): the section stays empty unless your application writes READ entries itself.")
	}

	return report, nil
}

// --- PCI-DSS Report ---

// pciWindow is the look-back window of the PCI-DSS report.
const pciWindow = 90 * 24 * time.Hour

// PCIDSSReport is a PCI-DSS compliance report.
type PCIDSSReport struct {
	GeneratedAt       time.Time               `json:"generated_at"`
	AuthEvents        PCIAuthEvents           `json:"auth_events"`
	SecurityIncidents []*sentinel.ThreatEvent `json:"security_incidents"`
	BlockedThreats    []*sentinel.ThreatEvent `json:"blocked_threats"`
	Summary           PCIDSSSummary           `json:"summary"`

	// Truncated names the sections whose listing hit its row cap and is not
	// the complete record.
	Truncated []string `json:"truncated,omitempty"`

	// Provenance describes the data behind the report and its limits.
	Provenance Provenance `json:"provenance"`
}

// PCIAuthEvents contains authentication event metrics.
type PCIAuthEvents struct {
	TotalAttempts int     `json:"total_attempts"`
	SuccessCount  int     `json:"success_count"`
	FailureCount  int     `json:"failure_count"`
	FailureRate   float64 `json:"failure_rate"`
}

// PCIDSSSummary contains aggregate PCI-DSS metrics.
type PCIDSSSummary struct {
	TotalIncidents    int `json:"total_incidents"`
	CriticalIncidents int `json:"critical_incidents"`
	HighIncidents     int `json:"high_incidents"`
	BlockedCount      int `json:"blocked_count"`
	UniqueAttackerIPs int `json:"unique_attacker_ips"`
}

// GeneratePCIDSS produces a PCI-DSS compliance report for the last 90 days.
func (g *Generator) GeneratePCIDSS(ctx context.Context) (*PCIDSSReport, error) {
	now := time.Now()
	start := now.Add(-pciWindow)

	report := &PCIDSSReport{
		GeneratedAt: now,
	}

	// Authentication events: logins AuthShield observed on the host app and
	// logins to the Sentinel dashboard.
	authLogs, total, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		Resource:  sentinel.AuditResourceAuth,
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  5000,
	})
	if err == nil {
		noteTruncated(&report.Truncated, "auth_events", total, len(authLogs))
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
	incidents, total, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  5000,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})
	if err == nil {
		report.SecurityIncidents = incidents
		noteTruncated(&report.Truncated, "security_incidents", total, len(incidents))
	}

	// Blocked threats. Before v2.2.2 this filtered on Resolved, so it listed
	// threats an operator had triaged rather than threats the WAF stopped.
	blocked := true
	blockedThreats, total, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		StartTime: &start,
		EndTime:   &now,
		Blocked:   &blocked,
		Page:      1,
		PageSize:  5000,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})
	if err == nil {
		report.BlockedThreats = blockedThreats
		noteTruncated(&report.Truncated, "blocked_threats", total, len(blockedThreats))
	}

	// Summary counts come from the store's aggregate query so they stay
	// exact when the incident listing above is truncated.
	if stats, err := g.store.GetThreatStats(ctx, pciWindow); err == nil && stats != nil {
		report.Summary = PCIDSSSummary{
			TotalIncidents:    int(stats.TotalThreats),
			CriticalIncidents: int(stats.CriticalCount),
			HighIncidents:     int(stats.HighCount),
			BlockedCount:      int(stats.BlockedCount),
			UniqueAttackerIPs: int(stats.UniqueIPs),
		}
	} else {
		report.Summary = summarizeIncidents(report.SecurityIncidents)
	}

	report.Provenance = g.provenance(ctx, start, pciWindow)
	if g.source.AuditRetentionDays > 0 && g.source.AuditRetentionDays < 365 {
		report.Provenance.warn("Storage.AuditRetentionDays is %d: PCI-DSS 10.5.1 requires 12 months of audit history.", g.source.AuditRetentionDays)
	}

	return report, nil
}

// summarizeIncidents computes PCI-DSS summary counts from a threat listing.
// Only a fallback for when the aggregate stats query fails — it undercounts
// if the listing was truncated.
func summarizeIncidents(incidents []*sentinel.ThreatEvent) PCIDSSSummary {
	critCount := 0
	highCount := 0
	blockedCount := 0
	ipSet := make(map[string]bool)
	for _, t := range incidents {
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
	return PCIDSSSummary{
		TotalIncidents:    len(incidents),
		CriticalIncidents: critCount,
		HighIncidents:     highCount,
		BlockedCount:      blockedCount,
		UniqueAttackerIPs: len(ipSet),
	}
}

// --- SOC2 Report ---

// SOC2Report is a SOC2 compliance report.
type SOC2Report struct {
	GeneratedAt        time.Time               `json:"generated_at"`
	WindowStart        time.Time               `json:"window_start"`
	WindowEnd          time.Time               `json:"window_end"`
	MonitoringEvidence SOC2Monitoring          `json:"monitoring_evidence"`
	IncidentResponse   []*sentinel.ThreatEvent `json:"incident_response"`
	AccessControl      SOC2AccessControl       `json:"access_control"`
	AnomalyEvents      []*sentinel.ThreatEvent `json:"anomaly_events"`
	Summary            SOC2Summary             `json:"summary"`

	// Truncated names the sections whose listing hit its row cap and is not
	// the complete record.
	Truncated []string `json:"truncated,omitempty"`

	// Provenance describes the data behind the report and its limits.
	Provenance Provenance `json:"provenance"`
}

// SOC2Monitoring contains security monitoring evidence.
type SOC2Monitoring struct {
	// TotalEventsProcessed is the number of threat events recorded in the
	// window. (Before v2.2.2 it was threats + blocked + unique IPs, a sum
	// that counted each blocked threat twice and measured nothing.)
	TotalEventsProcessed int64                   `json:"total_events_processed"`
	ThreatStats          *sentinel.ThreatStats   `json:"threat_stats"`
	SecurityScore        *sentinel.SecurityScore `json:"security_score"`
}

// SOC2AccessControl contains access control evidence.
type SOC2AccessControl struct {
	TotalUsers int                   `json:"total_users"`
	AuditLogs  []*sentinel.AuditLog  `json:"audit_logs"`
	BlockedIPs []*sentinel.BlockedIP `json:"blocked_ips"`
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
	var stats *sentinel.ThreatStats
	if s, err := g.store.GetThreatStats(ctx, window); err == nil && s != nil {
		stats = s
		report.MonitoringEvidence.ThreatStats = stats
		report.MonitoringEvidence.TotalEventsProcessed = stats.TotalThreats
	}

	score, err := g.store.GetSecurityScore(ctx)
	if err == nil {
		report.MonitoringEvidence.SecurityScore = score
	}

	// Incident response — resolved threats
	resolved := true
	incidents, total, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
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
		noteTruncated(&report.Truncated, "incident_response", total, len(incidents))
	}

	// Access control
	users, err := g.store.ListUsers(ctx)
	if err == nil {
		report.AccessControl.TotalUsers = len(users)
	}

	var auditTotal, anomalyTotal int64
	auditLogs, total, err := g.store.ListAuditLogs(ctx, sentinel.AuditFilter{
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  1000,
	})
	if err == nil {
		report.AccessControl.AuditLogs = auditLogs
		auditTotal = total
		noteTruncated(&report.Truncated, "access_control.audit_logs", total, len(auditLogs))
	}

	blockedIPs, err := g.store.ListBlockedIPs(ctx)
	if err == nil {
		report.AccessControl.BlockedIPs = blockedIPs
	}

	// Anomaly events
	anomalies, total, err := g.store.ListThreats(ctx, sentinel.ThreatFilter{
		Type:      string(sentinel.ThreatAnomalyDetected),
		StartTime: &start,
		EndTime:   &now,
		Page:      1,
		PageSize:  500,
	})
	if err == nil {
		report.AnomalyEvents = anomalies
		anomalyTotal = total
		noteTruncated(&report.Truncated, "anomaly_events", total, len(anomalies))
	}

	// Summary. Threat counts come from the aggregate stats query: before
	// v2.2.2 "detected" counted only resolved threats and "blocked" was
	// counted from a one-row page, so it could never exceed 1.
	report.Summary = SOC2Summary{
		TotalAnomalies:    int(anomalyTotal),
		TotalAuditEntries: int(auditTotal),
		ActiveBlockedIPs:  len(report.AccessControl.BlockedIPs),
	}
	if stats != nil {
		report.Summary.TotalThreatsDetected = int(stats.TotalThreats)
		report.Summary.TotalThreatsBlocked = int(stats.BlockedCount)
	}

	report.Provenance = g.provenance(ctx, start, window)

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
