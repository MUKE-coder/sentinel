package reports_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/reports"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
)

func seedTestData(t *testing.T, store *memory.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	// Seed some threats — 5 total, 3 blocked (i = 0, 2, 4), none resolved.
	for i := 0; i < 5; i++ {
		store.SaveThreat(ctx, &sentinel.ThreatEvent{
			ID:          "threat-" + string(rune('a'+i)),
			Timestamp:   now.Add(-time.Duration(i) * time.Hour),
			IP:          "10.0.0.1",
			Method:      "GET",
			Path:        "/api/users",
			ThreatTypes: []string{"SQLi"},
			Severity:    sentinel.SeverityCritical,
			Blocked:     i%2 == 0,
		})
	}

	// Seed user activity
	store.SaveUserActivity(ctx, &sentinel.UserActivity{
		ID:        "ua-1",
		UserID:    "user-1",
		Timestamp: now.Add(-1 * time.Hour),
		Method:    "GET",
		Path:      "/api/profile",
		IP:        "10.0.0.5",
	})
	store.SaveUserActivity(ctx, &sentinel.UserActivity{
		ID:        "ua-2",
		UserID:    "user-1",
		Timestamp: now.Add(-2 * time.Hour),
		Method:    "POST",
		Path:      "/api/settings",
		IP:        "10.0.0.5",
	})

	// Seed audit logs
	store.SaveAuditLog(ctx, &sentinel.AuditLog{
		ID:        "audit-1",
		Timestamp: now.Add(-1 * time.Hour),
		UserID:    "user-1",
		Action:    "DELETE",
		Resource:  "users",
		Success:   true,
	})
	store.SaveAuditLog(ctx, &sentinel.AuditLog{
		ID:        "audit-2",
		Timestamp: now.Add(-2 * time.Hour),
		UserID:    "user-1",
		Action:    "READ",
		Resource:  "users",
		Success:   true,
	})
}

func TestGenerateGDPR(t *testing.T) {
	store := memory.New()
	seedTestData(t, store)

	gen := reports.NewGenerator(store)
	report, err := gen.GenerateGDPR(context.Background(), 720*time.Hour)
	if err != nil {
		t.Fatalf("GenerateGDPR failed: %v", err)
	}

	if report.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be set")
	}
	if len(report.DataDeletions) != 1 {
		t.Errorf("expected 1 deletion, got %d", len(report.DataDeletions))
	}
	if len(report.DataExports) != 1 {
		t.Errorf("expected 1 export (READ), got %d", len(report.DataExports))
	}
	if report.Summary.TotalDeletions != 1 {
		t.Errorf("expected summary.TotalDeletions=1, got %d", report.Summary.TotalDeletions)
	}
	if len(report.Truncated) != 0 {
		t.Errorf("expected no truncated sections, got %v", report.Truncated)
	}
}

func TestGeneratePCIDSS(t *testing.T) {
	store := memory.New()
	seedTestData(t, store)

	gen := reports.NewGenerator(store)
	report, err := gen.GeneratePCIDSS(context.Background())
	if err != nil {
		t.Fatalf("GeneratePCIDSS failed: %v", err)
	}

	if report.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be set")
	}
	if len(report.SecurityIncidents) != 5 {
		t.Errorf("expected 5 incidents, got %d", len(report.SecurityIncidents))
	}
	if report.Summary.TotalIncidents != 5 {
		t.Errorf("expected summary.TotalIncidents=5, got %d", report.Summary.TotalIncidents)
	}
	if report.Summary.CriticalIncidents != 5 {
		t.Errorf("expected 5 critical, got %d", report.Summary.CriticalIncidents)
	}
	if report.Summary.UniqueAttackerIPs != 1 {
		t.Errorf("expected 1 unique IP, got %d", report.Summary.UniqueAttackerIPs)
	}
	// Before v2.2.2 BlockedThreats filtered on Resolved and listed none of
	// the three blocked (unresolved) threats.
	if len(report.BlockedThreats) != 3 {
		t.Errorf("expected 3 blocked threats, got %d", len(report.BlockedThreats))
	}
	for _, th := range report.BlockedThreats {
		if !th.Blocked {
			t.Errorf("threat %s in BlockedThreats was not blocked", th.ID)
		}
	}
	if report.Summary.BlockedCount != 3 {
		t.Errorf("expected summary.BlockedCount=3, got %d", report.Summary.BlockedCount)
	}
}

func TestGenerateSOC2(t *testing.T) {
	store := memory.New()
	seedTestData(t, store)

	gen := reports.NewGenerator(store)
	report, err := gen.GenerateSOC2(context.Background(), 720*time.Hour)
	if err != nil {
		t.Fatalf("GenerateSOC2 failed: %v", err)
	}

	if report.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be set")
	}
	if report.Summary.TotalAuditEntries != 2 {
		t.Errorf("expected 2 audit entries, got %d", report.Summary.TotalAuditEntries)
	}
	// Before v2.2.2 "detected" counted only resolved threats (0 here) and
	// "blocked" was counted from a one-row page (at most 1).
	if report.Summary.TotalThreatsDetected != 5 {
		t.Errorf("expected 5 threats detected, got %d", report.Summary.TotalThreatsDetected)
	}
	if report.Summary.TotalThreatsBlocked != 3 {
		t.Errorf("expected 3 threats blocked, got %d", report.Summary.TotalThreatsBlocked)
	}
	if report.MonitoringEvidence.TotalEventsProcessed != 5 {
		t.Errorf("expected 5 events processed, got %d", report.MonitoringEvidence.TotalEventsProcessed)
	}
}

func TestGenerateSOC2_FlagsTruncatedListing(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < 1001; i++ {
		store.SaveAuditLog(ctx, &sentinel.AuditLog{
			ID:        fmt.Sprintf("audit-%d", i),
			Timestamp: now.Add(-time.Minute),
			Action:    "UPDATE",
			Resource:  "orders",
			Success:   true,
		})
	}

	report, err := reports.NewGenerator(store).GenerateSOC2(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateSOC2 failed: %v", err)
	}
	if len(report.AccessControl.AuditLogs) != 1000 {
		t.Errorf("expected the audit listing capped at 1000, got %d", len(report.AccessControl.AuditLogs))
	}
	if report.Summary.TotalAuditEntries != 1001 {
		t.Errorf("expected summary to count all 1001 entries, got %d", report.Summary.TotalAuditEntries)
	}
	if !slices.Contains(report.Truncated, "access_control.audit_logs") {
		t.Errorf("expected access_control.audit_logs flagged as truncated, got %v", report.Truncated)
	}
}

func TestGenerateGDPR_EmptyStore(t *testing.T) {
	store := memory.New()
	gen := reports.NewGenerator(store)

	report, err := gen.GenerateGDPR(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateGDPR on empty store failed: %v", err)
	}
	if report.Summary.TotalUsers != 0 {
		t.Errorf("expected 0 users, got %d", report.Summary.TotalUsers)
	}
}
