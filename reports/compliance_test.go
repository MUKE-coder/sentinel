package reports_test

import (
	"context"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/reports"
	"github.com/MUKE-coder/sentinel/storage/memory"
)

func seedTestData(t *testing.T, store *memory.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	// Seed some threats
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
	if report.Summary.CriticalIncidents != 5 {
		t.Errorf("expected 5 critical, got %d", report.Summary.CriticalIncidents)
	}
	if report.Summary.UniqueAttackerIPs != 1 {
		t.Errorf("expected 1 unique IP, got %d", report.Summary.UniqueAttackerIPs)
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
