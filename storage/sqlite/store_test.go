package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "test.db")
	s, err := New(dsn)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		os.Remove(dsn)
	})
	return s
}

func TestSQLiteSaveThreatAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	event := &sentinel.ThreatEvent{
		ID:          "threat-1",
		Timestamp:   time.Now(),
		IP:          "192.168.1.1",
		Method:      "GET",
		Path:        "/api/users",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityHigh,
		Confidence:  85,
		Blocked:     true,
		Evidence: []sentinel.Evidence{
			{Pattern: "SQLi_Basic", Matched: "' OR 1=1--", Location: "query"},
		},
	}

	if err := s.SaveThreat(ctx, event); err != nil {
		t.Fatalf("SaveThreat: %v", err)
	}

	got, err := s.GetThreat(ctx, "threat-1")
	if err != nil {
		t.Fatalf("GetThreat: %v", err)
	}
	if got == nil {
		t.Fatal("expected threat, got nil")
	}
	if got.ID != "threat-1" {
		t.Errorf("expected ID threat-1, got %s", got.ID)
	}
	if got.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", got.IP)
	}
	if len(got.ThreatTypes) != 1 || got.ThreatTypes[0] != "SQLi" {
		t.Errorf("expected threat types [SQLi], got %v", got.ThreatTypes)
	}
	if len(got.Evidence) != 1 {
		t.Errorf("expected 1 evidence, got %d", len(got.Evidence))
	}
}

func TestSQLiteListThreatsWithFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		severity := sentinel.SeverityLow
		if i%5 == 0 {
			severity = sentinel.SeverityHigh
		}
		s.SaveThreat(ctx, &sentinel.ThreatEvent{
			ID:          fmt.Sprintf("threat-%d", i),
			Timestamp:   time.Now().Add(time.Duration(i) * time.Second),
			IP:          fmt.Sprintf("10.0.0.%d", i%5),
			Path:        "/api/test",
			ThreatTypes: []string{"SQLi"},
			Severity:    severity,
			Blocked:     true,
		})
	}

	// Test pagination
	threats, total, err := s.ListThreats(ctx, sentinel.ThreatFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListThreats: %v", err)
	}
	if total != 25 {
		t.Errorf("expected total 25, got %d", total)
	}
	if len(threats) != 10 {
		t.Errorf("expected 10 results, got %d", len(threats))
	}

	// Test severity filter
	_, total, err = s.ListThreats(ctx, sentinel.ThreatFilter{
		Severity: sentinel.SeverityHigh,
		Page:     1,
		PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListThreats with severity: %v", err)
	}
	if total != 5 {
		t.Errorf("expected 5 high severity, got %d", total)
	}

	// Test IP filter
	_, total, err = s.ListThreats(ctx, sentinel.ThreatFilter{
		IP:       "10.0.0.0",
		Page:     1,
		PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListThreats with IP: %v", err)
	}
	if total != 5 {
		t.Errorf("expected 5 from IP 10.0.0.0, got %d", total)
	}
}

func TestSQLiteUpdateThreat(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:        "threat-1",
		Timestamp: time.Now(),
		Resolved:  false,
	})

	resolved := true
	s.UpdateThreat(ctx, "threat-1", sentinel.ThreatUpdate{Resolved: &resolved})

	got, _ := s.GetThreat(ctx, "threat-1")
	if !got.Resolved {
		t.Error("expected threat to be resolved")
	}
}

func TestSQLiteActors(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	actor := &sentinel.ThreatActor{
		ID:          "actor-1",
		IP:          "192.168.1.1",
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		ThreatCount: 5,
		RiskScore:   75,
		Status:      sentinel.ActorActive,
		Country:     "Russia",
		AttackTypes: []string{"SQLi", "XSS"},
	}
	s.UpsertActor(ctx, actor)

	got, _ := s.GetActor(ctx, "192.168.1.1")
	if got == nil {
		t.Fatal("expected actor")
	}
	if got.RiskScore != 75 {
		t.Errorf("expected risk 75, got %d", got.RiskScore)
	}
	if len(got.AttackTypes) != 2 {
		t.Errorf("expected 2 attack types, got %d", len(got.AttackTypes))
	}

	actors, total, _ := s.ListActors(ctx, sentinel.ActorFilter{Page: 1, PageSize: 10})
	if total != 1 || len(actors) != 1 {
		t.Errorf("expected 1 actor, got %d/%d", total, len(actors))
	}
}

func TestSQLiteIPManagement(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.BlockIP(ctx, "10.0.0.1", "malicious", nil)
	blocked, _ := s.IsIPBlocked(ctx, "10.0.0.1")
	if !blocked {
		t.Error("expected blocked")
	}

	s.WhitelistIP(ctx, "10.0.0.2")
	whitelisted, _ := s.IsIPWhitelisted(ctx, "10.0.0.2")
	if !whitelisted {
		t.Error("expected whitelisted")
	}

	s.UnblockIP(ctx, "10.0.0.1")
	blocked, _ = s.IsIPBlocked(ctx, "10.0.0.1")
	if blocked {
		t.Error("expected not blocked after unblock")
	}

	// Expired block
	past := time.Now().Add(-1 * time.Hour)
	s.BlockIP(ctx, "10.0.0.3", "expired", &past)
	blocked, _ = s.IsIPBlocked(ctx, "10.0.0.3")
	if blocked {
		t.Error("expected expired block to not count")
	}
}

func TestSQLiteThreatStats(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:          "t1",
		Timestamp:   time.Now(),
		IP:          "1.1.1.1",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityCritical,
		Blocked:     true,
	})
	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:          "t2",
		Timestamp:   time.Now(),
		IP:          "2.2.2.2",
		ThreatTypes: []string{"XSS"},
		Severity:    sentinel.SeverityMedium,
		Blocked:     false,
	})

	stats, err := s.GetThreatStats(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("GetThreatStats: %v", err)
	}
	if stats.TotalThreats != 2 {
		t.Errorf("expected 2 threats, got %d", stats.TotalThreats)
	}
	if stats.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", stats.CriticalCount)
	}
	if stats.BlockedCount != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.BlockedCount)
	}
}

func TestSQLitePerformance(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		s.SavePerformanceMetric(ctx, &sentinel.PerformanceMetric{
			ID:         fmt.Sprintf("p%d", i),
			Timestamp:  time.Now(),
			Route:      "/api/test",
			Method:     "GET",
			StatusCode: 200,
			Duration:   int64(i * 10),
		})
	}

	overview, _ := s.GetPerformanceOverview(ctx)
	if overview.TotalRequests != 10 {
		t.Errorf("expected 10 requests, got %d", overview.TotalRequests)
	}

	metrics, _ := s.GetRouteMetrics(ctx)
	if len(metrics) != 1 {
		t.Errorf("expected 1 route metric, got %d", len(metrics))
	}
}

func TestSQLiteSecurityScore(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	score := &sentinel.SecurityScore{
		Overall:    85,
		Grade:      "B",
		ComputedAt: time.Now(),
	}
	if err := s.SaveSecurityScore(ctx, score); err != nil {
		t.Fatalf("SaveSecurityScore: %v", err)
	}

	got, err := s.GetSecurityScore(ctx)
	if err != nil {
		t.Fatalf("GetSecurityScore: %v", err)
	}
	if got == nil {
		t.Fatal("expected score")
	}
	if got.Overall != 85 {
		t.Errorf("expected 85, got %d", got.Overall)
	}
	if got.Grade != "B" {
		t.Errorf("expected B, got %s", got.Grade)
	}
}

func TestSQLiteCleanup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:        "old",
		Timestamp: time.Now().Add(-48 * time.Hour),
	})
	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:        "new",
		Timestamp: time.Now(),
	})

	s.Cleanup(ctx, 24*time.Hour)

	old, _ := s.GetThreat(ctx, "old")
	if old != nil {
		t.Error("expected old threat cleaned up")
	}

	newT, _ := s.GetThreat(ctx, "new")
	if newT == nil {
		t.Error("expected new threat to still exist")
	}
}
