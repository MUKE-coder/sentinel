package memory

import (
	"context"
	"fmt"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

func TestSaveThreatAndGet(t *testing.T) {
	s := New()
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
}

func TestListThreatsWithFilter(t *testing.T) {
	s := New()
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
	threats, total, err = s.ListThreats(ctx, sentinel.ThreatFilter{
		Severity: sentinel.SeverityHigh,
		Page:     1,
		PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListThreats with severity filter: %v", err)
	}
	if total != 5 {
		t.Errorf("expected 5 high severity threats, got %d", total)
	}

	// Test IP filter
	threats, total, err = s.ListThreats(ctx, sentinel.ThreatFilter{
		IP:       "10.0.0.0",
		Page:     1,
		PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListThreats with IP filter: %v", err)
	}
	if total != 5 {
		t.Errorf("expected 5 threats from IP 10.0.0.0, got %d", total)
	}
}

func TestUpdateThreat(t *testing.T) {
	s := New()
	ctx := context.Background()

	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:       "threat-1",
		Resolved: false,
	})

	resolved := true
	s.UpdateThreat(ctx, "threat-1", sentinel.ThreatUpdate{Resolved: &resolved})

	got, _ := s.GetThreat(ctx, "threat-1")
	if !got.Resolved {
		t.Error("expected threat to be resolved")
	}
}

func TestActorUpsertAndList(t *testing.T) {
	s := New()
	ctx := context.Background()

	actor := &sentinel.ThreatActor{
		IP:          "192.168.1.1",
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		ThreatCount: 5,
		RiskScore:   75,
		Status:      sentinel.ActorActive,
		Country:     "Russia",
	}
	s.UpsertActor(ctx, actor)

	got, _ := s.GetActor(ctx, "192.168.1.1")
	if got == nil {
		t.Fatal("expected actor, got nil")
	}
	if got.RiskScore != 75 {
		t.Errorf("expected risk score 75, got %d", got.RiskScore)
	}

	actors, total, _ := s.ListActors(ctx, sentinel.ActorFilter{Page: 1, PageSize: 10})
	if total != 1 {
		t.Errorf("expected 1 actor, got %d", total)
	}
	if len(actors) != 1 {
		t.Errorf("expected 1 result, got %d", len(actors))
	}
}

func TestIPBlockAndWhitelist(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Block an IP
	s.BlockIP(ctx, "10.0.0.1", "malicious", nil)

	blocked, _ := s.IsIPBlocked(ctx, "10.0.0.1")
	if !blocked {
		t.Error("expected IP to be blocked")
	}

	// Whitelist an IP
	s.WhitelistIP(ctx, "10.0.0.2")
	whitelisted, _ := s.IsIPWhitelisted(ctx, "10.0.0.2")
	if !whitelisted {
		t.Error("expected IP to be whitelisted")
	}

	// Unblock
	s.UnblockIP(ctx, "10.0.0.1")
	blocked, _ = s.IsIPBlocked(ctx, "10.0.0.1")
	if blocked {
		t.Error("expected IP to not be blocked after unblock")
	}

	// Expired block
	past := time.Now().Add(-1 * time.Hour)
	s.BlockIP(ctx, "10.0.0.3", "expired", &past)
	blocked, _ = s.IsIPBlocked(ctx, "10.0.0.3")
	if blocked {
		t.Error("expected expired block to not count")
	}
}

func TestThreatStats(t *testing.T) {
	s := New()
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
	if stats.UniqueIPs != 2 {
		t.Errorf("expected 2 unique IPs, got %d", stats.UniqueIPs)
	}
}

func TestPerformanceMetrics(t *testing.T) {
	s := New()
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

	overview, err := s.GetPerformanceOverview(ctx)
	if err != nil {
		t.Fatalf("GetPerformanceOverview: %v", err)
	}
	if overview.TotalRequests != 10 {
		t.Errorf("expected 10 requests, got %d", overview.TotalRequests)
	}
	if overview.ErrorRate != 0 {
		t.Errorf("expected 0 error rate, got %f", overview.ErrorRate)
	}

	metrics, err := s.GetRouteMetrics(ctx)
	if err != nil {
		t.Fatalf("GetRouteMetrics: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 route metric, got %d", len(metrics))
	}
}

func TestCleanup(t *testing.T) {
	s := New()
	ctx := context.Background()

	oldTime := time.Now().Add(-48 * time.Hour)
	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:        "old",
		Timestamp: oldTime,
	})
	s.SaveThreat(ctx, &sentinel.ThreatEvent{
		ID:        "new",
		Timestamp: time.Now(),
	})

	s.Cleanup(ctx, 24*time.Hour)

	old, _ := s.GetThreat(ctx, "old")
	if old != nil {
		t.Error("expected old threat to be cleaned up")
	}

	newThreat, _ := s.GetThreat(ctx, "new")
	if newThreat == nil {
		t.Error("expected new threat to still exist")
	}
}

func TestUserActivity(t *testing.T) {
	s := New()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		s.SaveUserActivity(ctx, &sentinel.UserActivity{
			ID:        fmt.Sprintf("a%d", i),
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			UserID:    "user-1",
			Path:      "/api/test",
			Method:    "GET",
		})
	}

	activities, total, err := s.ListUserActivity(ctx, "user-1", sentinel.ActivityFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUserActivity: %v", err)
	}
	if total != 5 {
		t.Errorf("expected 5 activities, got %d", total)
	}
	if len(activities) != 5 {
		t.Errorf("expected 5 results, got %d", len(activities))
	}
}

func TestAuditLogs(t *testing.T) {
	s := New()
	ctx := context.Background()

	s.SaveAuditLog(ctx, &sentinel.AuditLog{
		ID:        "audit-1",
		Timestamp: time.Now(),
		UserID:    "user-1",
		Action:    "CREATE",
		Resource:  "users",
	})
	s.SaveAuditLog(ctx, &sentinel.AuditLog{
		ID:        "audit-2",
		Timestamp: time.Now(),
		UserID:    "user-2",
		Action:    "DELETE",
		Resource:  "users",
	})

	// Filter by action
	logs, total, err := s.ListAuditLogs(ctx, sentinel.AuditFilter{
		Action:   "CREATE",
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 CREATE log, got %d", total)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 result, got %d", len(logs))
	}
}
