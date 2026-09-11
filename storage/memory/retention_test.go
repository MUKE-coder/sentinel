package memory

import (
	"context"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// TestCleanupPrunesActivityButKeepsAuditLogs: user activity is now recorded
// on every authenticated request, so it has to be pruned (it never was) —
// while audit logs wait for their own, longer retention.
func TestCleanupPrunesActivityButKeepsAuditLogs(t *testing.T) {
	s := New()
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)

	s.SaveUserActivity(ctx, &sentinel.UserActivity{ID: "old", UserID: "u1", Timestamp: old})
	s.SaveUserActivity(ctx, &sentinel.UserActivity{ID: "new", UserID: "u1", Timestamp: time.Now()})
	s.SaveUserActivity(ctx, &sentinel.UserActivity{ID: "gone", UserID: "u2", Timestamp: old})
	s.SaveAuditLog(ctx, &sentinel.AuditLog{ID: "old-audit", Timestamp: old})

	s.Cleanup(ctx, 24*time.Hour)

	if _, total, _ := s.ListUserActivity(ctx, "u1", sentinel.ActivityFilter{}); total != 1 {
		t.Errorf("expected 1 activity left for u1, got %d", total)
	}
	users, _ := s.ListUsers(ctx)
	if len(users) != 1 {
		t.Errorf("a user with no remaining activity should drop out, got %d users", len(users))
	}
	if _, total, _ := s.ListAuditLogs(ctx, sentinel.AuditFilter{}); total != 1 {
		t.Errorf("Cleanup must not delete audit logs, %d left", total)
	}

	s.PruneAuditLogs(ctx, 24*time.Hour)
	if _, total, _ := s.ListAuditLogs(ctx, sentinel.AuditFilter{}); total != 0 {
		t.Errorf("PruneAuditLogs should delete old entries, %d left", total)
	}
}

// TestListAuditLogsNewestFirst: entries saved out of time order still list
// newest first, as the SQL stores do — the oldest entry is the last one.
func TestListAuditLogsNewestFirst(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Now()

	s.SaveAuditLog(ctx, &sentinel.AuditLog{ID: "middle", Timestamp: now.Add(-time.Hour)})
	s.SaveAuditLog(ctx, &sentinel.AuditLog{ID: "oldest", Timestamp: now.Add(-2 * time.Hour)})
	s.SaveAuditLog(ctx, &sentinel.AuditLog{ID: "newest", Timestamp: now})

	logs, _, _ := s.ListAuditLogs(ctx, sentinel.AuditFilter{PageSize: 10})
	if len(logs) != 3 || logs[0].ID != "newest" || logs[1].ID != "middle" || logs[2].ID != "oldest" {
		ids := make([]string, len(logs))
		for i, l := range logs {
			ids[i] = l.ID
		}
		t.Fatalf("expected newest, middle, oldest; got %v", ids)
	}
}

func TestListUsersCountsLinkedThreats(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Now()

	s.SaveUserActivity(ctx, &sentinel.UserActivity{ID: "a1", UserID: "u1", Timestamp: now, ThreatID: "waf-1"})
	s.SaveUserActivity(ctx, &sentinel.UserActivity{ID: "a2", UserID: "u1", Timestamp: now})
	s.SaveThreat(ctx, &sentinel.ThreatEvent{ID: "anomaly-1", Timestamp: now, UserID: "u1"})

	users, _ := s.ListUsers(ctx)
	if len(users) != 1 || users[0].ThreatCount != 2 {
		t.Fatalf("expected u1 with 2 threats (1 attributed + 1 linked), got %+v", users)
	}
}
