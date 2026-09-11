package sqlite

import (
	"context"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func withinSecond(a, b time.Time) bool {
	d := a.Sub(b)
	return d < time.Second && d > -time.Second
}

// TestSQLiteListUsers pins the replacement for the v2.2 stub, which always
// returned no users — so the GDPR report's per-user section was empty on the
// default store.
func TestSQLiteListUsers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	save := func(id, user string, at time.Time, threatID string) {
		t.Helper()
		err := s.SaveUserActivity(ctx, &sentinel.UserActivity{
			ID: id, UserID: user, UserEmail: user + "@example.com",
			Timestamp: at, Path: "/api/x", Method: "GET", ThreatID: threatID,
		})
		if err != nil {
			t.Fatalf("SaveUserActivity: %v", err)
		}
	}
	save("a1", "u1", now.Add(-3*time.Hour), "")
	save("a2", "u1", now.Add(-2*time.Hour), "waf-threat")
	save("a3", "u1", now.Add(-10*time.Minute), "")
	save("a4", "u2", now.Add(-1*time.Hour), "")
	if err := s.SaveThreat(ctx, &sentinel.ThreatEvent{ID: "anomaly-1", Timestamp: now, UserID: "u1", ThreatTypes: []string{"AnomalyDetected"}}); err != nil {
		t.Fatalf("SaveThreat: %v", err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	u1, u2 := users[0], users[1]
	if u1.UserID != "u1" || u2.UserID != "u2" {
		t.Fatalf("expected most recently seen first (u1, u2), got %s, %s", u1.UserID, u2.UserID)
	}
	if u1.ActivityCount != 3 || u1.Email != "u1@example.com" {
		t.Errorf("u1: activity=%d email=%q", u1.ActivityCount, u1.Email)
	}
	if u1.ThreatCount != 2 {
		t.Errorf("u1: expected 2 threats (1 attributed + 1 linked), got %d", u1.ThreatCount)
	}
	if !withinSecond(u1.LastSeen, now.Add(-10*time.Minute)) {
		t.Errorf("u1: LastSeen %v, want %v", u1.LastSeen, now.Add(-10*time.Minute))
	}
	if u2.ThreatCount != 0 || u2.ActivityCount != 1 {
		t.Errorf("u2: activity=%d threats=%d", u2.ActivityCount, u2.ThreatCount)
	}
}

func TestSQLiteAnalytics(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	for _, th := range []*sentinel.ThreatEvent{
		{ID: "t1", Timestamp: now.Add(-1 * time.Hour), Path: "/login", Method: "POST", ThreatTypes: []string{"SQLi"}, Country: "DE", Lat: 51, Lng: 10},
		{ID: "t2", Timestamp: now.Add(-2 * time.Hour), Path: "/login", Method: "POST", ThreatTypes: []string{"SQLi", "XSS"}, Country: "DE", Lat: 51, Lng: 10},
		{ID: "t3", Timestamp: now.Add(-3 * time.Hour), Path: "/search", Method: "GET", ThreatTypes: []string{"XSS"}, Country: "US", Lat: 38, Lng: -97},
		{ID: "old", Timestamp: now.Add(-30 * 24 * time.Hour), Path: "/old", Method: "GET", ThreatTypes: []string{"SQLi"}, Country: "FR"},
	} {
		if err := s.SaveThreat(ctx, th); err != nil {
			t.Fatalf("SaveThreat: %v", err)
		}
	}
	week := 7 * 24 * time.Hour

	trends, err := s.GetAttackTrends(ctx, week, "day")
	if err != nil {
		t.Fatalf("GetAttackTrends: %v", err)
	}
	var total int64
	byType := map[string]int64{}
	for _, tr := range trends {
		total += tr.Total
		for k, v := range tr.ByType {
			byType[k] += v
		}
	}
	if total != 3 || byType["SQLi"] != 2 || byType["XSS"] != 2 {
		t.Errorf("trends: total=%d byType=%v, want 3 / SQLi:2 XSS:2", total, byType)
	}
	hourly, err := s.GetAttackTrends(ctx, 24*time.Hour, "hour")
	if err != nil || len(hourly) == 0 {
		t.Fatalf("hourly trends: %v (len %d)", err, len(hourly))
	}
	if len(hourly[0].Period) != len("2006-01-02T15:00") {
		t.Errorf("hourly period %q is not hour-formatted", hourly[0].Period)
	}

	geo, err := s.GetGeoStats(ctx, week)
	if err != nil {
		t.Fatalf("GetGeoStats: %v", err)
	}
	if len(geo) != 2 || geo[0].Country != "DE" || geo[0].Count != 2 || geo[1].Country != "US" {
		t.Errorf("geo: unexpected %+v", geo)
	}

	top, err := s.GetTopTargets(ctx, week, 1)
	if err != nil {
		t.Fatalf("GetTopTargets: %v", err)
	}
	if len(top) != 1 || top[0].Route != "/login" || top[0].Method != "POST" || top[0].Count != 2 {
		t.Errorf("top targets: unexpected %+v", top)
	}
}

// TestSQLiteCleanupKeepsAuditLogsUntilPruned: audit logs no longer go out
// with the 90-day RetentionDays sweep; they have their own retention.
func TestSQLiteCleanupKeepsAuditLogsUntilPruned(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)

	s.SaveAuditLog(ctx, &sentinel.AuditLog{ID: "old-audit", Timestamp: old, Action: "DELETE", Resource: "users"})
	s.SaveUserActivity(ctx, &sentinel.UserActivity{ID: "old-activity", UserID: "u1", Timestamp: old})

	s.Cleanup(ctx, 24*time.Hour)
	if _, total, _ := s.ListAuditLogs(ctx, sentinel.AuditFilter{}); total != 1 {
		t.Errorf("Cleanup must not delete audit logs, %d left", total)
	}
	if _, total, _ := s.ListUserActivity(ctx, "u1", sentinel.ActivityFilter{}); total != 0 {
		t.Errorf("Cleanup should delete old activity, %d left", total)
	}

	if err := s.PruneAuditLogs(ctx, 24*time.Hour); err != nil {
		t.Fatalf("PruneAuditLogs: %v", err)
	}
	if _, total, _ := s.ListAuditLogs(ctx, sentinel.AuditFilter{}); total != 0 {
		t.Errorf("PruneAuditLogs should delete old entries, %d left", total)
	}
}
