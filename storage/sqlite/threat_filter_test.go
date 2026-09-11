package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func seedThreats(t *testing.T, s *Store, n int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < n; i++ {
		err := s.SaveThreat(ctx, &sentinel.ThreatEvent{
			ID:          fmt.Sprintf("threat-%d", i),
			Timestamp:   now.Add(-time.Duration(i) * time.Minute),
			IP:          fmt.Sprintf("203.0.113.%d", i+1),
			Method:      "GET",
			Path:        "/api/items",
			ThreatTypes: []string{"SQLi"},
			Severity:    sentinel.SeverityHigh,
			Blocked:     i%2 == 0,
		})
		if err != nil {
			t.Fatalf("SaveThreat: %v", err)
		}
	}
}

func TestSQLiteListThreats_BlockedFilter(t *testing.T) {
	s := newTestStore(t)
	seedThreats(t, s, 5)

	blocked := true
	threats, total, err := s.ListThreats(context.Background(), sentinel.ThreatFilter{Blocked: &blocked, PageSize: 50})
	if err != nil {
		t.Fatalf("ListThreats: %v", err)
	}
	if total != 3 || len(threats) != 3 {
		t.Fatalf("expected 3 blocked threats, got total=%d len=%d", total, len(threats))
	}
	for _, th := range threats {
		if !th.Blocked {
			t.Errorf("threat %s is not blocked but passed the Blocked filter", th.ID)
		}
	}
}

// TestSQLiteListThreats_SortByIsAllowlisted pins the fix for sort_by being
// interpolated into ORDER BY. The dashboard API forwards the query parameter
// unchanged, so each of these used to execute as SQL.
func TestSQLiteListThreats_SortByIsAllowlisted(t *testing.T) {
	s := newTestStore(t)
	seedThreats(t, s, 3)

	for _, sortBy := range []string{
		"timestamp; DROP TABLE sentinel_threat_events",
		"(CASE WHEN (SELECT 1)=1 THEN ip ELSE path END)",
		"nonexistent_column",
	} {
		threats, total, err := s.ListThreats(context.Background(), sentinel.ThreatFilter{SortBy: sortBy, PageSize: 50})
		if err != nil {
			t.Fatalf("sort_by %q: expected fallback to timestamp, got error %v", sortBy, err)
		}
		if total != 3 || len(threats) != 3 {
			t.Fatalf("sort_by %q: expected 3 threats, got total=%d len=%d", sortBy, total, len(threats))
		}
		// Fallback order is timestamp DESC — threat-0 is the newest.
		if threats[0].ID != "threat-0" {
			t.Errorf("sort_by %q: expected timestamp DESC fallback, first row is %s", sortBy, threats[0].ID)
		}
	}
}
