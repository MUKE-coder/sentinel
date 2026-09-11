package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/storage/auditchain"
)

// TestSQLiteAuditChainSurvivesRoundTrip: a chain written through the store
// must verify when read back — timestamps, nested JSON, and nil/empty maps
// all go through SQLite's text encoding — and tampering through SQL must be
// caught.
func TestSQLiteAuditChainSurvivesRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := []byte("0123456789abcdef0123456789abcdef")
	chain := auditchain.New(key)

	for i := 0; i < 5; i++ {
		e := &sentinel.AuditLog{
			ID:        fmt.Sprintf("a%d", i+1),
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond),
			UserID:    "admin",
			Action:    "UPDATE",
			Resource:  "sentinel.waf_config",
			Before:    sentinel.JSONMap{"mode": "block"},
			After:     sentinel.JSONMap{"mode": "log", "limit": 3, "rules": map[string]any{"XSS": "strict"}},
			Success:   true,
		}
		if i == 2 {
			e.Before, e.After = nil, sentinel.JSONMap{}
		}
		chain.Link(e)
		if err := s.SaveAuditLog(ctx, e); err != nil {
			t.Fatalf("SaveAuditLog: %v", err)
		}
	}

	read := func() []*sentinel.AuditLog {
		logs, _, err := s.ListAuditLogs(ctx, sentinel.AuditFilter{PageSize: 100})
		if err != nil {
			t.Fatalf("ListAuditLogs: %v", err)
		}
		return logs
	}

	if r := auditchain.Verify(read(), key); !r.OK || r.Checked != 5 {
		t.Fatalf("a chain read back from SQLite must verify: %+v", r)
	}

	s.db.Model(&auditLogRow{}).Where("id = ?", "a2").Update("user_id", "forged")
	r := auditchain.Verify(read(), key)
	if r.OK || len(r.Problems) != 1 || r.Problems[0].Kind != auditchain.ProblemModified || r.Problems[0].EntryID != "a2" {
		t.Fatalf("an UPDATE through SQL must be reported as modified: %+v", r.Problems)
	}

	s.db.Where("id = ?", "a4").Delete(&auditLogRow{})
	r = auditchain.Verify(read(), key)
	found := false
	for _, p := range r.Problems {
		if p.Kind == auditchain.ProblemMissing && p.Seq == 4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("a DELETE through SQL must be reported as a missing entry: %+v", r.Problems)
	}
}
