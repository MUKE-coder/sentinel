package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/storage/postgres"
)

// TestPostgresStore_Smoke runs the same minimal interface check the SQLite
// adapter passes. It only runs when SENTINEL_TEST_PG_DSN points at a
// reachable Postgres ("postgres://user:pass@host:5432/db?sslmode=disable").
// CI sets this; local devs without Postgres skip cleanly.
func TestPostgresStore_Smoke(t *testing.T) {
	dsn := os.Getenv("SENTINEL_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("SENTINEL_TEST_PG_DSN not set — skipping Postgres integration test")
	}

	store, err := postgres.New(dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	threat := &sentinel.ThreatEvent{
		ID:          "pg-test-1",
		Timestamp:   time.Now().UTC(),
		IP:          "203.0.113.5",
		ActorID:     "actor_test",
		Method:      "GET",
		Path:        "/api/users",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityHigh,
		Confidence:  90,
	}
	if err := store.SaveThreat(ctx, threat); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := store.GetThreat(ctx, threat.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil || got.ID != threat.ID {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}

	list, total, err := store.ListThreats(ctx, sentinel.ThreatFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total < 1 || len(list) < 1 {
		t.Fatalf("list returned empty: total=%d len=%d", total, len(list))
	}
}
