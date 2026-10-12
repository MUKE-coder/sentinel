package mysql

import (
	"context"
	"os"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/google/uuid"
)

func TestNewRejectsEmptyDSN(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("an empty DSN must be an error, not a connection attempt")
	}
}

func TestNewReportsUnreachableServer(t *testing.T) {
	// Port 1 has nothing listening: New must fail rather than hand back a
	// store that errors on every query later.
	_, err := New("sentinel:sentinel@tcp(127.0.0.1:1)/sentinel?parseTime=True")
	if err == nil {
		t.Error("an unreachable server must be an error at New")
	}
}

// TestRoundTrip runs against a real MySQL when SENTINEL_MYSQL_DSN is set:
//
//	docker run --rm -e MYSQL_ROOT_PASSWORD=pw -e MYSQL_DATABASE=sentinel -p 3306:3306 mysql:8
//	SENTINEL_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/sentinel?charset=utf8mb4&parseTime=True' go test ./storage/mysql
//
// It covers what the schema needs from MySQL specifically: indexes on string
// columns, and JSON blobs longer than a VARCHAR.
func TestRoundTrip(t *testing.T) {
	dsn := os.Getenv("SENTINEL_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set SENTINEL_MYSQL_DSN to run the MySQL round trip")
	}
	store, err := New(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// A body snippet and evidence blob longer than any VARCHAR the driver
	// would pick for an untagged column.
	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'a'
	}
	threat := &sentinel.ThreatEvent{
		ID:          uuid.NewString(),
		Timestamp:   time.Now().UTC(),
		IP:          "203.0.113.9",
		Method:      "GET",
		Path:        "/api/items",
		BodySnippet: string(long),
		ThreatTypes: []string{string(sentinel.ThreatSQLi)},
		Severity:    sentinel.SeverityHigh,
		Confidence:  90,
	}
	if err := store.SaveThreat(ctx, threat); err != nil {
		t.Fatalf("SaveThreat: %v", err)
	}
	got, err := store.GetThreat(ctx, threat.ID)
	if err != nil {
		t.Fatalf("GetThreat: %v", err)
	}
	if len(got.BodySnippet) != len(long) {
		t.Errorf("body snippet came back %d bytes, want %d — the column is too narrow", len(got.BodySnippet), len(long))
	}

	if err := store.BlockIP(ctx, "203.0.113.9", "test", nil); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	blocked, err := store.IsIPBlocked(ctx, "203.0.113.9")
	if err != nil || !blocked {
		t.Errorf("IsIPBlocked = %v, %v; want true", blocked, err)
	}

	doc := &sentinel.LiveSettings{WAFMode: sentinel.ModeBlock}
	if err := store.SaveLiveSettings(ctx, doc); err != nil {
		t.Fatalf("SaveLiveSettings: %v", err)
	}
	stored, err := store.LiveSettings(ctx)
	if err != nil || stored == nil || stored.WAFMode != sentinel.ModeBlock {
		t.Errorf("LiveSettings = %+v, %v; want the stored block mode", stored, err)
	}
}

// Replicas start together and all run migrations against the one database.
// MySQL answers whichever lost the race with "table already exists", so
// Migrate retries; both callers must come back clean, or a starting replica
// dies on a race.
func TestConcurrentMigrate(t *testing.T) {
	dsn := os.Getenv("SENTINEL_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set SENTINEL_MYSQL_DSN to run the concurrent migration test")
	}

	const replicas = 4
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		go func() {
			store, err := New(dsn)
			if err != nil {
				errs <- err
				return
			}
			defer store.Close()
			errs <- store.Migrate(context.Background())
		}()
	}
	for i := 0; i < replicas; i++ {
		if err := <-errs; err != nil {
			t.Errorf("replica %d: %v", i+1, err)
		}
	}
}
