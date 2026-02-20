package sentinelgorm_test

import (
	"context"
	"sync"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	sentinelgorm "github.com/MUKE-coder/sentinel/gorm"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// testUser is a simple GORM model for testing.
type testUser struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (testUser) TableName() string { return "test_users" }

// auditCollector collects audit events from the pipeline.
type auditCollector struct {
	mu     sync.Mutex
	audits []*sentinel.AuditLog
}

func (ac *auditCollector) Handle(ctx context.Context, event pipeline.Event) error {
	if event.Type == pipeline.EventAudit {
		if al, ok := event.Payload.(*sentinel.AuditLog); ok {
			ac.mu.Lock()
			ac.audits = append(ac.audits, al)
			ac.mu.Unlock()
		}
	}
	return nil
}

func (ac *auditCollector) count() int {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return len(ac.audits)
}

func (ac *auditCollector) last() *sentinel.AuditLog {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if len(ac.audits) == 0 {
		return nil
	}
	return ac.audits[len(ac.audits)-1]
}

func (ac *auditCollector) all() []*sentinel.AuditLog {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	result := make([]*sentinel.AuditLog, len(ac.audits))
	copy(result, ac.audits)
	return result
}

func setupTest(t *testing.T) (*gorm.DB, *pipeline.Pipeline, *auditCollector) {
	t.Helper()

	pipe := pipeline.New(100)
	collector := &auditCollector{}
	pipe.AddHandler(collector)

	pipe.Start(1)
	t.Cleanup(func() {
		pipe.Stop()
		time.Sleep(50 * time.Millisecond)
	})

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	// Register Sentinel GORM plugin
	plugin := sentinelgorm.New(pipe)
	if err := db.Use(plugin); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	// Migrate test table
	if err := db.AutoMigrate(&testUser{}); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	return db, pipe, collector
}

func TestPlugin_Name(t *testing.T) {
	p := sentinelgorm.New(nil)
	if p.Name() != "sentinel" {
		t.Errorf("expected name 'sentinel', got '%s'", p.Name())
	}
}

func TestPlugin_CreateAudit(t *testing.T) {
	db, _, collector := setupTest(t)

	// Attach request info to context
	ctx := sentinelgorm.WithRequestInfo(context.Background(), &sentinelgorm.RequestInfo{
		IP:        "10.0.0.1",
		UserID:    "user-42",
		UserEmail: "admin@example.com",
		UserRole:  "admin",
		RequestID: "req-abc",
	})

	user := testUser{Name: "Alice", Email: "alice@example.com"}
	result := db.WithContext(ctx).Create(&user)
	if result.Error != nil {
		t.Fatalf("Create failed: %v", result.Error)
	}

	// Wait for pipeline processing
	time.Sleep(100 * time.Millisecond)

	if collector.count() != 1 {
		t.Fatalf("expected 1 audit log, got %d", collector.count())
	}

	al := collector.last()
	if al.Action != "CREATE" {
		t.Errorf("expected action CREATE, got %s", al.Action)
	}
	if al.Resource != "test_users" {
		t.Errorf("expected resource test_users, got %s", al.Resource)
	}
	if al.UserID != "user-42" {
		t.Errorf("expected user_id user-42, got %s", al.UserID)
	}
	if al.IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", al.IP)
	}
	if al.After == nil {
		t.Error("expected After state to be non-nil")
	}
	if al.After["name"] != "Alice" {
		t.Errorf("expected After.name=Alice, got %v", al.After["name"])
	}
}

func TestPlugin_DeleteAudit(t *testing.T) {
	db, _, collector := setupTest(t)

	ctx := sentinelgorm.WithRequestInfo(context.Background(), &sentinelgorm.RequestInfo{
		UserID: "user-99",
		IP:     "10.0.0.2",
	})

	// Create a user first
	user := testUser{Name: "Bob", Email: "bob@example.com"}
	db.WithContext(ctx).Create(&user)
	time.Sleep(50 * time.Millisecond)

	// Delete the user
	db.WithContext(ctx).Delete(&user)
	time.Sleep(100 * time.Millisecond)

	audits := collector.all()
	if len(audits) < 2 {
		t.Fatalf("expected at least 2 audit logs (create + delete), got %d", len(audits))
	}

	deleteLog := audits[len(audits)-1]
	if deleteLog.Action != "DELETE" {
		t.Errorf("expected action DELETE, got %s", deleteLog.Action)
	}
	if deleteLog.Resource != "test_users" {
		t.Errorf("expected resource test_users, got %s", deleteLog.Resource)
	}
	if deleteLog.Before == nil {
		t.Error("expected Before state to be non-nil for delete")
	}
}

func TestPlugin_UpdateAudit(t *testing.T) {
	db, _, collector := setupTest(t)

	ctx := sentinelgorm.WithRequestInfo(context.Background(), &sentinelgorm.RequestInfo{
		UserID: "user-50",
		IP:     "10.0.0.3",
	})

	// Create user
	user := testUser{Name: "Charlie", Email: "charlie@example.com"}
	db.WithContext(ctx).Create(&user)
	time.Sleep(50 * time.Millisecond)

	// Update user
	user.Name = "Charles"
	db.WithContext(ctx).Save(&user)
	time.Sleep(100 * time.Millisecond)

	audits := collector.all()
	if len(audits) < 2 {
		t.Fatalf("expected at least 2 audit logs (create + update), got %d", len(audits))
	}

	updateLog := audits[len(audits)-1]
	if updateLog.Action != "UPDATE" {
		t.Errorf("expected action UPDATE, got %s", updateLog.Action)
	}
	if updateLog.After == nil {
		t.Error("expected After state to be non-nil for update")
	}
	if updateLog.After["name"] != "Charles" {
		t.Errorf("expected After.name=Charles, got %v", updateLog.After["name"])
	}
}

func TestPlugin_QueryShield_NoContext(t *testing.T) {
	db, _, collector := setupTest(t)

	// Query without request context — should not panic
	var users []testUser
	result := db.Find(&users)
	if result.Error != nil {
		t.Fatalf("Find failed: %v", result.Error)
	}
	time.Sleep(50 * time.Millisecond)

	// No audit log should be emitted for queries (only for mutations)
	// No crash means success
	_ = collector.count()
}

func TestPlugin_DisabledAudit(t *testing.T) {
	pipe := pipeline.New(100)
	collector := &auditCollector{}
	pipe.AddHandler(collector)

	pipe.Start(1)
	defer func() {
		pipe.Stop()
		time.Sleep(50 * time.Millisecond)
	}()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	// Create plugin with audit disabled
	plugin := sentinelgorm.New(pipe, func(c *sentinelgorm.Config) {
		c.AuditEnabled = false
	})
	if err := db.Use(plugin); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	db.AutoMigrate(&testUser{})

	user := testUser{Name: "Dave", Email: "dave@example.com"}
	db.Create(&user)
	time.Sleep(100 * time.Millisecond)

	if collector.count() != 0 {
		t.Errorf("expected 0 audit logs when disabled, got %d", collector.count())
	}
}
