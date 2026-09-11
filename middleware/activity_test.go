package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

// eventRecorder collects pipeline payloads by type. Read it only after
// pipe.Stop(), which drains the buffer first.
type eventRecorder struct {
	mu         sync.Mutex
	activities []*sentinel.UserActivity
	audits     []*sentinel.AuditLog
	threats    []*sentinel.ThreatEvent
}

func (r *eventRecorder) Handle(_ context.Context, e pipeline.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch p := e.Payload.(type) {
	case *sentinel.UserActivity:
		r.activities = append(r.activities, p)
	case *sentinel.AuditLog:
		r.audits = append(r.audits, p)
	case *sentinel.ThreatEvent:
		r.threats = append(r.threats, p)
	}
	return nil
}

func newRecordingPipeline() (*pipeline.Pipeline, *eventRecorder) {
	pipe := pipeline.New(100)
	rec := &eventRecorder{}
	pipe.AddHandler(rec)
	pipe.Start(1)
	return pipe, rec
}

// fakeAuth stands in for a host app's auth middleware: it puts the user on
// the context when the request carries X-Test-User.
func fakeAuth(c *gin.Context) {
	if u := c.GetHeader("X-Test-User"); u != "" {
		c.Set("uid", u)
	}
	c.Next()
}

// contextUser is a UserExtractor reading what fakeAuth left on the context.
func contextUser(c *gin.Context) *sentinel.UserContext {
	id := c.GetString("uid")
	if id == "" {
		return nil
	}
	return &sentinel.UserContext{ID: id, Email: id + "@example.com"}
}

func serve(r *gin.Engine, path, user string) int {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "203.0.113.5:1234"
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestUserActivity_RecordsAuthenticatedRequests(t *testing.T) {
	pipe, rec := newRecordingPipeline()

	r := gin.New()
	r.Use(UserActivityMiddleware(contextUser, pipe, "/sentinel"))
	r.GET("/api/orders/:id", fakeAuth, func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/public", fakeAuth, func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/sentinel/api/threats", fakeAuth, func(c *gin.Context) { c.Status(http.StatusOK) })

	serve(r, "/api/orders/7", "u-42")
	serve(r, "/public", "")                   // anonymous: not recorded
	serve(r, "/sentinel/api/threats", "u-42") // Sentinel's own routes: not recorded
	pipe.Stop()

	if len(rec.activities) != 1 {
		t.Fatalf("expected 1 activity record, got %d", len(rec.activities))
	}
	a := rec.activities[0]
	if a.UserID != "u-42" || a.UserEmail != "u-42@example.com" {
		t.Errorf("wrong user on activity: %q / %q", a.UserID, a.UserEmail)
	}
	if a.Path != "/api/orders/:id" {
		t.Errorf("expected the route pattern /api/orders/:id (no record IDs), got %q", a.Path)
	}
	if a.Method != "GET" || a.StatusCode != http.StatusOK || a.IP != "203.0.113.5" {
		t.Errorf("unexpected request details: %s %d %s", a.Method, a.StatusCode, a.IP)
	}
}

// TestUserActivity_LinksWAFLoggedThreat: in log mode the request reaches the
// handler, so the activity record can point at the threat the WAF logged.
func TestUserActivity_LinksWAFLoggedThreat(t *testing.T) {
	pipe, rec := newRecordingPipeline()

	r := gin.New()
	r.Use(UserActivityMiddleware(contextUser, pipe, ""))
	r.Use(WAFMiddleware(sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeLog}, memory.New(), pipe, nil))
	r.GET("/api/products", fakeAuth, func(c *gin.Context) { c.Status(http.StatusOK) })

	if code := serve(r, "/api/products?id=1'+OR+1=1--", "u-7"); code != http.StatusOK {
		t.Fatalf("log mode should let the request through, got %d", code)
	}
	pipe.Stop()

	if len(rec.threats) != 1 || len(rec.activities) != 1 {
		t.Fatalf("expected 1 threat and 1 activity, got %d and %d", len(rec.threats), len(rec.activities))
	}
	if rec.activities[0].ThreatID == "" || rec.activities[0].ThreatID != rec.threats[0].ID {
		t.Errorf("activity ThreatID %q does not link threat %q", rec.activities[0].ThreatID, rec.threats[0].ID)
	}
}

func TestUserActivity_ExtractorPanicIsContained(t *testing.T) {
	pipe, rec := newRecordingPipeline()

	r := gin.New() // no Recovery: an escaped panic fails the test
	r.Use(UserActivityMiddleware(func(*gin.Context) *sentinel.UserContext { panic("boom") }, pipe, ""))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	if code := serve(r, "/x", ""); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	pipe.Stop()
	if len(rec.activities) != 0 {
		t.Errorf("expected no activity when the extractor panics, got %d", len(rec.activities))
	}
}

// TestAuthShield_AuditsLoginAttempts: login attempts that reach the handler
// become auth audit entries — the data the PCI-DSS report's auth section
// counts, which nothing recorded before v2.3.0.
func TestAuthShield_AuditsLoginAttempts(t *testing.T) {
	pipe, rec := newRecordingPipeline()
	r, _ := setupAuthShieldRouter(sentinel.AuthShieldConfig{
		Enabled:           true,
		LoginRoute:        "/api/login",
		MaxFailedAttempts: 5,
		LockoutDuration:   time.Minute,
	}, pipe)

	r.ServeHTTP(httptest.NewRecorder(), loginRequest("admin", "wrong"))
	r.ServeHTTP(httptest.NewRecorder(), loginRequest("admin", "secret"))
	pipe.Stop()

	if len(rec.audits) != 2 {
		t.Fatalf("expected 2 login audit entries, got %d", len(rec.audits))
	}
	for i, wantSuccess := range []bool{false, true} {
		a := rec.audits[i]
		if a.Resource != sentinel.AuditResourceAuth || a.Action != "LOGIN" || a.UserID != "admin" || a.ResourceID != "/api/login" {
			t.Errorf("entry %d: unexpected %s %s %s %s", i, a.Action, a.Resource, a.ResourceID, a.UserID)
		}
		if a.Success != wantSuccess {
			t.Errorf("entry %d: success = %v, want %v", i, a.Success, wantSuccess)
		}
	}
}
