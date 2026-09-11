package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/intelligence"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

type auditRecorder struct {
	mu      sync.Mutex
	entries []*sentinel.AuditLog
}

func (r *auditRecorder) Handle(_ context.Context, e pipeline.Event) error {
	if a, ok := e.Payload.(*sentinel.AuditLog); ok {
		r.mu.Lock()
		r.entries = append(r.entries, a)
		r.mu.Unlock()
	}
	return nil
}

// newAuditTestServer mounts the API with a recording pipeline. Callers stop
// the pipeline before reading the recorder — Stop drains it.
func newAuditTestServer(t *testing.T, cfg sentinel.Config) (*gin.Engine, *pipeline.Pipeline, *auditRecorder, string) {
	t.Helper()
	store := memory.New()
	pipe := pipeline.New(100)
	rec := &auditRecorder{}
	pipe.AddHandler(rec)
	pipe.Start(1)
	ipMgr := intelligence.NewIPManager(store)
	t.Cleanup(ipMgr.Stop)

	cfg.Dashboard.Prefix = "/sentinel"
	cfg.Dashboard.Username = "admin"
	cfg.Dashboard.Password = "correct-horse"
	cfg.Dashboard.SecretKey = "test-secret"
	srv := NewServer(store, pipe, ipMgr, nil, cfg)
	srv.SetWAF(middleware.NewWAF(cfg.WAF, store, pipe, nil))
	r := gin.New()
	srv.RegisterRoutes(r, "/sentinel")

	token, err := GenerateToken(cfg.Dashboard.SecretKey)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return r, pipe, rec, token
}

func call(r *gin.Engine, method, path, token, body string) int {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.7:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// TestDashboardActionsAreAudited: before v2.3.0 no dashboard action left an
// audit entry, so an operator could unblock an attacker or switch the WAF
// to log-only without a trace.
func TestDashboardActionsAreAudited(t *testing.T) {
	r, pipe, rec, token := newAuditTestServer(t, sentinel.Config{WAF: sentinel.WAFConfig{Mode: sentinel.ModeBlock}})

	for _, step := range []struct{ method, path, body string }{
		{"POST", "/sentinel/api/ip/block", `{"ip":"203.0.113.9","reason":"scanner"}`},
		{"DELETE", "/sentinel/api/ip/block/203.0.113.9", ""},
		{"PUT", "/sentinel/api/waf/rules", `{"mode":"log"}`},
	} {
		if code := call(r, step.method, step.path, token, step.body); code != http.StatusOK {
			t.Fatalf("%s %s: got %d", step.method, step.path, code)
		}
	}
	pipe.Stop()

	want := []struct{ action, resource, id string }{
		{"CREATE", auditResourceIPBlock, "203.0.113.9"},
		{"DELETE", auditResourceIPBlock, "203.0.113.9"},
		{"UPDATE", auditResourceWAFConfig, "waf"},
	}
	if len(rec.entries) != len(want) {
		t.Fatalf("expected %d audit entries, got %d", len(want), len(rec.entries))
	}
	for i, w := range want {
		e := rec.entries[i]
		if e.Action != w.action || e.Resource != w.resource || e.ResourceID != w.id {
			t.Errorf("entry %d: got %s %s %s, want %s %s %s", i, e.Action, e.Resource, e.ResourceID, w.action, w.resource, w.id)
		}
		if e.UserID != "admin" || e.UserRole != dashboardRole || !e.Success || e.IP != "198.51.100.7" {
			t.Errorf("entry %d: actor/outcome %q %q success=%v ip=%q", i, e.UserID, e.UserRole, e.Success, e.IP)
		}
	}
	waf := rec.entries[2]
	if waf.Before["mode"] != "block" || waf.After["mode"] != "log" {
		t.Errorf("WAF change should record block -> log, got %v -> %v", waf.Before["mode"], waf.After["mode"])
	}
}

func TestDashboardLoginIsAudited(t *testing.T) {
	r, pipe, rec, _ := newAuditTestServer(t, sentinel.Config{})

	if code := call(r, "POST", "/sentinel/api/auth/login", "", `{"username":"admin","password":"wrong"}`); code != http.StatusUnauthorized {
		t.Fatalf("bad password: got %d", code)
	}
	if code := call(r, "POST", "/sentinel/api/auth/login", "", `{"username":"admin","password":"correct-horse"}`); code != http.StatusOK {
		t.Fatalf("good password: got %d", code)
	}
	pipe.Stop()

	if len(rec.entries) != 2 {
		t.Fatalf("expected 2 login entries, got %d", len(rec.entries))
	}
	for i, wantSuccess := range []bool{false, true} {
		e := rec.entries[i]
		if e.Action != "LOGIN" || e.Resource != sentinel.AuditResourceAuth || e.UserID != "admin" || e.Success != wantSuccess {
			t.Errorf("entry %d: got %s %s %s success=%v", i, e.Action, e.Resource, e.UserID, e.Success)
		}
	}
}

func TestComplianceReportsRefusedOnMemoryStorageInReleaseMode(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(gin.TestMode)

	r, pipe, _, token := newAuditTestServer(t, sentinel.Config{Storage: sentinel.StorageConfig{Driver: sentinel.Memory}})
	defer pipe.Stop()

	for _, path := range []string{"/sentinel/api/reports/gdpr", "/sentinel/api/reports/pci-dss", "/sentinel/api/reports/soc2"} {
		if code := call(r, "GET", path, token, ""); code != http.StatusConflict {
			t.Errorf("%s on memory storage in release mode: got %d, want 409", path, code)
		}
		if code := call(r, "GET", path+"?acknowledge_ephemeral=true", token, ""); code != http.StatusOK {
			t.Errorf("%s with acknowledge_ephemeral: got %d, want 200", path, code)
		}
	}
}

func TestComplianceReportsServedOnDurableStorageInReleaseMode(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(gin.TestMode)

	r, pipe, _, token := newAuditTestServer(t, sentinel.Config{Storage: sentinel.StorageConfig{Driver: sentinel.SQLite}})
	defer pipe.Stop()

	if code := call(r, "GET", "/sentinel/api/reports/gdpr", token, ""); code != http.StatusOK {
		t.Errorf("GDPR report on durable storage: got %d, want 200", code)
	}
}
