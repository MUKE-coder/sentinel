package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/sentinel/v2/alerting"
	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/detection"
	"github.com/MUKE-coder/sentinel/v2/liveconfig"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

type settingsServer struct {
	router *gin.Engine
	token  string
	waf    *middleware.WAF
	store  *memory.Store
}

// newSettingsServer mounts the API over a running WAF, with or without the
// manager that stores dashboard settings.
func newSettingsServer(t *testing.T, persistable bool) *settingsServer {
	t.Helper()
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)
	t.Cleanup(pipe.Stop)

	cfg := sentinel.Config{
		Dashboard: sentinel.DashboardConfig{Prefix: "/sentinel", Username: "admin", Password: "pw", SecretKey: "test-secret"},
		WAF:       sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeLog, Rules: sentinel.RuleSet{SQLInjection: sentinel.RuleStrict}},
		Alerts:    sentinel.AlertConfig{MinSeverity: sentinel.SeverityHigh},
		Storage:   sentinel.StorageConfig{SyncInterval: 5 * time.Second},
	}
	waf := middleware.NewWAF(cfg.WAF, store, pipe, nil)
	rules := detection.NewCustomRuleEngine(nil)

	srv := NewServer(store, pipe, nil, nil, cfg)
	srv.SetWAF(waf)
	srv.SetCustomRuleEngine(rules)
	srv.SetAlertDispatcher(alerting.NewDispatcher(cfg.Alerts))
	if persistable {
		srv.SetLiveConfig(liveconfig.New(store, liveconfig.Targets{WAF: waf, CustomRules: rules}))
	}

	s := &settingsServer{router: gin.New(), waf: waf, store: store}
	srv.RegisterRoutes(s.router, "/sentinel")

	token, err := GenerateToken(cfg.Dashboard.SecretKey)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	s.token = token
	return s
}

func (s *settingsServer) do(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	return w
}

// A change through the dashboard is stored, so GET reports it next to the
// configured value and a restart would start from it.
func TestLiveSettings_ChangeIsStored(t *testing.T) {
	s := newSettingsServer(t, true)

	w := s.do("PUT", "/sentinel/api/waf/rules", `{"mode":"block"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /waf/rules: %d %s", w.Code, w.Body.String())
	}
	var updated map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if warning, ok := updated["warning"]; ok {
		t.Errorf("a stored change must not warn: %v", warning)
	}

	w = s.do("GET", "/sentinel/api/settings/live", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /settings/live: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Data struct {
			Persistable  bool   `json:"persistable"`
			SyncInterval string `json:"sync_interval"`
			Stored       *struct {
				WAFMode   string `json:"waf_mode"`
				Revision  int64  `json:"revision"`
				UpdatedBy string `json:"updated_by"`
			} `json:"stored"`
			Configured struct {
				WAFMode string `json:"waf_mode"`
			} `json:"configured"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Data.Persistable {
		t.Error("persistable should be true when a settings store is wired")
	}
	if got.Data.Stored == nil {
		t.Fatal("the stored settings are missing")
	}
	if got.Data.Stored.WAFMode != string(sentinel.ModeBlock) {
		t.Errorf("stored mode = %q, want block", got.Data.Stored.WAFMode)
	}
	if got.Data.Stored.Revision != 1 || got.Data.Stored.UpdatedBy != "admin" {
		t.Errorf("stored revision/author = %d/%q, want 1/admin", got.Data.Stored.Revision, got.Data.Stored.UpdatedBy)
	}
	if got.Data.Configured.WAFMode != string(sentinel.ModeLog) {
		t.Errorf("configured mode = %q, want the mount-time log", got.Data.Configured.WAFMode)
	}
	if got.Data.SyncInterval != "5s" {
		t.Errorf("sync_interval = %q, want 5s", got.Data.SyncInterval)
	}
}

// Discarding the stored settings puts the configured values back.
func TestLiveSettings_ResetRestoresConfigured(t *testing.T) {
	s := newSettingsServer(t, true)

	if w := s.do("PUT", "/sentinel/api/waf/rules", `{"mode":"block"}`); w.Code != http.StatusOK {
		t.Fatalf("PUT /waf/rules: %d", w.Code)
	}
	if s.waf.Mode() != sentinel.ModeBlock {
		t.Fatalf("running mode = %s, want block", s.waf.Mode())
	}

	w := s.do("DELETE", "/sentinel/api/settings/live", "")
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE /settings/live: %d %s", w.Code, w.Body.String())
	}
	if s.waf.Mode() != sentinel.ModeLog {
		t.Errorf("running mode after a reset = %s, want the configured log", s.waf.Mode())
	}

	w = s.do("GET", "/sentinel/api/settings/live", "")
	var got struct {
		Data struct {
			Stored *json.RawMessage `json:"stored"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Data.Stored != nil && string(*got.Data.Stored) != "null" {
		t.Errorf("stored settings should be gone, got %s", *got.Data.Stored)
	}
}

// With storage that cannot keep settings, the change still applies — and the
// response says it will not outlive this process, instead of looking
// permanent.
func TestLiveSettings_WarnsWhenNotPersistable(t *testing.T) {
	s := newSettingsServer(t, false)

	w := s.do("PUT", "/sentinel/api/waf/rules", `{"mode":"block"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /waf/rules: %d %s", w.Code, w.Body.String())
	}
	var updated struct {
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(updated.Warning, "this instance only") {
		t.Errorf("warning = %q, want it to say the change applies to this instance only", updated.Warning)
	}
	if s.waf.Mode() != sentinel.ModeBlock {
		t.Error("the change must still apply to the running WAF")
	}

	w = s.do("GET", "/sentinel/api/settings/live", "")
	if !strings.Contains(w.Body.String(), `"persistable":false`) {
		t.Errorf("GET /settings/live should report persistable false: %s", w.Body.String())
	}
	if w := s.do("DELETE", "/sentinel/api/settings/live", ""); w.Code != http.StatusConflict {
		t.Errorf("DELETE with nothing stored: %d, want 409", w.Code)
	}
}
