package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/detection"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

const sqliPath = "/api/products?id=1'+OR+1=1--"

func wafRouter(w *WAF) *gin.Engine {
	r := gin.New()
	r.Use(w.Handler())
	r.GET("/api/products", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/wp-admin", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func status(r *gin.Engine, path string) int {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w.Code
}

func defaultRules() sentinel.RuleSet {
	var cfg sentinel.Config
	cfg.ApplyDefaults()
	return cfg.WAF.Rules
}

// TestWAF_ModeChangesWhileRunning: before v2.3.0 PUT /waf/rules only changed
// the API server's copy of the config; the middleware kept its mount-time mode.
func TestWAF_ModeChangesWhileRunning(t *testing.T) {
	waf := NewWAF(sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeBlock, Rules: defaultRules()}, memory.New(), nil, nil)
	r := wafRouter(waf)

	if code := status(r, sqliPath); code != http.StatusForbidden {
		t.Fatalf("block mode: got %d, want 403", code)
	}
	if err := waf.SetMode(sentinel.ModeLog); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	if code := status(r, sqliPath); code != http.StatusOK {
		t.Errorf("after switching to log mode: got %d, want 200", code)
	}
	if err := waf.SetMode("Block"); err == nil {
		t.Error("SetMode must reject an unknown mode — it would silently act as log mode")
	}
	if waf.Mode() != sentinel.ModeLog {
		t.Errorf("a rejected SetMode must not change the mode, got %s", waf.Mode())
	}
}

func TestWAF_RuleSensitivityIsEnforced(t *testing.T) {
	rules := defaultRules()
	waf := NewWAF(sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeBlock, Rules: rules}, memory.New(), nil, nil)
	r := wafRouter(waf)

	if code := status(r, sqliPath); code != http.StatusForbidden {
		t.Fatalf("SQLi at strict: got %d, want 403", code)
	}
	rules.SQLInjection = sentinel.RuleOff
	if err := waf.SetRules(rules); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	if code := status(r, sqliPath); code != http.StatusOK {
		t.Errorf("SQLi with SQLInjection off: got %d, want 200", code)
	}
	rules.SQLInjection = "paranoid"
	if err := waf.SetRules(rules); err == nil {
		t.Error("SetRules must reject an unknown sensitivity")
	}
}

// TestWAF_LogOnlyCustomRule: a custom rule with Action "log" is watched, not
// enforced — even in block mode — unless something else on the request is.
func TestWAF_LogOnlyCustomRule(t *testing.T) {
	engine := detection.NewCustomRuleEngine([]sentinel.WAFRule{
		{ID: "watch", Name: "watch-admin", Pattern: `/wp-admin`, AppliesTo: []string{"path"}, Severity: sentinel.SeverityHigh, Action: detection.RuleActionLog, Enabled: true},
	})
	pipe, rec := newRecordingPipeline()
	waf := NewWAF(sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeBlock, Rules: defaultRules()}, memory.New(), pipe, engine)
	r := wafRouter(waf)

	if code := status(r, "/wp-admin"); code != http.StatusOK {
		t.Errorf("log-only rule in block mode: got %d, want 200", code)
	}
	if code := status(r, "/wp-admin?id=1'+OR+1=1--"); code != http.StatusForbidden {
		t.Errorf("log-only rule plus a built-in SQLi match: got %d, want 403", code)
	}
	pipe.Stop()

	if len(rec.threats) != 2 {
		t.Fatalf("expected both requests recorded as threats, got %d", len(rec.threats))
	}
	if rec.threats[0].Blocked || !rec.threats[1].Blocked {
		t.Errorf("blocked flags: log-only=%v mixed=%v, want false/true", rec.threats[0].Blocked, rec.threats[1].Blocked)
	}
}
