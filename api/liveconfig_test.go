package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/MUKE-coder/sentinel/v2/alerting"
	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/detection"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

type liveServer struct {
	router     *gin.Engine
	token      string
	waf        *middleware.WAF
	limiter    *middleware.RateLimiter
	dispatcher *alerting.Dispatcher
}

// newLiveServer mounts the API wired to a running WAF, rate limiter, and
// alert dispatcher, the way MountE does.
func newLiveServer(t *testing.T) *liveServer {
	t.Helper()
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)
	t.Cleanup(pipe.Stop)

	cfg := sentinel.Config{
		Dashboard: sentinel.DashboardConfig{Prefix: "/sentinel", Username: "admin", Password: "pw", SecretKey: "test-secret"},
		WAF:       sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeBlock, Rules: sentinel.RuleSet{SQLInjection: sentinel.RuleStrict, XSS: sentinel.RuleStrict}},
		RateLimit: sentinel.RateLimitConfig{
			Enabled:  true,
			Strategy: sentinel.SlidingWindow,
			ByRoute:  map[string]sentinel.Limit{"/api/login": {Requests: 5, Window: time.Minute}},
		},
		Alerts: sentinel.AlertConfig{MinSeverity: sentinel.SeverityHigh},
	}
	ls := &liveServer{
		waf:        middleware.NewWAF(cfg.WAF, store, pipe, nil),
		limiter:    middleware.NewRateLimiter(),
		dispatcher: alerting.NewDispatcher(cfg.Alerts),
	}
	t.Cleanup(ls.limiter.Stop)
	middleware.RateLimitMiddleware(cfg.RateLimit, ls.limiter, pipe) // applies strategy and routes

	srv := NewServer(store, pipe, nil, nil, cfg)
	srv.SetWAF(ls.waf)
	srv.SetRateLimiter(ls.limiter)
	srv.SetAlertDispatcher(ls.dispatcher)
	srv.SetCustomRuleEngine(detection.NewCustomRuleEngine(nil))
	ls.router = gin.New()
	srv.RegisterRoutes(ls.router, "/sentinel")

	token, err := GenerateToken(cfg.Dashboard.SecretKey)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	ls.token = token
	return ls
}

func (ls *liveServer) call(method, path, body string) int {
	return call(ls.router, method, path, ls.token, body)
}

// TestUpdateWAFRules_ReachesRunningWAF: before v2.3.0 this endpoint changed
// only the API server's copy of the config; the WAF kept enforcing the
// mount-time mode and a request without "rules" reset every category.
func TestUpdateWAFRules_ReachesRunningWAF(t *testing.T) {
	ls := newLiveServer(t)

	if code := ls.call("PUT", "/sentinel/api/waf/rules", `{"mode":"log","rules":{"SQLInjection":"off"}}`); code != http.StatusOK {
		t.Fatalf("PUT /waf/rules: got %d", code)
	}
	if ls.waf.Mode() != sentinel.ModeLog {
		t.Errorf("running WAF mode = %s, want log", ls.waf.Mode())
	}
	rules := ls.waf.Rules()
	if rules.SQLInjection != sentinel.RuleOff || rules.XSS != sentinel.RuleStrict {
		t.Errorf("rules = %+v, want SQLInjection off and XSS left at strict", rules)
	}

	if code := ls.call("PUT", "/sentinel/api/waf/rules", `{"mode":"block"}`); code != http.StatusOK {
		t.Fatalf("mode-only PUT: got %d", code)
	}
	if ls.waf.Rules().SQLInjection != sentinel.RuleOff {
		t.Error("a mode-only update must not reset the rule set")
	}
}

func TestUpdateWAFRules_RejectsInvalidInput(t *testing.T) {
	ls := newLiveServer(t)

	for _, body := range []string{`{"mode":"Block"}`, `{"rules":{"XSS":"paranoid"}}`} {
		if code := ls.call("PUT", "/sentinel/api/waf/rules", body); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", body, code)
		}
	}
	if ls.waf.Mode() != sentinel.ModeBlock || ls.waf.Rules().XSS != sentinel.RuleStrict {
		t.Error("a rejected update must leave the running WAF unchanged")
	}
}

func TestUpdateWAFRules_WAFDisabled(t *testing.T) {
	r, pipe, _, token := newAuditTestServer(t, sentinel.Config{})
	defer pipe.Stop()
	srv := NewServer(memory.New(), pipe, nil, nil, sentinel.Config{Dashboard: sentinel.DashboardConfig{SecretKey: "test-secret"}})
	r = gin.New()
	srv.RegisterRoutes(r, "/sentinel")

	if code := call(r, "PUT", "/sentinel/api/waf/rules", token, `{"mode":"log"}`); code != http.StatusConflict {
		t.Errorf("with no running WAF: got %d, want 409", code)
	}
}

func TestUpdateRateLimits_ReachesRunningLimiter(t *testing.T) {
	ls := newLiveServer(t)

	body := `{"by_route":{"/api/search":{"requests":10,"window":"1m"},"/api/login":{"requests":0,"window":"1m"}}}`
	if code := ls.call("PUT", "/sentinel/api/rate-limits", body); code != http.StatusOK {
		t.Fatalf("PUT /rate-limits: got %d", code)
	}
	routes := ls.limiter.RouteLimits()
	if _, ok := routes["/api/login"]; ok {
		t.Error("requests 0 should remove the /api/login limit")
	}
	if got := routes["/api/search"]; got.Requests != 10 || got.Window != time.Minute {
		t.Errorf("/api/search limit = %+v, want 10/1m", got)
	}
}

func TestUpdateRateLimits_RejectsInvalidInput(t *testing.T) {
	ls := newLiveServer(t)

	for _, body := range []string{
		`{"by_route":{"/api/search":{"requests":10,"window":"soon"}}}`,
		`{"by_route":{"/api/search":{"requests":10,"window":"0s"}}}`,
		`{"by_route":{"/api/**/x":{"requests":10,"window":"1m"}}}`,
		`{"by_route":{"api/search":{"requests":10,"window":"1m"}}}`,
	} {
		if code := ls.call("PUT", "/sentinel/api/rate-limits", body); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", body, code)
		}
	}
	if routes := ls.limiter.RouteLimits(); len(routes) != 1 || routes["/api/login"].Requests != 5 {
		t.Errorf("a rejected update must leave the limits unchanged, got %v", routes)
	}
}

func TestUpdateAlertConfig_ReachesDispatcher(t *testing.T) {
	ls := newLiveServer(t)

	if code := ls.call("PUT", "/sentinel/api/alerts/config", `{"min_severity":"low"}`); code != http.StatusOK {
		t.Fatalf("PUT /alerts/config: got %d", code)
	}
	if ls.dispatcher.MinSeverity() != sentinel.SeverityLow {
		t.Errorf("dispatcher threshold = %s, want Low", ls.dispatcher.MinSeverity())
	}
	if code := ls.call("PUT", "/sentinel/api/alerts/config", `{"min_severity":"urgent"}`); code != http.StatusBadRequest {
		t.Errorf("unknown severity: got %d, want 400", code)
	}
	if ls.dispatcher.MinSeverity() != sentinel.SeverityLow {
		t.Error("a rejected update must leave the threshold unchanged")
	}
}

func TestAddCustomRule_RejectsUnknownAction(t *testing.T) {
	ls := newLiveServer(t)

	body := `{"id":"r1","name":"x","pattern":"x","applies_to":["path"],"severity":"High","action":"drop","enabled":true}`
	if code := ls.call("POST", "/sentinel/api/waf/custom-rules", body); code != http.StatusBadRequest {
		t.Errorf("unknown action: got %d, want 400", code)
	}
	body = `{"id":"r2","name":"x","pattern":"x","applies_to":["path"],"severity":"High","action":"log","enabled":true}`
	if code := ls.call("POST", "/sentinel/api/waf/custom-rules", body); code != http.StatusOK {
		t.Errorf("log action: got %d, want 200", code)
	}
}
