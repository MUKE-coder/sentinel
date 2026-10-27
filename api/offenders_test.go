package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/intelligence"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

type offenderServer struct {
	router  *gin.Engine
	token   string
	store   *memory.Store
	ipMgr   *intelligence.IPManager
	audited *auditRecorder

	// stopPipe drains the pipeline so the recorder can be read. Stopping
	// twice panics, so it runs once however many callers ask.
	stopPipe func()
}

func newOffenderServer(t *testing.T) *offenderServer {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := memory.New()
	pipe := pipeline.New(100)
	rec := &auditRecorder{}
	pipe.AddHandler(rec)
	pipe.Start(1)
	var once sync.Once
	stop := func() { once.Do(pipe.Stop) }
	t.Cleanup(stop)

	ipMgr := intelligence.NewIPManagerWithSync(store, 0)
	t.Cleanup(ipMgr.Stop)

	cfg := sentinel.Config{Dashboard: sentinel.DashboardConfig{
		Prefix: "/sentinel", Username: "admin", Password: "pw", SecretKey: "test-secret",
	}}
	srv := NewServer(store, pipe, ipMgr, nil, cfg)
	r := gin.New()
	srv.RegisterRoutes(r, "/sentinel")

	token, err := GenerateToken(cfg.Dashboard.SecretKey)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return &offenderServer{router: r, token: token, store: store, ipMgr: ipMgr, audited: rec, stopPipe: stop}
}

func (s *offenderServer) actor(t *testing.T, ip string, threats int, lastSeen time.Time, status sentinel.ActorStatus) {
	t.Helper()
	err := s.store.UpsertActor(context.Background(), &sentinel.ThreatActor{
		ID:          "actor-" + ip,
		IP:          ip,
		ThreatCount: threats,
		LastSeen:    lastSeen,
		FirstSeen:   lastSeen.Add(-time.Hour),
		Status:      status,
	})
	if err != nil {
		t.Fatalf("UpsertActor: %v", err)
	}
}

func (s *offenderServer) post(body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/sentinel/api/ip/block-offenders", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	return w
}

type offenderResponse struct {
	Data struct {
		Matched   int      `json:"matched"`
		Blocked   int      `json:"blocked"`
		IPs       []string `json:"ips"`
		DryRun    bool     `json:"dry_run"`
		Truncated bool     `json:"truncated"`
	} `json:"data"`
}

func decodeOffenders(t *testing.T, w *httptest.ResponseRecorder) offenderResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var got offenderResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// Going through a scan by hand is how a threat log with thousands of rows
// gets ignored. One call blocks everyone over the threshold — and a dry run
// shows who that is before anything happens.
func TestBlockOffenders_DryRunThenBlock(t *testing.T) {
	s := newOffenderServer(t)
	now := time.Now()
	s.actor(t, "203.0.113.1", 40, now, sentinel.ActorActive)                       // scanner
	s.actor(t, "203.0.113.2", 12, now.Add(-time.Hour), sentinel.ActorActive)       // scanner
	s.actor(t, "203.0.113.3", 2, now, sentinel.ActorActive)                        // below the threshold
	s.actor(t, "203.0.113.4", 99, now.Add(-30*24*time.Hour), sentinel.ActorActive) // long gone

	dry := decodeOffenders(t, s.post(`{"min_threats":5,"since":"168h","dry_run":true}`))
	if dry.Data.Matched != 2 || dry.Data.Blocked != 0 {
		t.Fatalf("dry run matched %d blocked %d, want 2 and 0 (%v)", dry.Data.Matched, dry.Data.Blocked, dry.Data.IPs)
	}
	if !dry.Data.DryRun {
		t.Error("the response should say it was a dry run")
	}
	if s.ipMgr.IsBlocked("203.0.113.1") {
		t.Fatal("a dry run must block nobody")
	}

	real := decodeOffenders(t, s.post(`{"min_threats":5,"since":"168h"}`))
	if real.Data.Blocked != 2 {
		t.Fatalf("blocked %d, want 2 (%v)", real.Data.Blocked, real.Data.IPs)
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if !s.ipMgr.IsBlocked(ip) {
			t.Errorf("%s should be blocked", ip)
		}
	}
	for _, ip := range []string{"203.0.113.3", "203.0.113.4"} {
		if s.ipMgr.IsBlocked(ip) {
			t.Errorf("%s is below the threshold or too old and must not be blocked", ip)
		}
	}

	// Running it again finds nobody new: the blocked ones are skipped.
	again := decodeOffenders(t, s.post(`{"min_threats":5,"since":"168h"}`))
	if again.Data.Matched != 0 {
		t.Errorf("a second run matched %d, want 0 — already-blocked addresses must be skipped", again.Data.Matched)
	}

	// The operation is audited once, with the addresses as evidence.
	s.stopPipe()
	s.audited.mu.Lock()
	defer s.audited.mu.Unlock()
	var bulk []*sentinel.AuditLog
	for _, entry := range s.audited.entries {
		if entry.Action == "CREATE" && entry.ResourceID == "bulk" {
			bulk = append(bulk, entry)
		}
	}
	if len(bulk) != 1 {
		t.Fatalf("want exactly one bulk audit entry (the sweep that blocked nobody is not a change), got %d", len(bulk))
	}
	if blocked, _ := bulk[0].After["blocked"].(int); blocked != 2 {
		t.Errorf("the audit entry should record 2 blocked, got %v", bulk[0].After["blocked"])
	}
}

// Whitelisted addresses are never swept up, however much they trip
// detection.
func TestBlockOffenders_SkipsWhitelisted(t *testing.T) {
	s := newOffenderServer(t)
	now := time.Now()
	s.actor(t, "198.51.100.1", 50, now, sentinel.ActorWhitelisted)
	s.actor(t, "198.51.100.2", 50, now, sentinel.ActorActive)
	if err := s.ipMgr.WhitelistIP(context.Background(), "198.51.100.2"); err != nil {
		t.Fatal(err)
	}

	got := decodeOffenders(t, s.post(`{"min_threats":5}`))
	if got.Data.Blocked != 0 {
		t.Errorf("blocked %d, want 0 — both addresses are whitelisted (%v)", got.Data.Blocked, got.Data.IPs)
	}
}

// The criteria have to be usable, or the call is refused rather than
// guessing at what was meant.
func TestBlockOffenders_RejectsBadCriteria(t *testing.T) {
	s := newOffenderServer(t)
	for _, body := range []string{
		`{"since":"last week"}`,
		`{"since":"-5h"}`,
		`{"duration":"forever"}`,
		`{"duration":"0s"}`,
	} {
		if code := s.post(body).Code; code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", body, code)
		}
	}
}
