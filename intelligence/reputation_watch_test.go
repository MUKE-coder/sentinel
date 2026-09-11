package intelligence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
)

// fakeAbuseIPDB scores 203.0.113.66 as abusive and everything else as clean,
// counting calls.
func fakeAbuseIPDB(t *testing.T, calls *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		ip := r.URL.Query().Get("ipAddress")
		score := 0
		if ip == "203.0.113.66" {
			score = 97
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"ipAddress": ip, "abuseConfidenceScore": score, "isp": "Example Hosting", "totalReports": 12,
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func threatFrom(ip string) pipeline.Event {
	return pipeline.Event{Type: pipeline.EventThreat, Payload: &sentinel.ThreatEvent{ID: "t-" + ip, IP: ip, Timestamp: time.Now()}}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestReputationWatcher_ChecksLiveTraffic: before v2.4.0 AbuseIPDB was only
// consulted when someone opened an IP in the dashboard, so AutoBlock never
// acted on live traffic.
func TestReputationWatcher_ChecksLiveTraffic(t *testing.T) {
	var calls atomic.Int64
	srv := fakeAbuseIPDB(t, &calls)
	store := memory.New()
	ctx := context.Background()
	store.UpsertActor(ctx, &sentinel.ThreatActor{ID: "203.0.113.66", IP: "203.0.113.66", LastSeen: time.Now()})

	ipMgr := NewIPManager(store)
	defer ipMgr.Stop()
	checker := NewReputationChecker(sentinel.IPReputationConfig{
		Enabled: true, AbuseIPDBKey: "k", AutoBlock: true, MinAbuseScore: 80,
	}, ipMgr)
	checker.endpoint = srv.URL
	w := NewReputationWatcher(checker, store, 10)
	defer w.Stop()

	w.Handle(ctx, threatFrom("203.0.113.66"))

	waitFor(t, "the actor to be scored", func() bool {
		a, _ := store.GetActor(ctx, "203.0.113.66")
		return a != nil && a.AbuseScore == 97
	})
	a, _ := store.GetActor(ctx, "203.0.113.66")
	if !a.IsKnownBadActor || a.ISP != "Example Hosting" || a.RiskScore < 20 {
		t.Errorf("actor not updated from reputation: %+v", a)
	}
	if !ipMgr.IsBlocked("203.0.113.66") {
		t.Error("AutoBlock should block an IP scored above MinAbuseScore on live traffic")
	}

	// The same IP again the same day costs nothing.
	w.Handle(ctx, threatFrom("203.0.113.66"))
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", calls.Load())
	}
}

func TestReputationWatcher_RespectsQuotaAndSkipsPrivateIPs(t *testing.T) {
	var calls atomic.Int64
	srv := fakeAbuseIPDB(t, &calls)
	ipMgr := NewIPManager(memory.New())
	defer ipMgr.Stop()
	checker := NewReputationChecker(sentinel.IPReputationConfig{Enabled: true, AbuseIPDBKey: "k", MinAbuseScore: 80}, ipMgr)
	checker.endpoint = srv.URL
	w := NewReputationWatcher(checker, memory.New(), 2)
	defer w.Stop()

	ctx := context.Background()
	for _, ip := range []string{"10.0.0.5", "127.0.0.1", "192.168.1.9", "fe80::1"} {
		w.Handle(ctx, threatFrom(ip))
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		w.Handle(ctx, threatFrom(ip))
	}

	waitFor(t, "the quota to be spent", func() bool { return w.UsedToday() == 2 })
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 2 {
		t.Errorf("a quota of 2 must allow exactly 2 API calls (private IPs never count), got %d", calls.Load())
	}
}
