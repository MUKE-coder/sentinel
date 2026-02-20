package ai_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/ai"
)

// mockAIServer returns a test HTTP server that returns valid JSON for any prompt.
func mockAIServer(t *testing.T, responseJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Detect which provider based on headers
		if r.Header.Get("x-api-key") != "" {
			// Claude format
			resp := map[string]interface{}{
				"content": []map[string]string{
					{"type": "text", "text": responseJSON},
				},
			}
			json.NewEncoder(w).Encode(resp)
		} else if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			// OpenAI format
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{"message": map[string]string{"content": responseJSON}},
				},
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			// Gemini format
			resp := map[string]interface{}{
				"candidates": []map[string]interface{}{
					{"content": map[string]interface{}{
						"parts": []map[string]string{
							{"text": responseJSON},
						},
					}},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
}

func TestNewProvider_NilConfig(t *testing.T) {
	p := ai.NewProvider(nil)
	if p != nil {
		t.Error("expected nil provider for nil config")
	}
}

func TestNewProvider_EmptyAPIKey(t *testing.T) {
	p := ai.NewProvider(&sentinel.AIConfig{Provider: sentinel.Claude})
	if p != nil {
		t.Error("expected nil provider for empty API key")
	}
}

func TestNewProvider_AllProviders(t *testing.T) {
	for _, provider := range []sentinel.AIProvider{sentinel.Claude, sentinel.OpenAI, sentinel.Gemini} {
		p := ai.NewProvider(&sentinel.AIConfig{
			Provider: provider,
			APIKey:   "test-key",
		})
		if p == nil {
			t.Errorf("expected non-nil provider for %s", provider)
		}
	}
}

func TestNewProvider_UnknownProvider(t *testing.T) {
	p := ai.NewProvider(&sentinel.AIConfig{
		Provider: "unknown",
		APIKey:   "test-key",
	})
	if p != nil {
		t.Error("expected nil provider for unknown provider type")
	}
}

func TestCachedProvider_CachesThreatAnalysis(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"content": []map[string]string{
				{"type": "text", "text": `{"summary":"test","explanation":"test","severity_assessment":"High","succeeded":false,"recommendations":["block IP"],"threat_category":"SQLi","confidence":90}`},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create a provider that points to our mock server
	provider := ai.NewTestClaudeProvider("test-key", "test-model", server.URL)
	cached := ai.NewCachedProvider(provider, 1*time.Hour)

	threat := &sentinel.ThreatEvent{
		ID:          "threat-1",
		IP:          "1.2.3.4",
		Method:      "GET",
		Path:        "/admin",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityHigh,
	}

	ctx := context.Background()

	// First call — hits the API
	result1, err := cached.AnalyzeThreat(ctx, threat, nil)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if result1.Summary != "test" {
		t.Errorf("expected summary 'test', got '%s'", result1.Summary)
	}

	// Second call — should be cached
	result2, err := cached.AnalyzeThreat(ctx, threat, nil)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if result2.Summary != "test" {
		t.Errorf("expected summary 'test', got '%s'", result2.Summary)
	}

	if callCount != 1 {
		t.Errorf("expected 1 API call (cached), got %d", callCount)
	}
}

func TestCleanJSONResponse(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`{"key":"value"}`, `{"key":"value"}`},
		{"```json\n{\"key\":\"value\"}\n```", `{"key":"value"}`},
		{"```\n{\"key\":\"value\"}\n```", `{"key":"value"}`},
		{"  {\"key\":\"value\"}  ", `{"key":"value"}`},
	}

	for _, tt := range tests {
		result := ai.CleanJSONResponse(tt.input)
		if result != tt.expected {
			t.Errorf("cleanJSONResponse(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestPromptBuilding(t *testing.T) {
	threat := &sentinel.ThreatEvent{
		ID:          "t-1",
		Timestamp:   time.Now(),
		IP:          "10.0.0.1",
		Method:      "POST",
		Path:        "/api/login",
		StatusCode:  403,
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityCritical,
		Confidence:  95,
		Blocked:     true,
		QueryParams: "id=1' OR 1=1--",
		Evidence: []sentinel.Evidence{
			{Pattern: "union_select", Matched: "UNION SELECT", Location: "query", Parameter: "id"},
		},
		Country: "CN",
	}

	actor := &sentinel.ThreatActor{
		IP:            "10.0.0.1",
		Country:       "CN",
		ISP:           "Cloud Provider",
		TotalRequests: 500,
		ThreatCount:   45,
		RiskScore:     85,
		AttackTypes:   []string{"SQLi", "XSS"},
		FirstSeen:     time.Now().Add(-24 * time.Hour),
		LastSeen:      time.Now(),
		AbuseScore:    90,
	}

	// Just verify the prompts are non-empty and contain key data
	prompt := ai.BuildThreatAnalysisPromptExported(threat, actor)
	if !strings.Contains(prompt, "10.0.0.1") {
		t.Error("threat analysis prompt should contain IP")
	}
	if !strings.Contains(prompt, "SQLi") {
		t.Error("threat analysis prompt should contain threat type")
	}
	if !strings.Contains(prompt, "UNION SELECT") {
		t.Error("threat analysis prompt should contain evidence")
	}

	actorPrompt := ai.BuildActorAnalysisPromptExported(actor, []*sentinel.ThreatEvent{threat})
	if !strings.Contains(actorPrompt, "Cloud Provider") {
		t.Error("actor analysis prompt should contain ISP")
	}

	stats := &sentinel.ThreatStats{
		TotalThreats:  100,
		CriticalCount: 5,
		HighCount:     20,
		MediumCount:   45,
		LowCount:      30,
		BlockedCount:  80,
		UniqueIPs:     15,
		TopAttackTypes: []sentinel.AttackTypeStat{
			{Type: "SQLi", Count: 50},
			{Type: "XSS", Count: 30},
		},
	}

	dailyPrompt := ai.BuildDailySummaryPromptExported(stats)
	if !strings.Contains(dailyPrompt, "100") {
		t.Error("daily summary prompt should contain total threats")
	}

	secCtx := &ai.SecurityContext{
		ThreatStats:   stats,
		RecentThreats: []*sentinel.ThreatEvent{threat},
		TopActors:     []*sentinel.ThreatActor{actor},
	}

	nlPrompt := ai.BuildNLQueryPromptExported("show me SQL injections", secCtx)
	if !strings.Contains(nlPrompt, "show me SQL injections") {
		t.Error("NL query prompt should contain the user question")
	}

	wafPrompt := ai.BuildWAFRecommendationsPromptExported([]*sentinel.ThreatEvent{threat})
	if !strings.Contains(wafPrompt, "SQLi") {
		t.Error("WAF recommendations prompt should contain threat type")
	}
}
