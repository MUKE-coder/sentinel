package ai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MUKE-coder/sentinel/v2/ai"
	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func TestRedactor_Text(t *testing.T) {
	r := ai.NewRedactor(sentinel.AIRedaction{})
	cases := []struct{ in, mustNotContain, mustContain string }{
		{"contact alice@example.com today", "alice@example.com", "[email]"},
		{"Authorization: Bearer abcdef1234567890", "abcdef1234567890", "Bearer [token]"},
		{"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sflKxwRJSMeKKF2QT4fwpM", "eyJhbGci", "[jwt]"},
		{"password=hunter2&next=/home", "hunter2", "password=[redacted]"},
		{`{"api_key": "sk-live-abc123"}`, "sk-live-abc123", "[redacted]"},
		{"card 4111 1111 1111 1111 exp", "4111", "[card]"},
		{"secret 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "9f86d081", "[secret]"},
	}
	for _, tc := range cases {
		got := r.Text(tc.in)
		if strings.Contains(got, tc.mustNotContain) || !strings.Contains(got, tc.mustContain) {
			t.Errorf("Text(%q) = %q; want %q masked as %q", tc.in, got, tc.mustNotContain, tc.mustContain)
		}
	}

	// Attack fragments and ordinary values survive.
	for _, keep := range []string{"' OR 1=1--", "UNION SELECT password FROM users", "<script>alert(1)</script>", "order 1234567890123456"} {
		if got := r.Text(keep); got != keep {
			t.Errorf("Text(%q) = %q; want it unchanged", keep, got)
		}
	}

	if got := ai.NewRedactor(sentinel.AIRedaction{DisableScrubbing: true}).Text("alice@example.com"); got != "alice@example.com" {
		t.Errorf("DisableScrubbing should pass text through, got %q", got)
	}
}

func TestRedactor_IP(t *testing.T) {
	r := ai.NewRedactor(sentinel.AIRedaction{})
	for in, want := range map[string]string{
		"203.0.113.77":        "203.0.113.x",
		"::ffff:203.0.113.77": "203.0.113.x",
		"2001:db8:1:2::77":    "2001:db8:1::/48",
		"not-an-ip":           "[ip]",
	} {
		if got := r.IP(in); got != want {
			t.Errorf("IP(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ai.NewRedactor(sentinel.AIRedaction{SendFullIPs: true}).IP("203.0.113.77"); got != "203.0.113.77" {
		t.Errorf("SendFullIPs should keep the address, got %q", got)
	}
}

func TestRedactor_QueryAndBody(t *testing.T) {
	r := ai.NewRedactor(sentinel.AIRedaction{})
	if got := r.Query("q=hello&email=alice@example.com"); got != "email=[redacted]&q=[redacted]" {
		t.Errorf("Query masks values and keeps names: got %q", got)
	}
	if got := r.Body(`{"password":"hunter2"}`); !strings.HasPrefix(got, "[omitted:") {
		t.Errorf("Body should be omitted by default, got %q", got)
	}

	send := ai.NewRedactor(sentinel.AIRedaction{SendPayloads: true})
	if got := send.Query("q=hello&email=alice@example.com"); !strings.Contains(got, "q=hello") || strings.Contains(got, "alice@example.com") {
		t.Errorf("SendPayloads keeps the query but still scrubs it: got %q", got)
	}
	if got := send.Body(`{"password":"hunter2","item":"book"}`); strings.Contains(got, "hunter2") || !strings.Contains(got, "book") {
		t.Errorf("SendPayloads keeps the body but still scrubs it: got %q", got)
	}
}

// capturingClaude is a fake Anthropic endpoint that records every request
// body — exactly what would have left the process.
type capturingClaude struct {
	mu     sync.Mutex
	bodies []string
}

func (c *capturingClaude) server(t *testing.T, response string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, string(b))
		c.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]string{{"type": "text", "text": response}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (c *capturingClaude) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.bodies, "\n")
}

func piiThreat() *sentinel.ThreatEvent {
	return &sentinel.ThreatEvent{
		ID:          "t-pii",
		Timestamp:   time.Now(),
		IP:          "203.0.113.77",
		UserID:      "user-8841",
		Method:      "POST",
		Path:        "/api/users/alice@example.com/orders",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityHigh,
		QueryParams: "email=alice@example.com&card=4111111111111111&q=1' UNION SELECT password FROM users--",
		BodySnippet: `{"name":"Alice Smith","password":"hunter2","ssn":"078-05-1120"}`,
		UserAgent:   "Mozilla/5.0 (Bearer abcdef1234567890)",
		City:        "Springfield",
		Evidence: []sentinel.Evidence{
			{Pattern: "SQLi_Basic", Matched: "UNION SELECT password FROM users", Location: "query", Parameter: "q"},
		},
	}
}

// TestEgress_DefaultRedaction is the review's "AI data-egress test": drive
// every AI feature with a threat full of personal data through a real Claude
// provider pointed at a fake endpoint, and inspect exactly what was sent.
func TestEgress_DefaultRedaction(t *testing.T) {
	capture := &capturingClaude{}
	srv := capture.server(t, `{"summary":"ok"}`)
	p := ai.NewRedactingProvider(ai.NewTestClaudeProvider("k", "m", srv.URL), sentinel.AIRedaction{})

	threat := piiThreat()
	actor := &sentinel.ThreatActor{IP: "203.0.113.77", City: "Springfield", TargetedRoutes: []string{"POST /api/users/alice@example.com/orders"}}
	ctx := context.Background()

	p.AnalyzeThreat(ctx, threat, actor)
	p.AnalyzeActor(ctx, actor, []*sentinel.ThreatEvent{threat})
	p.NaturalLanguageQuery(ctx, "what happened?", &ai.SecurityContext{
		RecentThreats: []*sentinel.ThreatEvent{threat},
		TopActors:     []*sentinel.ThreatActor{actor},
	})
	p.RecommendWAFRules(ctx, []*sentinel.ThreatEvent{threat})

	sent := capture.all()
	if len(capture.bodies) != 4 {
		t.Fatalf("expected 4 provider calls, got %d", len(capture.bodies))
	}
	for _, leaked := range []string{
		"203.0.113.77", "alice@example.com", "4111111111111111", "hunter2", "078-05-1120",
		"Alice Smith", "abcdef1234567890", "Springfield", "user-8841",
	} {
		if strings.Contains(sent, leaked) {
			t.Errorf("%q left the process", leaked)
		}
	}
	for _, kept := range []string{"UNION SELECT password FROM users", "203.0.113.x", "SQLi"} {
		if !strings.Contains(sent, kept) {
			t.Errorf("expected %q in what was sent — the analysis needs it", kept)
		}
	}

	// The caller's data must not be modified by redaction.
	if threat.IP != "203.0.113.77" || threat.BodySnippet == "" {
		t.Error("redaction modified the caller's threat event")
	}
}

func TestEgress_SendPayloadsStillScrubs(t *testing.T) {
	capture := &capturingClaude{}
	srv := capture.server(t, `{"summary":"ok"}`)
	p := ai.NewRedactingProvider(ai.NewTestClaudeProvider("k", "m", srv.URL), sentinel.AIRedaction{SendPayloads: true, SendFullIPs: true})

	p.AnalyzeThreat(context.Background(), piiThreat(), nil)
	sent := capture.all()
	if !strings.Contains(sent, "203.0.113.77") || !strings.Contains(sent, "Alice Smith") {
		t.Error("SendPayloads + SendFullIPs should send the address and the body")
	}
	for _, leaked := range []string{"hunter2", "alice@example.com", "4111111111111111"} {
		if strings.Contains(sent, leaked) {
			t.Errorf("%q left the process despite scrubbing", leaked)
		}
	}
}
