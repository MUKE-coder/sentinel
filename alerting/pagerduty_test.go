package alerting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

func TestPagerDutyProvider_PayloadAndSeverity(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	p := NewPagerDutyProvider(sentinel.PagerDutyConfig{IntegrationKey: "rk"})
	p.endpoint = srv.URL

	te := &sentinel.ThreatEvent{
		ID:          "abc",
		IP:          "1.2.3.4",
		Method:      "POST",
		Path:        "/api/login",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityCritical,
		CVSS:        9.8,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := p.Send(context.Background(), te); err != nil {
		t.Fatalf("send: %v", err)
	}

	if got := received["routing_key"]; got != "rk" {
		t.Errorf("routing_key = %v", got)
	}
	payload, ok := received["payload"].(map[string]any)
	if !ok {
		t.Fatalf("missing payload object")
	}
	if got := payload["severity"]; got != "critical" {
		t.Errorf("severity = %v, want critical", got)
	}
	details := payload["custom_details"].(map[string]any)
	if details["cvss_score"].(float64) != 9.8 {
		t.Errorf("cvss_score = %v", details["cvss_score"])
	}
}

func TestPagerDutyProvider_MinCVSSFilters(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	p := NewPagerDutyProvider(sentinel.PagerDutyConfig{IntegrationKey: "rk", MinCVSS: 9.0})
	p.endpoint = srv.URL

	te := &sentinel.ThreatEvent{
		ID:       "xyz",
		IP:       "1.2.3.4",
		Severity: sentinel.SeverityHigh,
		CVSS:     7.5,
	}
	if err := p.Send(context.Background(), te); err != nil {
		t.Fatalf("send: %v", err)
	}
	if called {
		t.Fatal("PagerDuty should not be called below MinCVSS threshold")
	}
}
