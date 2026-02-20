package alerting_test

import (
	"context"
	"sync"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/alerting"
	"github.com/MUKE-coder/sentinel/pipeline"
)

// mockProvider is a test alert provider that records sent alerts.
type mockProvider struct {
	name    string
	sent    []*sentinel.ThreatEvent
	mu      sync.Mutex
	failN   int // fail this many times before succeeding
	callNum int
}

func (m *mockProvider) Name() string { return m.name }

func (m *mockProvider) Send(ctx context.Context, te *sentinel.ThreatEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callNum++
	if m.callNum <= m.failN {
		return context.DeadlineExceeded
	}
	m.sent = append(m.sent, te)
	return nil
}

func (m *mockProvider) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func TestDispatcher_SendsToProviders(t *testing.T) {
	dispatcher := alerting.NewDispatcher(sentinel.AlertConfig{
		MinSeverity: sentinel.SeverityHigh,
	})

	mock := &mockProvider{name: "test"}
	dispatcher.AddProvider(mock)

	te := &sentinel.ThreatEvent{
		ID:          "t1",
		Timestamp:   time.Now(),
		IP:          "1.2.3.4",
		Method:      "GET",
		Path:        "/api/users",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityCritical,
		Blocked:     true,
	}

	event := pipeline.Event{
		Type:      pipeline.EventThreat,
		Timestamp: time.Now(),
		Payload:   te,
	}

	err := dispatcher.Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	if mock.sentCount() != 1 {
		t.Errorf("expected 1 alert sent, got %d", mock.sentCount())
	}
}

func TestDispatcher_SeverityThreshold(t *testing.T) {
	dispatcher := alerting.NewDispatcher(sentinel.AlertConfig{
		MinSeverity: sentinel.SeverityHigh,
	})

	mock := &mockProvider{name: "test"}
	dispatcher.AddProvider(mock)

	// Low severity — should NOT trigger alert
	te := &sentinel.ThreatEvent{
		ID:          "t2",
		Timestamp:   time.Now(),
		IP:          "1.2.3.5",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityLow,
	}

	event := pipeline.Event{
		Type:      pipeline.EventThreat,
		Timestamp: time.Now(),
		Payload:   te,
	}

	dispatcher.Handle(context.Background(), event)

	if mock.sentCount() != 0 {
		t.Errorf("expected no alert for low severity, got %d", mock.sentCount())
	}
}

func TestDispatcher_Deduplication(t *testing.T) {
	dispatcher := alerting.NewDispatcher(sentinel.AlertConfig{
		MinSeverity: sentinel.SeverityHigh,
	})

	mock := &mockProvider{name: "test"}
	dispatcher.AddProvider(mock)

	te := &sentinel.ThreatEvent{
		ID:          "t3",
		Timestamp:   time.Now(),
		IP:          "5.6.7.8",
		ThreatTypes: []string{"XSS"},
		Severity:    sentinel.SeverityCritical,
	}

	event := pipeline.Event{
		Type:      pipeline.EventThreat,
		Timestamp: time.Now(),
		Payload:   te,
	}

	// First call — should send
	dispatcher.Handle(context.Background(), event)
	// Second call — same IP + type, should be deduped
	te2 := &sentinel.ThreatEvent{
		ID:          "t4",
		Timestamp:   time.Now(),
		IP:          "5.6.7.8",
		ThreatTypes: []string{"XSS"},
		Severity:    sentinel.SeverityCritical,
	}
	event2 := pipeline.Event{
		Type:      pipeline.EventThreat,
		Timestamp: time.Now(),
		Payload:   te2,
	}
	dispatcher.Handle(context.Background(), event2)

	if mock.sentCount() != 1 {
		t.Errorf("expected 1 alert (dedup should prevent second), got %d", mock.sentCount())
	}
}

func TestDispatcher_IgnoresNonThreatEvents(t *testing.T) {
	dispatcher := alerting.NewDispatcher(sentinel.AlertConfig{
		MinSeverity: sentinel.SeverityLow,
	})

	mock := &mockProvider{name: "test"}
	dispatcher.AddProvider(mock)

	event := pipeline.Event{
		Type:      pipeline.EventPerformance,
		Timestamp: time.Now(),
		Payload:   &sentinel.PerformanceMetric{},
	}

	dispatcher.Handle(context.Background(), event)

	if mock.sentCount() != 0 {
		t.Errorf("expected no alert for non-threat event, got %d", mock.sentCount())
	}
}

func TestDispatcher_AlertHistory(t *testing.T) {
	dispatcher := alerting.NewDispatcher(sentinel.AlertConfig{
		MinSeverity: sentinel.SeverityHigh,
	})

	mock := &mockProvider{name: "test-channel"}
	dispatcher.AddProvider(mock)

	te := &sentinel.ThreatEvent{
		ID:          "t5",
		Timestamp:   time.Now(),
		IP:          "9.8.7.6",
		ThreatTypes: []string{"SQLi"},
		Severity:    sentinel.SeverityCritical,
	}

	event := pipeline.Event{
		Type:      pipeline.EventThreat,
		Timestamp: time.Now(),
		Payload:   te,
	}

	dispatcher.Handle(context.Background(), event)

	history := dispatcher.GetHistory()
	if len(history) == 0 {
		t.Fatal("expected at least one history entry")
	}

	h := history[0]
	if h.Channel != "test-channel" {
		t.Errorf("expected channel 'test-channel', got '%s'", h.Channel)
	}
	if !h.Success {
		t.Error("expected success=true")
	}
	if h.ThreatID != "t5" {
		t.Errorf("expected threat_id 't5', got '%s'", h.ThreatID)
	}
}

func TestDispatcher_MultipleProviders(t *testing.T) {
	dispatcher := alerting.NewDispatcher(sentinel.AlertConfig{
		MinSeverity: sentinel.SeverityHigh,
	})

	mock1 := &mockProvider{name: "slack"}
	mock2 := &mockProvider{name: "webhook"}
	dispatcher.AddProvider(mock1)
	dispatcher.AddProvider(mock2)

	te := &sentinel.ThreatEvent{
		ID:          "t6",
		Timestamp:   time.Now(),
		IP:          "11.22.33.44",
		ThreatTypes: []string{"SSRF"},
		Severity:    sentinel.SeverityHigh,
	}

	event := pipeline.Event{
		Type:      pipeline.EventThreat,
		Timestamp: time.Now(),
		Payload:   te,
	}

	dispatcher.Handle(context.Background(), event)

	if mock1.sentCount() != 1 {
		t.Errorf("expected 1 alert to slack, got %d", mock1.sentCount())
	}
	if mock2.sentCount() != 1 {
		t.Errorf("expected 1 alert to webhook, got %d", mock2.sentCount())
	}

	if dispatcher.ProviderCount() != 2 {
		t.Errorf("expected 2 providers, got %d", dispatcher.ProviderCount())
	}
}
