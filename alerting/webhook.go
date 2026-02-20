package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// WebhookProvider sends alerts to a generic HTTP webhook.
type WebhookProvider struct {
	config sentinel.WebhookConfig
	client *http.Client
}

// NewWebhookProvider creates a new webhook alert provider.
func NewWebhookProvider(config sentinel.WebhookConfig) *WebhookProvider {
	return &WebhookProvider{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "webhook".
func (w *WebhookProvider) Name() string {
	return "webhook"
}

// Send sends a threat alert to the webhook URL as JSON.
func (w *WebhookProvider) Send(ctx context.Context, te *sentinel.ThreatEvent) error {
	if w.config.URL == "" {
		return fmt.Errorf("webhook: URL not configured")
	}

	payload, err := json.Marshal(map[string]interface{}{
		"event":        "threat_detected",
		"threat_id":    te.ID,
		"timestamp":    te.Timestamp.UTC().Format(time.RFC3339),
		"ip":           te.IP,
		"method":       te.Method,
		"path":         te.Path,
		"threat_types": te.ThreatTypes,
		"severity":     te.Severity,
		"confidence":   te.Confidence,
		"blocked":      te.Blocked,
		"country":      te.Country,
		"evidence":     te.Evidence,
	})
	if err != nil {
		return fmt.Errorf("webhook: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.config.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: received status %d", resp.StatusCode)
	}

	return nil
}
