package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// SlackProvider sends alerts to a Slack webhook.
type SlackProvider struct {
	webhookURL string
	client     *http.Client
}

// NewSlackProvider creates a new Slack alert provider.
func NewSlackProvider(webhookURL string) *SlackProvider {
	return &SlackProvider{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "slack".
func (s *SlackProvider) Name() string {
	return "slack"
}

// Send sends a threat alert to Slack.
func (s *SlackProvider) Send(ctx context.Context, te *sentinel.ThreatEvent) error {
	message := formatSlackMessage(te)

	payload, err := json.Marshal(map[string]interface{}{
		"text":   message,
		"blocks": buildSlackBlocks(te),
	})
	if err != nil {
		return fmt.Errorf("slack: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: received status %d", resp.StatusCode)
	}

	return nil
}

func formatSlackMessage(te *sentinel.ThreatEvent) string {
	emoji := severityEmoji(te.Severity)
	types := strings.Join(te.ThreatTypes, ", ")
	return fmt.Sprintf("%s %s Threat Detected — %s from %s on %s",
		emoji, te.Severity, types, te.IP, te.Path)
}

func buildSlackBlocks(te *sentinel.ThreatEvent) []map[string]interface{} {
	emoji := severityEmoji(te.Severity)
	types := strings.Join(te.ThreatTypes, ", ")

	location := te.IP
	if te.Country != "" {
		location = fmt.Sprintf("%s (%s)", te.IP, te.Country)
	}

	blockedStr := "No"
	if te.Blocked {
		blockedStr = "Yes"
	}

	headerText := fmt.Sprintf("%s *%s Threat Detected*", emoji, te.Severity)
	detailsText := fmt.Sprintf(
		"*Type:* %s\n*IP:* %s\n*Route:* %s %s\n*Blocked:* %s\n*Time:* %s",
		types,
		location,
		te.Method, te.Path,
		blockedStr,
		te.Timestamp.UTC().Format(time.RFC3339),
	)

	return []map[string]interface{}{
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": headerText,
			},
		},
		{
			"type": "divider",
		},
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": detailsText,
			},
		},
	}
}

func severityEmoji(sev sentinel.Severity) string {
	switch sev {
	case sentinel.SeverityCritical:
		return "\xf0\x9f\x9a\xa8" // red rotating light
	case sentinel.SeverityHigh:
		return "\xe2\x9a\xa0\xef\xb8\x8f" // warning
	case sentinel.SeverityMedium:
		return "\xf0\x9f\x94\xb6" // diamond
	default:
		return "\xe2\x84\xb9\xef\xb8\x8f" // info
	}
}
