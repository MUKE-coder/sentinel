package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// PagerDutyAPI is the Events API v2 endpoint. Overridable for tests.
const PagerDutyAPI = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyProvider sends Sentinel threat events to PagerDuty Events API v2.
// Maps Sentinel severities to PagerDuty severities (critical / error / warning
// / info) and includes the CVSS score in the payload custom_details so SOC
// dashboards can prioritize.
type PagerDutyProvider struct {
	integrationKey string
	minSeverity    sentinel.Severity
	minCVSS        float64
	http           *http.Client
	endpoint       string
}

// NewPagerDutyProvider creates a PagerDuty alert provider. minSeverity is
// optional — empty inherits the dispatcher's threshold. minCVSS is an
// additional floor; 0 disables it.
func NewPagerDutyProvider(cfg sentinel.PagerDutyConfig) *PagerDutyProvider {
	return &PagerDutyProvider{
		integrationKey: cfg.IntegrationKey,
		minSeverity:    cfg.MinSeverity,
		minCVSS:        cfg.MinCVSS,
		http:           &http.Client{Timeout: 10 * time.Second},
		endpoint:       PagerDutyAPI,
	}
}

// Name implements AlertProvider.
func (p *PagerDutyProvider) Name() string { return "pagerduty" }

// Send implements AlertProvider.
func (p *PagerDutyProvider) Send(ctx context.Context, te *sentinel.ThreatEvent) error {
	if p.integrationKey == "" {
		return fmt.Errorf("pagerduty: missing integration key")
	}
	if p.minCVSS > 0 && te.CVSS < p.minCVSS {
		return nil
	}
	if p.minSeverity != "" && !severityAtLeast(te.Severity, p.minSeverity) {
		return nil
	}

	threatType := "Threat"
	if len(te.ThreatTypes) > 0 {
		threatType = te.ThreatTypes[0]
	}

	body := map[string]any{
		"routing_key":  p.integrationKey,
		"event_action": "trigger",
		// Group by IP+type so PagerDuty itself dedups across providers/restarts.
		"dedup_key": fmt.Sprintf("sentinel:%s:%s", te.IP, threatType),
		"payload": map[string]any{
			"summary":   fmt.Sprintf("[Sentinel] %s on %s from %s (CVSS %.1f)", threatType, te.Path, te.IP, te.CVSS),
			"source":    te.IP,
			"severity":  pagerDutySeverity(te.Severity),
			"component": te.Path,
			"class":     threatType,
			"custom_details": map[string]any{
				"threat_id":    te.ID,
				"actor_id":     te.ActorID,
				"user_id":      te.UserID,
				"method":       te.Method,
				"path":         te.Path,
				"status_code":  te.StatusCode,
				"user_agent":   te.UserAgent,
				"country":      te.Country,
				"city":         te.City,
				"confidence":   te.Confidence,
				"cvss_score":   te.CVSS,
				"cvss_vector":  te.CVSSVector,
				"blocked":      te.Blocked,
				"evidence":     te.Evidence,
				"query_params": te.QueryParams,
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pagerduty: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("pagerduty: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("pagerduty: status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func pagerDutySeverity(s sentinel.Severity) string {
	switch s {
	case sentinel.SeverityCritical:
		return "critical"
	case sentinel.SeverityHigh:
		return "error"
	case sentinel.SeverityMedium:
		return "warning"
	default:
		return "info"
	}
}

func severityAtLeast(have, want sentinel.Severity) bool {
	order := map[sentinel.Severity]int{
		sentinel.SeverityLow:      1,
		sentinel.SeverityMedium:   2,
		sentinel.SeverityHigh:     3,
		sentinel.SeverityCritical: 4,
	}
	return order[have] >= order[want]
}
