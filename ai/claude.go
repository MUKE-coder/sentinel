package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// ClaudeProvider implements Provider using the Anthropic Messages API.
type ClaudeProvider struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

// NewClaudeProvider creates a new Claude AI provider.
func NewClaudeProvider(apiKey, model string) *ClaudeProvider {
	return &ClaudeProvider{
		apiKey:  apiKey,
		model:   model,
		baseURL: "https://api.anthropic.com/v1/messages",
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

type claudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []claudeMessage `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *ClaudeProvider) call(ctx context.Context, prompt string) (string, error) {
	reqBody := claudeRequest{
		Model:     c.model,
		MaxTokens: 2048,
		Messages: []claudeMessage{
			{Role: "user", Content: prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if claudeResp.Error != nil {
		return "", fmt.Errorf("API error: %s", claudeResp.Error.Message)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return cleanJSONResponse(claudeResp.Content[0].Text), nil
}

func (c *ClaudeProvider) AnalyzeThreat(ctx context.Context, threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) (*ThreatAnalysis, error) {
	prompt := buildThreatAnalysisPrompt(threat, actor)
	raw, err := c.call(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var result ThreatAnalysis
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (c *ClaudeProvider) AnalyzeActor(ctx context.Context, actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) (*ActorAnalysis, error) {
	prompt := buildActorAnalysisPrompt(actor, recentEvents)
	raw, err := c.call(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var result ActorAnalysis
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (c *ClaudeProvider) GenerateDailySummary(ctx context.Context, stats *sentinel.ThreatStats) (*DailySummary, error) {
	prompt := buildDailySummaryPrompt(stats)
	raw, err := c.call(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var result DailySummary
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (c *ClaudeProvider) NaturalLanguageQuery(ctx context.Context, query string, secCtx *SecurityContext) (*QueryResult, error) {
	prompt := buildNLQueryPrompt(query, secCtx)
	raw, err := c.call(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (c *ClaudeProvider) RecommendWAFRules(ctx context.Context, recentThreats []*sentinel.ThreatEvent) ([]*WAFRecommendation, error) {
	prompt := buildWAFRecommendationsPrompt(recentThreats)
	raw, err := c.call(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var result []*WAFRecommendation
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return result, nil
}

// cleanJSONResponse strips markdown code fences if the AI wrapped the response.
func cleanJSONResponse(s string) string {
	s = strings.TrimSpace(s)
	// Remove ```json ... ``` wrapping
	if strings.HasPrefix(s, "```") {
		lines := strings.SplitN(s, "\n", 2)
		if len(lines) == 2 {
			s = lines[1]
		}
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	}
	return strings.TrimSpace(s)
}
