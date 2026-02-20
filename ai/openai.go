package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// OpenAIProvider implements Provider using the OpenAI Chat Completions API.
type OpenAIProvider struct {
	apiKey string
	model  string
	client *http.Client
}

// NewOpenAIProvider creates a new OpenAI provider.
func NewOpenAIProvider(apiKey, model string) *OpenAIProvider {
	return &OpenAIProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

type openaiRequest struct {
	Model       string           `json:"model"`
	Messages    []openaiMessage  `json:"messages"`
	MaxTokens   int              `json:"max_tokens"`
	Temperature float64          `json:"temperature"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (o *OpenAIProvider) call(ctx context.Context, prompt string) (string, error) {
	reqBody := openaiRequest{
		Model: o.model,
		Messages: []openaiMessage{
			{Role: "system", Content: "You are a cybersecurity expert. Always respond with valid JSON only, no markdown."},
			{Role: "user", Content: prompt},
		},
		MaxTokens:   2048,
		Temperature: 0.3,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(req)
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

	var openaiResp openaiResponse
	if err := json.Unmarshal(respBody, &openaiResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if openaiResp.Error != nil {
		return "", fmt.Errorf("API error: %s", openaiResp.Error.Message)
	}

	if len(openaiResp.Choices) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return cleanJSONResponse(openaiResp.Choices[0].Message.Content), nil
}

func (o *OpenAIProvider) AnalyzeThreat(ctx context.Context, threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) (*ThreatAnalysis, error) {
	raw, err := o.call(ctx, buildThreatAnalysisPrompt(threat, actor))
	if err != nil {
		return nil, err
	}
	var result ThreatAnalysis
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (o *OpenAIProvider) AnalyzeActor(ctx context.Context, actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) (*ActorAnalysis, error) {
	raw, err := o.call(ctx, buildActorAnalysisPrompt(actor, recentEvents))
	if err != nil {
		return nil, err
	}
	var result ActorAnalysis
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (o *OpenAIProvider) GenerateDailySummary(ctx context.Context, stats *sentinel.ThreatStats) (*DailySummary, error) {
	raw, err := o.call(ctx, buildDailySummaryPrompt(stats))
	if err != nil {
		return nil, err
	}
	var result DailySummary
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (o *OpenAIProvider) NaturalLanguageQuery(ctx context.Context, query string, secCtx *SecurityContext) (*QueryResult, error) {
	raw, err := o.call(ctx, buildNLQueryPrompt(query, secCtx))
	if err != nil {
		return nil, err
	}
	var result QueryResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (o *OpenAIProvider) RecommendWAFRules(ctx context.Context, recentThreats []*sentinel.ThreatEvent) ([]*WAFRecommendation, error) {
	raw, err := o.call(ctx, buildWAFRecommendationsPrompt(recentThreats))
	if err != nil {
		return nil, err
	}
	var result []*WAFRecommendation
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return result, nil
}
