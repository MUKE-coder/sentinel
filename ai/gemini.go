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

// GeminiProvider implements Provider using the Google Gemini API.
type GeminiProvider struct {
	apiKey string
	model  string
	client *http.Client
}

// NewGeminiProvider creates a new Google Gemini provider.
func NewGeminiProvider(apiKey, model string) *GeminiProvider {
	return &GeminiProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	GenerationConfig geminiGenerationConfig `json:"generationConfig"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens"`
	Temperature     float64 `json:"temperature"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (g *GeminiProvider) call(ctx context.Context, prompt string) (string, error) {
	reqBody := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
		GenerationConfig: geminiGenerationConfig{
			MaxOutputTokens: 2048,
			Temperature:     0.3,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", g.model, g.apiKey)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
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

	var geminiResp geminiResponse
	if err := json.Unmarshal(respBody, &geminiResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if geminiResp.Error != nil {
		return "", fmt.Errorf("API error: %s", geminiResp.Error.Message)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return cleanJSONResponse(geminiResp.Candidates[0].Content.Parts[0].Text), nil
}

func (g *GeminiProvider) AnalyzeThreat(ctx context.Context, threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) (*ThreatAnalysis, error) {
	raw, err := g.call(ctx, buildThreatAnalysisPrompt(threat, actor))
	if err != nil {
		return nil, err
	}
	var result ThreatAnalysis
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (g *GeminiProvider) AnalyzeActor(ctx context.Context, actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) (*ActorAnalysis, error) {
	raw, err := g.call(ctx, buildActorAnalysisPrompt(actor, recentEvents))
	if err != nil {
		return nil, err
	}
	var result ActorAnalysis
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (g *GeminiProvider) GenerateDailySummary(ctx context.Context, stats *sentinel.ThreatStats) (*DailySummary, error) {
	raw, err := g.call(ctx, buildDailySummaryPrompt(stats))
	if err != nil {
		return nil, err
	}
	var result DailySummary
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (g *GeminiProvider) NaturalLanguageQuery(ctx context.Context, query string, secCtx *SecurityContext) (*QueryResult, error) {
	raw, err := g.call(ctx, buildNLQueryPrompt(query, secCtx))
	if err != nil {
		return nil, err
	}
	var result QueryResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return &result, nil
}

func (g *GeminiProvider) RecommendWAFRules(ctx context.Context, recentThreats []*sentinel.ThreatEvent) ([]*WAFRecommendation, error) {
	raw, err := g.call(ctx, buildWAFRecommendationsPrompt(recentThreats))
	if err != nil {
		return nil, err
	}
	var result []*WAFRecommendation
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return result, nil
}
