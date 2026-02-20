package ai

import (
	sentinel "github.com/MUKE-coder/sentinel/core"
)

// Exported test helpers for black-box testing.

// CleanJSONResponse exports cleanJSONResponse for testing.
func CleanJSONResponse(s string) string {
	return cleanJSONResponse(s)
}

// BuildThreatAnalysisPromptExported exports the prompt builder for testing.
func BuildThreatAnalysisPromptExported(threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) string {
	return buildThreatAnalysisPrompt(threat, actor)
}

// BuildActorAnalysisPromptExported exports the prompt builder for testing.
func BuildActorAnalysisPromptExported(actor *sentinel.ThreatActor, events []*sentinel.ThreatEvent) string {
	return buildActorAnalysisPrompt(actor, events)
}

// BuildDailySummaryPromptExported exports the prompt builder for testing.
func BuildDailySummaryPromptExported(stats *sentinel.ThreatStats) string {
	return buildDailySummaryPrompt(stats)
}

// BuildNLQueryPromptExported exports the prompt builder for testing.
func BuildNLQueryPromptExported(query string, secCtx *SecurityContext) string {
	return buildNLQueryPrompt(query, secCtx)
}

// BuildWAFRecommendationsPromptExported exports the prompt builder for testing.
func BuildWAFRecommendationsPromptExported(threats []*sentinel.ThreatEvent) string {
	return buildWAFRecommendationsPrompt(threats)
}

// NewTestClaudeProvider creates a Claude provider that uses a custom base URL for testing.
func NewTestClaudeProvider(apiKey, model, baseURL string) *ClaudeProvider {
	p := NewClaudeProvider(apiKey, model)
	p.baseURL = baseURL
	return p
}
