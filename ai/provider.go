// Package ai provides optional AI-powered security analysis.
// Supports Anthropic Claude, OpenAI GPT, and Google Gemini.
package ai

import (
	"context"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// Provider defines the interface for AI-powered security analysis.
type Provider interface {
	// AnalyzeThreat generates a plain-English analysis of a threat event.
	AnalyzeThreat(ctx context.Context, threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) (*ThreatAnalysis, error)

	// AnalyzeActor generates an assessment of a threat actor's behavior and intent.
	AnalyzeActor(ctx context.Context, actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) (*ActorAnalysis, error)

	// GenerateDailySummary produces a daily security summary from threat statistics.
	GenerateDailySummary(ctx context.Context, stats *sentinel.ThreatStats) (*DailySummary, error)

	// NaturalLanguageQuery answers a security question using live data.
	NaturalLanguageQuery(ctx context.Context, query string, secCtx *SecurityContext) (*QueryResult, error)

	// RecommendWAFRules suggests WAF rules based on recent attack patterns.
	RecommendWAFRules(ctx context.Context, recentThreats []*sentinel.ThreatEvent) ([]*WAFRecommendation, error)
}

// ThreatAnalysis is the AI-generated analysis of a threat event.
type ThreatAnalysis struct {
	Summary         string   `json:"summary"`
	Explanation     string   `json:"explanation"`
	SeverityAssess  string   `json:"severity_assessment"`
	Succeeded       bool     `json:"succeeded"`
	Recommendations []string `json:"recommendations"`
	ThreatCategory  string   `json:"threat_category"`
	Confidence      int      `json:"confidence"`
}

// ActorAnalysis is the AI-generated analysis of a threat actor.
type ActorAnalysis struct {
	Summary        string   `json:"summary"`
	Intent         string   `json:"intent"`
	Sophistication string   `json:"sophistication"`
	RiskLevel      string   `json:"risk_level"`
	Recommendations []string `json:"recommendations"`
	RelatedGroups  []string `json:"related_groups,omitempty"`
}

// DailySummary is the AI-generated daily security summary.
type DailySummary struct {
	Summary         string   `json:"summary"`
	Highlights      []string `json:"highlights"`
	TopThreats      []string `json:"top_threats"`
	TrendAnalysis   string   `json:"trend_analysis"`
	Recommendations []string `json:"recommendations"`
	OverallStatus   string   `json:"overall_status"`
}

// QueryResult is the AI response to a natural language security query.
type QueryResult struct {
	Answer      string   `json:"answer"`
	Sources     []string `json:"sources,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
}

// WAFRecommendation is a suggested WAF rule from AI analysis.
type WAFRecommendation struct {
	RuleID    string   `json:"rule_id"`
	Name      string   `json:"name"`
	Pattern   string   `json:"pattern"`
	Severity  string   `json:"severity"`
	Reason    string   `json:"reason"`
	AppliesTo []string `json:"applies_to"`
}

// SecurityContext provides context for natural language queries.
type SecurityContext struct {
	RecentThreats []*sentinel.ThreatEvent `json:"recent_threats,omitempty"`
	TopActors     []*sentinel.ThreatActor `json:"top_actors,omitempty"`
	ThreatStats   *sentinel.ThreatStats   `json:"threat_stats,omitempty"`
	Score         *sentinel.SecurityScore  `json:"score,omitempty"`
}

// CachedProvider wraps a Provider with response caching.
type CachedProvider struct {
	provider Provider
	cache    map[string]*cacheEntry
	mu       sync.RWMutex
	ttl      time.Duration
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

// NewCachedProvider creates a caching wrapper around any Provider.
func NewCachedProvider(provider Provider, ttl time.Duration) *CachedProvider {
	if ttl == 0 {
		ttl = 1 * time.Hour
	}
	return &CachedProvider{
		provider: provider,
		cache:    make(map[string]*cacheEntry),
		ttl:      ttl,
	}
}

func (c *CachedProvider) get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

func (c *CachedProvider) set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = &cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// AnalyzeThreat caches by threat ID.
func (c *CachedProvider) AnalyzeThreat(ctx context.Context, threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) (*ThreatAnalysis, error) {
	key := "threat:" + threat.ID
	if v, ok := c.get(key); ok {
		return v.(*ThreatAnalysis), nil
	}
	result, err := c.provider.AnalyzeThreat(ctx, threat, actor)
	if err != nil {
		return nil, err
	}
	c.set(key, result)
	return result, nil
}

// AnalyzeActor caches by actor IP.
func (c *CachedProvider) AnalyzeActor(ctx context.Context, actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) (*ActorAnalysis, error) {
	key := "actor:" + actor.IP
	if v, ok := c.get(key); ok {
		return v.(*ActorAnalysis), nil
	}
	result, err := c.provider.AnalyzeActor(ctx, actor, recentEvents)
	if err != nil {
		return nil, err
	}
	c.set(key, result)
	return result, nil
}

// GenerateDailySummary caches by date.
func (c *CachedProvider) GenerateDailySummary(ctx context.Context, stats *sentinel.ThreatStats) (*DailySummary, error) {
	key := "daily:" + time.Now().Format("2006-01-02")
	if v, ok := c.get(key); ok {
		return v.(*DailySummary), nil
	}
	result, err := c.provider.GenerateDailySummary(ctx, stats)
	if err != nil {
		return nil, err
	}
	c.set(key, result)
	return result, nil
}

// NaturalLanguageQuery is not cached (each query is unique).
func (c *CachedProvider) NaturalLanguageQuery(ctx context.Context, query string, secCtx *SecurityContext) (*QueryResult, error) {
	return c.provider.NaturalLanguageQuery(ctx, query, secCtx)
}

// RecommendWAFRules caches by date.
func (c *CachedProvider) RecommendWAFRules(ctx context.Context, recentThreats []*sentinel.ThreatEvent) ([]*WAFRecommendation, error) {
	key := "waf-rec:" + time.Now().Format("2006-01-02")
	if v, ok := c.get(key); ok {
		return v.([]*WAFRecommendation), nil
	}
	result, err := c.provider.RecommendWAFRules(ctx, recentThreats)
	if err != nil {
		return nil, err
	}
	c.set(key, result)
	return result, nil
}

// NewProvider creates the appropriate Provider based on configuration.
// Returns nil if AI is not configured.
func NewProvider(config *sentinel.AIConfig) Provider {
	if config == nil || config.APIKey == "" {
		return nil
	}

	var provider Provider
	switch config.Provider {
	case sentinel.Claude:
		model := config.Model
		if model == "" {
			model = "claude-sonnet-4-20250514"
		}
		provider = NewClaudeProvider(config.APIKey, model)
	case sentinel.OpenAI:
		model := config.Model
		if model == "" {
			model = "gpt-4o"
		}
		provider = NewOpenAIProvider(config.APIKey, model)
	case sentinel.Gemini:
		model := config.Model
		if model == "" {
			model = "gemini-2.0-flash"
		}
		provider = NewGeminiProvider(config.APIKey, model)
	default:
		return nil
	}

	return NewCachedProvider(provider, 1*time.Hour)
}
