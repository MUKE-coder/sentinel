package ai

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// ErrBudgetExhausted is returned when the AI provider's call or token budget
// for the current 24-hour window has been spent. Callers should fall back to
// non-AI paths (cached summaries, plain text) rather than crashing.
var ErrBudgetExhausted = errors.New("ai: daily budget exhausted")

// BudgetedProvider wraps a Provider with a per-day call cap. It exists to
// keep a runaway natural-language-query loop or a misbehaving cron job from
// burning a noticeable share of someone's monthly LLM bill in one afternoon.
// The counter resets at midnight UTC.
//
// Set MaxCallsPerDay to 0 to disable the cap (the default when unset).
type BudgetedProvider struct {
	provider       Provider
	maxCallsPerDay int64

	mu        sync.Mutex
	windowDay int64
	calls     atomic.Int64
}

// NewBudgetedProvider wraps a Provider with a daily call cap. If
// maxCallsPerDay <= 0 the cap is disabled and calls pass through directly.
func NewBudgetedProvider(p Provider, maxCallsPerDay int64) *BudgetedProvider {
	return &BudgetedProvider{
		provider:       p,
		maxCallsPerDay: maxCallsPerDay,
		windowDay:      currentDay(),
	}
}

func currentDay() int64 {
	return time.Now().UTC().Truncate(24 * time.Hour).Unix()
}

// Allow reports whether one more call is permitted and reserves it on success.
// Resets the counter at the UTC midnight boundary.
func (b *BudgetedProvider) Allow() bool {
	if b.maxCallsPerDay <= 0 {
		return true
	}
	b.mu.Lock()
	day := currentDay()
	if day != b.windowDay {
		b.windowDay = day
		b.calls.Store(0)
	}
	b.mu.Unlock()

	if b.calls.Add(1) > b.maxCallsPerDay {
		return false
	}
	return true
}

// CallsToday returns the current call count for the active 24-hour window.
func (b *BudgetedProvider) CallsToday() int64 {
	return b.calls.Load()
}

// AnalyzeThreat enforces the budget then delegates.
func (b *BudgetedProvider) AnalyzeThreat(ctx context.Context, threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) (*ThreatAnalysis, error) {
	if !b.Allow() {
		return nil, ErrBudgetExhausted
	}
	return b.provider.AnalyzeThreat(ctx, threat, actor)
}

// AnalyzeActor enforces the budget then delegates.
func (b *BudgetedProvider) AnalyzeActor(ctx context.Context, actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) (*ActorAnalysis, error) {
	if !b.Allow() {
		return nil, ErrBudgetExhausted
	}
	return b.provider.AnalyzeActor(ctx, actor, recentEvents)
}

// GenerateDailySummary enforces the budget then delegates.
func (b *BudgetedProvider) GenerateDailySummary(ctx context.Context, stats *sentinel.ThreatStats) (*DailySummary, error) {
	if !b.Allow() {
		return nil, ErrBudgetExhausted
	}
	return b.provider.GenerateDailySummary(ctx, stats)
}

// NaturalLanguageQuery enforces the budget then delegates.
func (b *BudgetedProvider) NaturalLanguageQuery(ctx context.Context, query string, secCtx *SecurityContext) (*QueryResult, error) {
	if !b.Allow() {
		return nil, ErrBudgetExhausted
	}
	return b.provider.NaturalLanguageQuery(ctx, query, secCtx)
}

// RecommendWAFRules enforces the budget then delegates.
func (b *BudgetedProvider) RecommendWAFRules(ctx context.Context, recentThreats []*sentinel.ThreatEvent) ([]*WAFRecommendation, error) {
	if !b.Allow() {
		return nil, ErrBudgetExhausted
	}
	return b.provider.RecommendWAFRules(ctx, recentThreats)
}
