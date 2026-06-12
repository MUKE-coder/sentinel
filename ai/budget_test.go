package ai

import (
	"context"
	"errors"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

type stubProvider struct{ calls int }

func (s *stubProvider) AnalyzeThreat(_ context.Context, _ *sentinel.ThreatEvent, _ *sentinel.ThreatActor) (*ThreatAnalysis, error) {
	s.calls++
	return &ThreatAnalysis{}, nil
}
func (s *stubProvider) AnalyzeActor(_ context.Context, _ *sentinel.ThreatActor, _ []*sentinel.ThreatEvent) (*ActorAnalysis, error) {
	s.calls++
	return &ActorAnalysis{}, nil
}
func (s *stubProvider) GenerateDailySummary(_ context.Context, _ *sentinel.ThreatStats) (*DailySummary, error) {
	s.calls++
	return &DailySummary{}, nil
}
func (s *stubProvider) NaturalLanguageQuery(_ context.Context, _ string, _ *SecurityContext) (*QueryResult, error) {
	s.calls++
	return &QueryResult{}, nil
}
func (s *stubProvider) RecommendWAFRules(_ context.Context, _ []*sentinel.ThreatEvent) ([]*WAFRecommendation, error) {
	s.calls++
	return nil, nil
}

func TestBudgetedProvider_EnforcesCap(t *testing.T) {
	stub := &stubProvider{}
	bp := NewBudgetedProvider(stub, 2)
	ctx := context.Background()
	threat := &sentinel.ThreatEvent{ID: "t"}

	if _, err := bp.AnalyzeThreat(ctx, threat, nil); err != nil {
		t.Fatalf("call 1 must succeed, got %v", err)
	}
	if _, err := bp.AnalyzeThreat(ctx, threat, nil); err != nil {
		t.Fatalf("call 2 must succeed, got %v", err)
	}
	_, err := bp.AnalyzeThreat(ctx, threat, nil)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("call 3 should be ErrBudgetExhausted, got %v", err)
	}
	if stub.calls != 2 {
		t.Fatalf("underlying provider should have been called 2x, got %d", stub.calls)
	}
}

func TestBudgetedProvider_ZeroDisables(t *testing.T) {
	stub := &stubProvider{}
	bp := NewBudgetedProvider(stub, 0)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if _, err := bp.AnalyzeThreat(ctx, &sentinel.ThreatEvent{}, nil); err != nil {
			t.Fatalf("uncapped call %d returned %v", i, err)
		}
	}
}
