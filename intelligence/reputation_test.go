package intelligence_test

import (
	"context"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/intelligence"
	"github.com/MUKE-coder/sentinel/storage/memory"
)

func TestReputationChecker_NoAPIKey(t *testing.T) {
	store := memory.New()
	store.Migrate(context.Background())
	ipMgr := intelligence.NewIPManager(store)
	defer ipMgr.Stop()

	rc := intelligence.NewReputationChecker(sentinel.IPReputationConfig{
		Enabled: true,
		// No API key
	}, ipMgr)

	result, err := rc.CheckReputation(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("expected no error without API key, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil result without API key")
	}
}

func TestReputationChecker_CacheSize(t *testing.T) {
	store := memory.New()
	store.Migrate(context.Background())
	ipMgr := intelligence.NewIPManager(store)
	defer ipMgr.Stop()

	rc := intelligence.NewReputationChecker(sentinel.IPReputationConfig{
		Enabled: true,
		// No API key — won't make requests, but cache should remain empty
	}, ipMgr)

	if rc.CacheSize() != 0 {
		t.Errorf("expected empty cache, got %d", rc.CacheSize())
	}
}
