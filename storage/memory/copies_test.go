package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// TestActorsAreCopies: the profiler and the reputation watcher update actors
// they read back; with shared pointers those updates raced API readers.
func TestActorsAreCopies(t *testing.T) {
	s := New()
	ctx := context.Background()
	s.UpsertActor(ctx, &sentinel.ThreatActor{IP: "203.0.113.1", AttackTypes: []string{"SQLi"}})

	a, _ := s.GetActor(ctx, "203.0.113.1")
	a.RiskScore = 99
	a.AttackTypes[0] = "changed"

	again, _ := s.GetActor(ctx, "203.0.113.1")
	if again.RiskScore != 0 || again.AttackTypes[0] != "SQLi" {
		t.Errorf("changing a returned actor changed the stored one: %+v", again)
	}
}

// TestThreatUpdatesDoNotRaceReaders runs UpdateThreat against readers of
// the same event; under -race this failed while reads shared pointers.
func TestThreatUpdatesDoNotRaceReaders(t *testing.T) {
	s := New()
	ctx := context.Background()
	s.SaveThreat(ctx, &sentinel.ThreatEvent{ID: "t1", Timestamp: time.Now()})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			resolved := i%2 == 0
			s.UpdateThreat(ctx, "t1", sentinel.ThreatUpdate{Resolved: &resolved})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if th, _ := s.GetThreat(ctx, "t1"); th != nil {
				_ = th.Resolved
			}
			if list, _, _ := s.ListThreats(ctx, sentinel.ThreatFilter{PageSize: 10}); len(list) > 0 {
				_ = list[0].Resolved
			}
		}
	}()
	wg.Wait()
}
