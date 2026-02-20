// Package intelligence provides threat actor profiling, anomaly detection,
// security scoring, IP reputation checking, and geolocation.
package intelligence

import (
	"context"
	"log"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/MUKE-coder/sentinel/storage"
)

// Profiler processes threat events and maintains threat actor profiles.
// It runs as a pipeline handler, updating actor profiles for every threat event.
type Profiler struct {
	store storage.Store
}

// NewProfiler creates a new threat actor profiler.
func NewProfiler(store storage.Store) *Profiler {
	return &Profiler{store: store}
}

// Handle processes a pipeline event. Only EventThreat events are handled.
func (p *Profiler) Handle(ctx context.Context, event pipeline.Event) error {
	if event.Type != pipeline.EventThreat {
		return nil
	}

	te, ok := event.Payload.(*sentinel.ThreatEvent)
	if !ok || te == nil {
		return nil
	}

	return p.ProcessThreat(ctx, te)
}

// ProcessThreat updates the threat actor profile for the given threat event.
func (p *Profiler) ProcessThreat(ctx context.Context, te *sentinel.ThreatEvent) error {
	ip := te.IP
	if ip == "" {
		return nil
	}

	// Get or create actor
	actor, err := p.store.GetActor(ctx, ip)
	if err != nil || actor == nil {
		// Actor doesn't exist yet — create a new one
		actor = &sentinel.ThreatActor{
			ID:        ip,
			IP:        ip,
			FirstSeen: te.Timestamp,
			Status:    sentinel.ActorActive,
		}
	}

	// Update basic counters
	actor.LastSeen = te.Timestamp
	actor.TotalRequests++
	actor.ThreatCount++

	// Deduplicate attack types
	for _, tt := range te.ThreatTypes {
		if !containsStr(actor.AttackTypes, tt) {
			actor.AttackTypes = append(actor.AttackTypes, tt)
		}
	}

	// Deduplicate targeted routes
	route := te.Method + " " + te.Path
	if !containsStr(actor.TargetedRoutes, route) {
		actor.TargetedRoutes = append(actor.TargetedRoutes, route)
	}

	// Copy geo data from threat if available and actor doesn't have it
	if actor.Country == "" && te.Country != "" {
		actor.Country = te.Country
		actor.City = te.City
		actor.Lat = te.Lat
		actor.Lng = te.Lng
	}

	// Recompute risk score
	actor.RiskScore = ComputeRiskScore(actor)

	// Persist
	if err := p.store.UpsertActor(ctx, actor); err != nil {
		log.Printf("[sentinel] profiler: failed to upsert actor %s: %v", ip, err)
		return err
	}

	return nil
}

// ComputeRiskScore calculates a risk score (0-100) for a threat actor based on:
//   - +10 for each unique attack type (max 50)
//   - +20 if known bad actor (AbuseIPDB)
//   - +10 if attacked in last hour
//   - +20 if attack count > 100
//   - Capped at 100
func ComputeRiskScore(actor *sentinel.ThreatActor) int {
	score := 0

	// +10 for each unique attack type, max 50
	attackTypeScore := len(actor.AttackTypes) * 10
	if attackTypeScore > 50 {
		attackTypeScore = 50
	}
	score += attackTypeScore

	// +20 if known bad actor
	if actor.IsKnownBadActor {
		score += 20
	}

	// +10 if attacked in last hour
	if time.Since(actor.LastSeen) < time.Hour {
		score += 10
	}

	// +20 if attack count > 100
	if actor.ThreatCount > 100 {
		score += 20
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
