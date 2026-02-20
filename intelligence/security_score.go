package intelligence

import (
	"context"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/storage"
)

// ScoreEngine computes and caches the security score.
type ScoreEngine struct {
	store  storage.Store
	config sentinel.Config
}

// NewScoreEngine creates a new security score engine.
func NewScoreEngine(store storage.Store, config sentinel.Config) *ScoreEngine {
	return &ScoreEngine{store: store, config: config}
}

// ComputeScore calculates the security score based on current state.
func (e *ScoreEngine) ComputeScore(ctx context.Context) (*sentinel.SecurityScore, error) {
	stats, err := e.store.GetThreatStats(ctx, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	// Threat Activity score (weight: 30%)
	threatScore := computeThreatActivityScore(stats)

	// Auth Security score (weight: 20%)
	authScore := computeAuthSecurityScore(e.config)

	// Response Posture score (weight: 20%)
	responseScore := computeResponsePostureScore(stats)

	// Header Compliance score (weight: 15%)
	headerScore := computeHeaderComplianceScore(e.config)

	// Rate Limiting Coverage score (weight: 15%)
	rateLimitScore := computeRateLimitCoverageScore(e.config)

	overall := int(
		float64(threatScore)*0.30 +
			float64(authScore)*0.20 +
			float64(responseScore)*0.20 +
			float64(headerScore)*0.15 +
			float64(rateLimitScore)*0.15,
	)

	grade := scoreToGrade(overall)
	recommendations := generateRecommendations(threatScore, authScore, responseScore, headerScore, rateLimitScore, e.config)

	score := &sentinel.SecurityScore{
		Overall: overall,
		Grade:   grade,
		ThreatActivity: sentinel.SubScore{
			Score:  threatScore,
			Weight: 0.30,
			Label:  "Threat Activity",
		},
		AuthSecurity: sentinel.SubScore{
			Score:  authScore,
			Weight: 0.20,
			Label:  "Auth Security",
		},
		ResponsePosture: sentinel.SubScore{
			Score:  responseScore,
			Weight: 0.20,
			Label:  "Response Posture",
		},
		HeaderCompliance: sentinel.SubScore{
			Score:  headerScore,
			Weight: 0.15,
			Label:  "Header Compliance",
		},
		RateLimitCoverage: sentinel.SubScore{
			Score:  rateLimitScore,
			Weight: 0.15,
			Label:  "Rate Limiting",
		},
		ComputedAt:      time.Now(),
		Trend:           "stable",
		Recommendations: recommendations,
	}

	// Save to store
	if err := e.store.SaveSecurityScore(ctx, score); err != nil {
		return score, err
	}

	return score, nil
}

func computeThreatActivityScore(stats *sentinel.ThreatStats) int {
	if stats == nil || stats.TotalThreats == 0 {
		return 100
	}

	score := 100
	// Deduct for critical threats
	score -= int(stats.CriticalCount) * 20
	// Deduct for high threats
	score -= int(stats.HighCount) * 10
	// Deduct for medium threats
	score -= int(stats.MediumCount) * 5
	// Deduct for low threats
	score -= int(stats.LowCount) * 2

	// Bonus for blocked threats
	if stats.TotalThreats > 0 {
		blockRate := float64(stats.BlockedCount) / float64(stats.TotalThreats)
		if blockRate > 0.9 {
			score += 10
		} else if blockRate > 0.5 {
			score += 5
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func computeAuthSecurityScore(config sentinel.Config) int {
	score := 50 // Base score

	if config.Dashboard.Password != "" && config.Dashboard.Password != "sentinel" {
		score += 20
	}
	if config.Dashboard.SecretKey != "" && config.Dashboard.SecretKey != "sentinel-default-secret-change-me" {
		score += 20
	}
	if config.AuthShield.Enabled {
		score += 10
	}

	if score > 100 {
		score = 100
	}
	return score
}

func computeResponsePostureScore(stats *sentinel.ThreatStats) int {
	if stats == nil || stats.TotalThreats == 0 {
		return 80
	}

	if stats.BlockedCount == stats.TotalThreats {
		return 100
	}

	blockRate := float64(stats.BlockedCount) / float64(stats.TotalThreats)
	return int(blockRate * 100)
}

func computeHeaderComplianceScore(config sentinel.Config) int {
	score := 0
	total := 5

	if config.Headers.Enabled != nil && !*config.Headers.Enabled {
		return 0
	}

	score++ // X-Content-Type-Options (always set by default)
	if config.Headers.XFrameOptions != "" {
		score++
	}
	if config.Headers.ReferrerPolicy != "" {
		score++
	}
	if config.Headers.ContentSecurityPolicy != "" {
		score++
	}
	if config.Headers.StrictTransportSecurity {
		score++
	}

	return (score * 100) / total
}

func computeRateLimitCoverageScore(config sentinel.Config) int {
	if !config.RateLimit.Enabled {
		return 0
	}

	score := 30 // Base for having rate limiting enabled
	if config.RateLimit.ByIP != nil {
		score += 30
	}
	if config.RateLimit.ByUser != nil {
		score += 20
	}
	if config.RateLimit.ByRoute != nil && len(config.RateLimit.ByRoute) > 0 {
		score += 20
	}

	if score > 100 {
		score = 100
	}
	return score
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func generateRecommendations(threat, auth, response, header, rateLimit int, config sentinel.Config) []sentinel.Recommendation {
	var recs []sentinel.Recommendation

	if !config.WAF.Enabled {
		recs = append(recs, sentinel.Recommendation{
			Title:       "Enable WAF",
			Description: "Enable the Web Application Firewall to protect against common attacks.",
			Impact:      "High",
			Category:    "threat_activity",
		})
	} else if config.WAF.Mode != sentinel.ModeBlock {
		recs = append(recs, sentinel.Recommendation{
			Title:       "Set WAF to Block Mode",
			Description: "Switch WAF from log mode to block mode to actively prevent attacks.",
			Impact:      "High",
			Category:    "response_posture",
		})
	}

	if !config.RateLimit.Enabled {
		recs = append(recs, sentinel.Recommendation{
			Title:       "Enable Rate Limiting",
			Description: "Enable rate limiting to prevent abuse and brute force attacks.",
			Impact:      "Medium",
			Category:    "rate_limit_coverage",
		})
	}

	if header < 80 {
		recs = append(recs, sentinel.Recommendation{
			Title:       "Add Security Headers",
			Description: "Configure Content-Security-Policy and Strict-Transport-Security headers.",
			Impact:      "Medium",
			Category:    "header_compliance",
		})
	}

	if auth < 70 {
		recs = append(recs, sentinel.Recommendation{
			Title:       "Strengthen Authentication",
			Description: "Change default passwords and secret keys. Enable auth shield for brute force protection.",
			Impact:      "High",
			Category:    "auth_security",
		})
	}

	return recs
}
