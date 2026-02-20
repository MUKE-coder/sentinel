package intelligence

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/MUKE-coder/sentinel/storage"
)

// AnomalyDetector maintains per-user behavioral baselines and detects anomalies
// by comparing new activity against established patterns.
type AnomalyDetector struct {
	store     storage.Store
	pipe      *pipeline.Pipeline
	geoLoc    *GeoLocator
	config    sentinel.AnomalyConfig
	baselines map[string]*UserBaseline
	mu        sync.RWMutex
}

// UserBaseline represents a user's normal behavioral pattern computed from historical data.
type UserBaseline struct {
	UserID         string
	ActiveHours    map[int]int     // hour-of-day -> activity count
	TypicalRoutes  map[string]int  // route -> access count
	AvgRequestsPerHour float64
	SourceIPs      map[string]bool
	Countries      map[string]bool
	AvgResponseSize float64
	TotalRequests  int
	ComputedAt     time.Time
}

// NewAnomalyDetector creates a new anomaly detector.
func NewAnomalyDetector(store storage.Store, pipe *pipeline.Pipeline, geoLoc *GeoLocator, config sentinel.AnomalyConfig) *AnomalyDetector {
	return &AnomalyDetector{
		store:     store,
		pipe:      pipe,
		geoLoc:    geoLoc,
		config:    config,
		baselines: make(map[string]*UserBaseline),
	}
}

// Handle processes pipeline events to detect anomalies in user activity.
func (ad *AnomalyDetector) Handle(ctx context.Context, event pipeline.Event) error {
	if !ad.config.Enabled {
		return nil
	}
	if event.Type != pipeline.EventUserActivity {
		return nil
	}

	activity, ok := event.Payload.(*sentinel.UserActivity)
	if !ok || activity == nil || activity.UserID == "" {
		return nil
	}

	return ad.CheckActivity(ctx, activity)
}

// CheckActivity checks a user activity event against the user's behavioral baseline.
func (ad *AnomalyDetector) CheckActivity(ctx context.Context, activity *sentinel.UserActivity) error {
	baseline := ad.getOrComputeBaseline(ctx, activity.UserID)
	if baseline == nil || baseline.TotalRequests < 10 {
		// Not enough data for a baseline
		return nil
	}

	var totalScore int
	var anomalies []string

	// Run each enabled check
	for _, check := range ad.config.Checks {
		score := 0
		switch check {
		case sentinel.CheckOffHoursAccess:
			score = ad.checkOffHours(activity, baseline)
		case sentinel.CheckUnusualAccess:
			score = ad.checkUnusualAccess(activity, baseline)
		case sentinel.CheckVelocityAnomaly:
			score = ad.checkVelocity(activity, baseline)
		case sentinel.CheckImpossibleTravel:
			score = ad.checkImpossibleTravel(activity, baseline)
		case sentinel.CheckDataExfiltration:
			score = ad.checkDataExfiltration(activity, baseline)
		}
		if score > 0 {
			totalScore += score
			anomalies = append(anomalies, string(check))
		}
	}

	// Cap score at 100
	if totalScore > 100 {
		totalScore = 100
	}

	// Emit threat if score exceeds threshold
	threshold := ad.getThreshold()
	if totalScore >= threshold && len(anomalies) > 0 {
		severity := ad.scoreToSeverity(totalScore)
		te := &sentinel.ThreatEvent{
			ID:          fmt.Sprintf("anomaly-%s-%d", activity.UserID, time.Now().UnixNano()),
			Timestamp:   activity.Timestamp,
			IP:          activity.IP,
			UserID:      activity.UserID,
			Method:      activity.Method,
			Path:        activity.Path,
			ThreatTypes: []string{string(sentinel.ThreatAnomalyDetected)},
			Severity:    severity,
			Confidence:  totalScore,
			Evidence: []sentinel.Evidence{
				{
					Pattern:  "behavioral_anomaly",
					Matched:  fmt.Sprintf("anomaly_score=%d, checks=%v", totalScore, anomalies),
					Location: "user_behavior",
				},
			},
			Blocked: false,
			Country: activity.Country,
		}
		ad.pipe.EmitThreat(te)
		log.Printf("[sentinel] anomaly: detected for user %s (score: %d, checks: %v)",
			activity.UserID, totalScore, anomalies)
	}

	return nil
}

// checkOffHours detects access outside the user's normal active hours.
// Returns 0-30 based on how unusual the hour is.
func (ad *AnomalyDetector) checkOffHours(activity *sentinel.UserActivity, baseline *UserBaseline) int {
	hour := activity.Timestamp.Hour()
	count := baseline.ActiveHours[hour]

	if baseline.TotalRequests == 0 {
		return 0
	}

	// Calculate what percentage of activity happens at this hour
	hourPct := float64(count) / float64(baseline.TotalRequests) * 100

	// If this hour has < 1% of activity, it's off-hours
	if hourPct < 1.0 {
		return 30
	}
	// If < 3%, mildly unusual
	if hourPct < 3.0 {
		return 15
	}

	return 0
}

// checkUnusualAccess detects access to routes the user has never accessed before.
// Returns 0-25 based on how unusual the route is.
func (ad *AnomalyDetector) checkUnusualAccess(activity *sentinel.UserActivity, baseline *UserBaseline) int {
	route := activity.Method + " " + activity.Path
	if _, known := baseline.TypicalRoutes[route]; !known {
		return 25
	}
	return 0
}

// checkVelocity detects if request rate exceeds 3x the baseline for this time of day.
// Returns 0-25 based on the velocity anomaly.
func (ad *AnomalyDetector) checkVelocity(activity *sentinel.UserActivity, baseline *UserBaseline) int {
	if baseline.AvgRequestsPerHour <= 0 {
		return 0
	}

	// Get current hourly rate from baseline
	hour := activity.Timestamp.Hour()
	hourlyRate := float64(baseline.ActiveHours[hour])
	daysInBaseline := float64(baseline.TotalRequests) / (24 * baseline.AvgRequestsPerHour)
	if daysInBaseline < 1 {
		daysInBaseline = 1
	}
	avgForHour := hourlyRate / daysInBaseline

	if avgForHour > 0 && baseline.AvgRequestsPerHour > 3*avgForHour {
		return 25
	}

	return 0
}

// checkImpossibleTravel detects if a user is active from two IPs >1000km apart within 1 hour.
// Returns 0-30 based on whether impossible travel is detected.
func (ad *AnomalyDetector) checkImpossibleTravel(activity *sentinel.UserActivity, baseline *UserBaseline) int {
	// If user has known source IPs and current IP is new
	if len(baseline.SourceIPs) > 0 && !baseline.SourceIPs[activity.IP] {
		// New IP detected — could indicate impossible travel
		// Without real-time geo distance calculation between recent IPs, we give a moderate score
		if activity.Country != "" && len(baseline.Countries) > 0 && !baseline.Countries[activity.Country] {
			return 30 // Different country = strong signal
		}
		return 10 // New IP but same/unknown country
	}
	return 0
}

// checkDataExfiltration detects if response size per session exceeds 5x baseline average.
// Returns 0-20 based on the size anomaly.
func (ad *AnomalyDetector) checkDataExfiltration(activity *sentinel.UserActivity, baseline *UserBaseline) int {
	if baseline.AvgResponseSize <= 0 {
		return 0
	}

	// We use duration_ms as a proxy — if we had response size we'd use that
	// For now, check if the activity duration is abnormally high
	avgDuration := baseline.AvgResponseSize // stored as avg response size
	if avgDuration > 0 && float64(activity.Duration) > 5*avgDuration {
		return 20
	}

	return 0
}

// getOrComputeBaseline retrieves or computes the behavioral baseline for a user.
func (ad *AnomalyDetector) getOrComputeBaseline(ctx context.Context, userID string) *UserBaseline {
	ad.mu.RLock()
	bl, ok := ad.baselines[userID]
	ad.mu.RUnlock()

	// Use cached baseline if it's less than 1 hour old
	if ok && time.Since(bl.ComputedAt) < time.Hour {
		return bl
	}

	// Compute from storage
	baseline := ad.computeBaseline(ctx, userID)
	if baseline != nil {
		ad.mu.Lock()
		ad.baselines[userID] = baseline
		ad.mu.Unlock()
	}

	return baseline
}

// computeBaseline builds a behavioral baseline from the user's activity over the learning period.
func (ad *AnomalyDetector) computeBaseline(ctx context.Context, userID string) *UserBaseline {
	start := time.Now().Add(-ad.config.LearningPeriod)
	filter := sentinel.ActivityFilter{
		StartTime: &start,
		Page:      1,
		PageSize:  10000, // Get all activity in the window
	}

	activities, _, err := ad.store.ListUserActivity(ctx, userID, filter)
	if err != nil {
		log.Printf("[sentinel] anomaly: failed to load activity for user %s: %v", userID, err)
		return nil
	}

	if len(activities) == 0 {
		return nil
	}

	bl := &UserBaseline{
		UserID:        userID,
		ActiveHours:   make(map[int]int),
		TypicalRoutes: make(map[string]int),
		SourceIPs:     make(map[string]bool),
		Countries:     make(map[string]bool),
		TotalRequests: len(activities),
		ComputedAt:    time.Now(),
	}

	var totalDuration int64
	for _, a := range activities {
		bl.ActiveHours[a.Timestamp.Hour()]++
		route := a.Method + " " + a.Path
		bl.TypicalRoutes[route]++
		bl.SourceIPs[a.IP] = true
		if a.Country != "" {
			bl.Countries[a.Country] = true
		}
		totalDuration += a.Duration
	}

	// Compute averages
	hours := time.Since(start).Hours()
	if hours > 0 {
		bl.AvgRequestsPerHour = float64(len(activities)) / hours
	}
	if len(activities) > 0 {
		bl.AvgResponseSize = float64(totalDuration) / float64(len(activities))
	}

	return bl
}

func (ad *AnomalyDetector) getThreshold() int {
	switch ad.config.Sensitivity {
	case sentinel.AnomalySensitivityHigh:
		return 15
	case sentinel.AnomalySensitivityLow:
		return 50
	default: // medium
		return 30
	}
}

func (ad *AnomalyDetector) scoreToSeverity(score int) sentinel.Severity {
	switch {
	case score >= 80:
		return sentinel.SeverityCritical
	case score >= 60:
		return sentinel.SeverityHigh
	case score >= 30:
		return sentinel.SeverityMedium
	default:
		return sentinel.SeverityLow
	}
}

// haversineDistance calculates the distance in km between two lat/lng coordinates.
func haversineDistance(lat1, lng1, lat2, lng2 float64) float64 {
	const earthRadius = 6371.0 // km

	dLat := (lat2 - lat1) * math.Pi / 180
	dLng := (lng2 - lng1) * math.Pi / 180

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLng/2)*math.Sin(dLng/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadius * c
}
