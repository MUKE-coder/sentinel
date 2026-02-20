package core

import (
	"encoding/json"
	"time"
)

// JSONMap is a map[string]interface{} that marshals to/from JSON in the database.
type JSONMap map[string]interface{}

// Ensure JSONMap implements json.Marshaler.
var _ json.Marshaler = JSONMap{}

// MarshalJSON implements the json.Marshaler interface.
func (m JSONMap) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}(m))
}

// InspectedRequest contains all input vectors extracted from an HTTP request
// for threat analysis. Used by the detection engine and WAF middleware.
type InspectedRequest struct {
	Method    string
	Path      string
	RawQuery  string
	Headers   map[string][]string
	Body      string
	IP        string
	UserAgent string
}

// Evidence represents a single piece of evidence from a threat detection match.
type Evidence struct {
	Pattern   string `json:"pattern"`
	Matched   string `json:"matched"`
	Location  string `json:"location"`
	Parameter string `json:"parameter,omitempty"`
}

// ThreatEvent represents a single detected security threat.
type ThreatEvent struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	IP            string    `json:"ip"`
	ActorID       string    `json:"actor_id"`
	UserID        string    `json:"user_id,omitempty"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	StatusCode    int       `json:"status_code"`
	UserAgent     string    `json:"user_agent"`
	Referer       string    `json:"referer,omitempty"`
	QueryParams   string    `json:"query_params,omitempty"`
	BodySnippet   string    `json:"body_snippet,omitempty"`
	Headers       JSONMap   `json:"headers"`
	ThreatTypes   []string  `json:"threat_types"`
	Severity      Severity  `json:"severity"`
	Confidence    int       `json:"confidence"`
	Evidence      []Evidence `json:"evidence"`
	Blocked       bool      `json:"blocked"`
	Country       string    `json:"country,omitempty"`
	City          string    `json:"city,omitempty"`
	Lat           float64   `json:"lat,omitempty"`
	Lng           float64   `json:"lng,omitempty"`
	Resolved      bool      `json:"resolved"`
	FalsePositive bool      `json:"false_positive"`
}

// ThreatActor represents a persistent profile of an attacker.
type ThreatActor struct {
	ID              string      `json:"id"`
	IP              string      `json:"ip"`
	FirstSeen       time.Time   `json:"first_seen"`
	LastSeen        time.Time   `json:"last_seen"`
	TotalRequests   int         `json:"total_requests"`
	ThreatCount     int         `json:"threat_count"`
	AttackTypes     []string    `json:"attack_types"`
	TargetedRoutes  []string    `json:"targeted_routes"`
	RiskScore       int         `json:"risk_score"`
	Status          ActorStatus `json:"status"`
	Country         string      `json:"country"`
	City            string      `json:"city,omitempty"`
	ISP             string      `json:"isp"`
	IsKnownBadActor bool        `json:"is_known_bad_actor"`
	AbuseScore      int         `json:"abuse_score"`
	Lat             float64     `json:"lat"`
	Lng             float64     `json:"lng"`
}

// AuditLog represents an immutable audit trail entry.
type AuditLog struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	UserID     string    `json:"user_id"`
	UserEmail  string    `json:"user_email,omitempty"`
	UserRole   string    `json:"user_role,omitempty"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID string    `json:"resource_id"`
	Before     JSONMap   `json:"before,omitempty"`
	After      JSONMap   `json:"after,omitempty"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	RequestID  string    `json:"request_id"`
}

// UserActivity represents a per-user activity record.
type UserActivity struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	UserID     string    `json:"user_id"`
	UserEmail  string    `json:"user_email,omitempty"`
	Action     string    `json:"action"`
	Path       string    `json:"path"`
	Method     string    `json:"method"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	StatusCode int       `json:"status_code"`
	Duration   int64     `json:"duration_ms"`
	ThreatID   string    `json:"threat_id,omitempty"`
	Country    string    `json:"country,omitempty"`
}

// SubScore represents a sub-component of the security score.
type SubScore struct {
	Score   int     `json:"score"`
	Weight  float64 `json:"weight"`
	Label   string  `json:"label"`
	Details string  `json:"details,omitempty"`
}

// Recommendation is an actionable suggestion to improve the security score.
type Recommendation struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Category    string `json:"category"`
}

// SecurityScore represents the overall security posture score.
type SecurityScore struct {
	Overall           int              `json:"overall"`
	Grade             string           `json:"grade"`
	ThreatActivity    SubScore         `json:"threat_activity"`
	AuthSecurity      SubScore         `json:"auth_security"`
	ResponsePosture   SubScore         `json:"response_posture"`
	HeaderCompliance  SubScore         `json:"header_compliance"`
	RateLimitCoverage SubScore         `json:"rate_limit_coverage"`
	ComputedAt        time.Time        `json:"computed_at"`
	Trend             string           `json:"trend"`
	Recommendations   []Recommendation `json:"recommendations"`
}

// PerformanceMetric represents a single performance measurement.
type PerformanceMetric struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Route        string    `json:"route"`
	Method       string    `json:"method"`
	StatusCode   int       `json:"status_code"`
	Duration     int64     `json:"duration_ms"`
	ResponseSize int64     `json:"response_size"`
	IP           string    `json:"ip"`
	Error        string    `json:"error,omitempty"`
}

// PerformanceOverview is a snapshot of current system performance.
type PerformanceOverview struct {
	AvgResponseTime  float64   `json:"avg_response_time_ms"`
	ErrorRate        float64   `json:"error_rate"`
	TotalRequests    int64     `json:"total_requests"`
	ActiveGoroutines int       `json:"active_goroutines"`
	MemoryUsageMB    float64   `json:"memory_usage_mb"`
	DBQueryAvg       float64   `json:"db_query_avg_ms"`
	ComputedAt       time.Time `json:"computed_at"`
}

// RouteMetric contains performance metrics for a specific route.
type RouteMetric struct {
	Route        string  `json:"route"`
	Method       string  `json:"method"`
	P50          float64 `json:"p50_ms"`
	P95          float64 `json:"p95_ms"`
	P99          float64 `json:"p99_ms"`
	ErrorRate    float64 `json:"error_rate"`
	RequestCount int64   `json:"request_count"`
}

// BlockedIP represents a blocked IP address.
type BlockedIP struct {
	IP        string     `json:"ip"`
	Reason    string     `json:"reason"`
	BlockedAt time.Time  `json:"blocked_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CIDR      bool       `json:"cidr"`
}

// WhitelistedIP represents a whitelisted IP address.
type WhitelistedIP struct {
	IP          string    `json:"ip"`
	WhitelistAt time.Time `json:"whitelisted_at"`
}

// ThreatStats contains aggregated threat statistics.
type ThreatStats struct {
	TotalThreats   int64            `json:"total_threats"`
	CriticalCount  int64            `json:"critical_count"`
	HighCount      int64            `json:"high_count"`
	MediumCount    int64            `json:"medium_count"`
	LowCount       int64            `json:"low_count"`
	BlockedCount   int64            `json:"blocked_count"`
	UniqueIPs      int64            `json:"unique_ips"`
	TopAttackTypes []AttackTypeStat `json:"top_attack_types"`
	Window         string           `json:"window"`
}

// AttackTypeStat is a count of threats by attack type.
type AttackTypeStat struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

// ThreatFilter defines query filters for listing threats.
type ThreatFilter struct {
	Severity  Severity   `json:"severity,omitempty"`
	Type      string     `json:"type,omitempty"`
	IP        string     `json:"ip,omitempty"`
	UserID    string     `json:"user_id,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Resolved  *bool      `json:"resolved,omitempty"`
	Search    string     `json:"search,omitempty"`
	Page      int        `json:"page"`
	PageSize  int        `json:"page_size"`
	SortBy    string     `json:"sort_by"`
	SortOrder string     `json:"sort_order"`
}

// ActorFilter defines query filters for listing threat actors.
type ActorFilter struct {
	Status    ActorStatus `json:"status,omitempty"`
	MinRisk   int         `json:"min_risk,omitempty"`
	Search    string      `json:"search,omitempty"`
	Page      int         `json:"page"`
	PageSize  int         `json:"page_size"`
	SortBy    string      `json:"sort_by"`
	SortOrder string      `json:"sort_order"`
}

// ActivityFilter defines query filters for listing user activity.
type ActivityFilter struct {
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Path      string     `json:"path,omitempty"`
	Page      int        `json:"page"`
	PageSize  int        `json:"page_size"`
}

// AuditFilter defines query filters for listing audit logs.
type AuditFilter struct {
	UserID    string     `json:"user_id,omitempty"`
	Action    string     `json:"action,omitempty"`
	Resource  string     `json:"resource,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Page      int        `json:"page"`
	PageSize  int        `json:"page_size"`
}

// ThreatUpdate contains fields that can be updated on a threat event.
type ThreatUpdate struct {
	Resolved      *bool `json:"resolved,omitempty"`
	FalsePositive *bool `json:"false_positive,omitempty"`
}

// ReputationResult contains IP reputation data from AbuseIPDB.
type ReputationResult struct {
	IP            string    `json:"ip"`
	AbuseScore    int       `json:"abuse_score"`
	TotalReports  int       `json:"total_reports"`
	CountryCode   string    `json:"country_code"`
	ISP           string    `json:"isp"`
	Domain        string    `json:"domain,omitempty"`
	IsWhitelisted bool      `json:"is_whitelisted"`
	CheckedAt     time.Time `json:"checked_at"`
}

// GeoResult contains geolocation data for an IP address.
type GeoResult struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lng         float64 `json:"lng"`
	ISP         string  `json:"isp"`
	ASN         string  `json:"asn"`
}

// AlertHistory records a sent alert.
type AlertHistory struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ThreatID    string    `json:"threat_id"`
	Channel     string    `json:"channel"`
	Severity    Severity  `json:"severity"`
	IP          string    `json:"ip"`
	ThreatType  string    `json:"threat_type"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
}

// UserSummary contains aggregated user information for the users API.
type UserSummary struct {
	UserID        string    `json:"user_id"`
	Email         string    `json:"email,omitempty"`
	ActivityCount int64     `json:"activity_count"`
	ThreatCount   int64     `json:"threat_count"`
	LastSeen      time.Time `json:"last_seen"`
}

// AttackTrend contains time-series data for attack trends.
type AttackTrend struct {
	Period string           `json:"period"`
	Total  int64            `json:"total"`
	ByType map[string]int64 `json:"by_type"`
}

// GeoStats contains aggregated geographic attack data.
type GeoStats struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Count       int64   `json:"count"`
	Lat         float64 `json:"lat"`
	Lng         float64 `json:"lng"`
}

// TopTarget contains data about the most targeted routes.
type TopTarget struct {
	Route  string `json:"route"`
	Method string `json:"method"`
	Count  int64  `json:"count"`
}
