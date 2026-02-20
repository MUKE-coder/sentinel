package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// ReputationChecker checks IP reputation via AbuseIPDB and caches results.
type ReputationChecker struct {
	config    sentinel.IPReputationConfig
	ipManager *IPManager
	cache     map[string]*cachedReputation
	mu        sync.RWMutex
	client    *http.Client
}

type cachedReputation struct {
	result    *sentinel.ReputationResult
	checkedAt time.Time
}

const reputationCacheTTL = 24 * time.Hour

// NewReputationChecker creates a new reputation checker.
// If the API key is not configured, CheckReputation will return nil gracefully.
func NewReputationChecker(config sentinel.IPReputationConfig, ipManager *IPManager) *ReputationChecker {
	return &ReputationChecker{
		config:    config,
		ipManager: ipManager,
		cache:     make(map[string]*cachedReputation),
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// CheckReputation checks the reputation of an IP address via AbuseIPDB.
// Returns nil if the API key is not configured or if the IP is already cached.
func (rc *ReputationChecker) CheckReputation(ctx context.Context, ip string) (*sentinel.ReputationResult, error) {
	// Gracefully skip if no API key configured
	if rc.config.AbuseIPDBKey == "" {
		return nil, nil
	}

	// Check cache
	rc.mu.RLock()
	cached, ok := rc.cache[ip]
	rc.mu.RUnlock()

	if ok && time.Since(cached.checkedAt) < reputationCacheTTL {
		return cached.result, nil
	}

	// Call AbuseIPDB API
	result, err := rc.queryAbuseIPDB(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb query failed for %s: %w", ip, err)
	}

	// Cache the result
	rc.mu.Lock()
	rc.cache[ip] = &cachedReputation{
		result:    result,
		checkedAt: time.Now(),
	}
	rc.mu.Unlock()

	// Auto-block if abuse score exceeds threshold
	if rc.config.AutoBlock && result.AbuseScore >= rc.config.MinAbuseScore {
		reason := fmt.Sprintf("AbuseIPDB score %d (threshold: %d)", result.AbuseScore, rc.config.MinAbuseScore)
		if err := rc.ipManager.BlockIP(ctx, ip, reason, nil); err != nil {
			log.Printf("[sentinel] reputation: failed to auto-block %s: %v", ip, err)
		} else {
			log.Printf("[sentinel] reputation: auto-blocked %s (abuse score: %d)", ip, result.AbuseScore)
		}
	}

	return result, nil
}

// abuseIPDBResponse matches the AbuseIPDB v2 CHECK endpoint response.
type abuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		TotalReports         int    `json:"totalReports"`
		IsWhitelisted        *bool  `json:"isWhitelisted"`
	} `json:"data"`
}

func (rc *ReputationChecker) queryAbuseIPDB(ctx context.Context, ip string) (*sentinel.ReputationResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.abuseipdb.com/api/v2/check", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Key", rc.config.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb returned status %d", resp.StatusCode)
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode abuseipdb response: %w", err)
	}

	isWhitelisted := false
	if apiResp.Data.IsWhitelisted != nil {
		isWhitelisted = *apiResp.Data.IsWhitelisted
	}

	return &sentinel.ReputationResult{
		IP:            apiResp.Data.IPAddress,
		AbuseScore:    apiResp.Data.AbuseConfidenceScore,
		TotalReports:  apiResp.Data.TotalReports,
		CountryCode:   apiResp.Data.CountryCode,
		ISP:           apiResp.Data.ISP,
		Domain:        apiResp.Data.Domain,
		IsWhitelisted: isWhitelisted,
		CheckedAt:     time.Now(),
	}, nil
}

// CacheSize returns the number of cached reputation results.
func (rc *ReputationChecker) CacheSize() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.cache)
}
