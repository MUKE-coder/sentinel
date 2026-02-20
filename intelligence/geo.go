package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// GeoLocator provides IP geolocation lookups with an LRU cache.
// It uses the ip-api.com free API for lookups (no API key required).
// For production with high volume, configure a MaxMind GeoLite2 database path.
type GeoLocator struct {
	cache   map[string]*geoCacheEntry
	order   []string // LRU order (most recent at end)
	maxSize int
	mu      sync.RWMutex
	client  *http.Client
	enabled bool
}

type geoCacheEntry struct {
	result     *sentinel.GeoResult
	accessedAt time.Time
}

const defaultGeoCacheSize = 10000

// NewGeoLocator creates a new geolocation service.
func NewGeoLocator(config sentinel.GeoConfig) *GeoLocator {
	return &GeoLocator{
		cache:   make(map[string]*geoCacheEntry),
		maxSize: defaultGeoCacheSize,
		client:  &http.Client{Timeout: 5 * time.Second},
		enabled: config.Enabled,
	}
}

// LookupIP returns geolocation data for an IP address.
// Returns nil for private/loopback IPs. Results are cached in an LRU cache.
func (g *GeoLocator) LookupIP(ctx context.Context, ip string) (*sentinel.GeoResult, error) {
	if !g.enabled {
		return nil, nil
	}

	// Skip private/loopback IPs
	if isPrivateIP(ip) {
		return nil, nil
	}

	// Check cache
	g.mu.RLock()
	entry, ok := g.cache[ip]
	g.mu.RUnlock()

	if ok {
		g.mu.Lock()
		entry.accessedAt = time.Now()
		g.touchLRU(ip)
		g.mu.Unlock()
		return entry.result, nil
	}

	// Query the API
	result, err := g.queryIPAPI(ctx, ip)
	if err != nil {
		return nil, err
	}

	// Cache the result
	g.mu.Lock()
	g.addToCache(ip, result)
	g.mu.Unlock()

	return result, nil
}

// ipAPIResponse matches the ip-api.com JSON response.
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	AS          string  `json:"as"`
	Message     string  `json:"message"`
}

func (g *GeoLocator) queryIPAPI(ctx context.Context, ip string) (*sentinel.GeoResult, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,lat,lon,isp,as", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("geo: failed to decode response: %w", err)
	}

	if apiResp.Status != "success" {
		return nil, fmt.Errorf("geo: API returned status %s: %s", apiResp.Status, apiResp.Message)
	}

	return &sentinel.GeoResult{
		IP:          ip,
		Country:     apiResp.Country,
		CountryCode: apiResp.CountryCode,
		City:        apiResp.City,
		Lat:         apiResp.Lat,
		Lng:         apiResp.Lon,
		ISP:         apiResp.ISP,
		ASN:         apiResp.AS,
	}, nil
}

// addToCache adds a result to the LRU cache, evicting the oldest if at capacity.
// Must be called with g.mu held.
func (g *GeoLocator) addToCache(ip string, result *sentinel.GeoResult) {
	if len(g.cache) >= g.maxSize {
		// Evict the oldest entry (front of order slice)
		if len(g.order) > 0 {
			oldest := g.order[0]
			g.order = g.order[1:]
			delete(g.cache, oldest)
		}
	}
	g.cache[ip] = &geoCacheEntry{
		result:     result,
		accessedAt: time.Now(),
	}
	g.order = append(g.order, ip)
}

// touchLRU moves an IP to the end of the LRU order.
// Must be called with g.mu held.
func (g *GeoLocator) touchLRU(ip string) {
	for i, v := range g.order {
		if v == ip {
			g.order = append(g.order[:i], g.order[i+1:]...)
			g.order = append(g.order, ip)
			return
		}
	}
}

// CacheSize returns the current number of cached entries.
func (g *GeoLocator) CacheSize() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.cache)
}

// IsPrivateIP returns true if the IP is private, loopback, or unspecified.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // Invalid IPs treated as private (skip lookup)
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}
