package intelligence_test

import (
	"context"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/intelligence"
)

func TestGeoLocator_Disabled(t *testing.T) {
	geo := intelligence.NewGeoLocator(sentinel.GeoConfig{Enabled: false})

	result, err := geo.LookupIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("expected no error when disabled, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil result when disabled")
	}
}

func TestGeoLocator_PrivateIPSkipped(t *testing.T) {
	geo := intelligence.NewGeoLocator(sentinel.GeoConfig{Enabled: true})

	privateIPs := []string{
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"::1",
	}

	for _, ip := range privateIPs {
		result, err := geo.LookupIP(context.Background(), ip)
		if err != nil {
			t.Errorf("expected no error for private IP %s, got: %v", ip, err)
		}
		if result != nil {
			t.Errorf("expected nil result for private IP %s", ip)
		}
	}
}

func TestGeoLocator_InvalidIP(t *testing.T) {
	geo := intelligence.NewGeoLocator(sentinel.GeoConfig{Enabled: true})

	result, err := geo.LookupIP(context.Background(), "not-an-ip")
	if err != nil {
		t.Fatalf("expected no error for invalid IP, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil result for invalid IP")
	}
}

func TestGeoLocator_CacheSize(t *testing.T) {
	geo := intelligence.NewGeoLocator(sentinel.GeoConfig{Enabled: true})

	// No lookups performed yet
	if geo.CacheSize() != 0 {
		t.Errorf("expected empty cache, got %d", geo.CacheSize())
	}
}
