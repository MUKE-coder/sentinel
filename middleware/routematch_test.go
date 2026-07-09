package middleware

import (
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func TestRouteMatcher(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		path     string
		want     bool
	}{
		{"exact match", []string{"/health"}, "/health", true},
		{"exact no submatch", []string{"/health"}, "/healthz", false},
		{"exact no prefix match", []string{"/health"}, "/health/live", false},
		{"single star prefix", []string{"/api/auth/*"}, "/api/auth/login", true},
		{"single star matches base", []string{"/api/auth/*"}, "/api/auth", true},
		{"single star no sibling", []string{"/api/auth/*"}, "/api/authx", false},
		{"double star prefix", []string{"/v1/**"}, "/v1/payments/collect", true},
		{"double star matches base", []string{"/v1/**"}, "/v1", true},
		{"double star no sibling", []string{"/v1/**"}, "/v2/payments", false},
		{"segment glob", []string{"/api/member/apps/*/products"}, "/api/member/apps/42/products", true},
		{"segment glob no cross-segment", []string{"/api/member/apps/*/products"}, "/api/member/apps/42/extra/products", false},
		{"mixed list", []string{"/health", "/v1/**"}, "/v1/x", true},
		{"empty list", nil, "/anything", false},
		{"mid double-star ignored", []string{"/api/**/products"}, "/api/a/products", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewRouteMatcher(tc.patterns)
			if got := m.Matches(tc.path); got != tc.want {
				t.Errorf("NewRouteMatcher(%v).Matches(%q) = %v, want %v", tc.patterns, tc.path, got, tc.want)
			}
		})
	}
}

// Regression test for issue #7: wildcard ExcludeRoutes entries were silent
// dead code — the WAF kept inspecting (and blocking) routes callers believed
// excluded.
func TestCompileRouteLimitsWildcards(t *testing.T) {
	byRoute := map[string]sentinel.Limit{
		"/api/auth/login": {Requests: 5, Window: 15 * time.Minute},
		"/v1/*":           {Requests: 100, Window: time.Minute},
	}
	exact, patterns := compileRouteLimits(byRoute)

	if _, ok := exact["/api/auth/login"]; !ok {
		t.Fatal("exact key missing from exact map")
	}
	if len(patterns) != 1 || patterns[0].pattern != "/v1/*" {
		t.Fatalf("expected one wildcard pattern, got %+v", patterns)
	}

	// Exact key wins over patterns.
	limit, key, ok := resolveRouteLimit(exact, patterns, "/api/auth/login")
	if !ok || key != "/api/auth/login" || limit.Requests != 5 {
		t.Errorf("exact route resolution failed: %v %q %+v", ok, key, limit)
	}

	// Wildcard matches, and the counter key is the pattern — all matching
	// paths share one budget.
	limit, key, ok = resolveRouteLimit(exact, patterns, "/v1/payments/collect")
	if !ok || key != "/v1/*" || limit.Requests != 100 {
		t.Errorf("wildcard route resolution failed: %v %q %+v", ok, key, limit)
	}

	if _, _, ok := resolveRouteLimit(exact, patterns, "/other"); ok {
		t.Error("unrelated path should not resolve a route limit")
	}
}
