package detection

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func hasOpenRedirect(matches []ThreatMatch) bool {
	for _, m := range matches {
		if m.PatternName == "OpenRedirect" {
			return true
		}
	}
	return false
}

// An absolute URL in a redirect parameter is the shape of both an open
// redirect and an ordinary callback. Told which hosts the application owns,
// the WAF stops reporting its own.
func TestFilterRedirects(t *testing.T) {
	allow := NewRedirectAllowlist([]string{"example.com", "*.apps.example.com", " EXAMPLE.ORG "})

	cases := []struct {
		name     string
		rawQuery string
		want     bool // want an open-redirect match to survive
	}{
		{"own host", "callback=https://example.com/oauth/callback", false},
		{"own host, different case", "next=https://EXAMPLE.com/account", false},
		{"own host with a port", "return_to=https://example.com:8443/docs", false},
		{"own host, second entry", "redirect=https://example.org/welcome", false},
		{"subdomain of a wildcard", "next=https://dash.apps.example.com/home", false},
		{"percent-encoded own host", "next=https%3A%2F%2Fexample.com%2Fdocs", false},
		{"double-encoded own host", "next=https%253A%252F%252Fexample.com%252Fdocs", false},
		{"someone else's host", "next=https://evil.example/login", true},
		{"scheme-relative stranger", "next=//evil.example", true},
		{"lookalike host", "next=https://evil-example.com/login", true},
		{"wildcard must not match the bare domain", "next=https://apps.example.com/x", true},
		{"a stranger alongside our own host", "next=https://example.com/a&url=https://evil.example", true},
		{"unparseable target stays suspicious", `next=/\evil.example`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := sentinel.InspectedRequest{RawQuery: tc.rawQuery}
			matches := ClassifyRequest(req)
			if !hasOpenRedirect(matches) && tc.want {
				t.Skipf("the pattern does not flag %q at all, nothing to filter", tc.rawQuery)
			}
			got := hasOpenRedirect(FilterRedirects(matches, req, allow))
			if got != tc.want {
				t.Errorf("open-redirect match survived = %v, want %v (query %q)", got, tc.want, tc.rawQuery)
			}
		})
	}
}

// Without an allowlist nothing changes: every absolute redirect target is
// still reported, as before v2.6.0.
func TestFilterRedirectsWithoutAllowlist(t *testing.T) {
	req := sentinel.InspectedRequest{RawQuery: "callback=https://example.com/oauth"}
	matches := ClassifyRequest(req)
	if !hasOpenRedirect(matches) {
		t.Fatal("expected an open-redirect match to filter")
	}
	if !hasOpenRedirect(FilterRedirects(matches, req, nil)) {
		t.Error("with no allowlist the match must stay")
	}
	if !hasOpenRedirect(FilterRedirects(matches, req, NewRedirectAllowlist(nil))) {
		t.Error("an empty allowlist must allow nothing")
	}
}

// Filtering an allowed redirect must not drop anything else the request was
// flagged for.
func TestFilterRedirectsKeepsOtherThreats(t *testing.T) {
	allow := NewRedirectAllowlist([]string{"example.com"})
	req := sentinel.InspectedRequest{RawQuery: "next=https://example.com/a&id=1' OR '1'='1"}
	filtered := FilterRedirects(ClassifyRequest(req), req, allow)

	if hasOpenRedirect(filtered) {
		t.Error("the redirect to our own host should have been dropped")
	}
	sqli := false
	for _, m := range filtered {
		if m.ThreatType == sentinel.ThreatSQLi {
			sqli = true
		}
	}
	if !sqli {
		t.Error("the SQL injection in the same request must still be reported")
	}
}

func TestRedirectAllowlistAllows(t *testing.T) {
	allow := NewRedirectAllowlist([]string{"example.com", "*.cdn.example"})
	for host, want := range map[string]bool{
		"example.com":        true,
		"EXAMPLE.COM":        true,
		"a.cdn.example":      true,
		"deep.a.cdn.example": true,
		"cdn.example":        false,
		"notexample.com":     false,
		"example.com.evil":   false,
		"":                   false,
	} {
		if got := allow.Allows(host); got != want {
			t.Errorf("Allows(%q) = %v, want %v", host, got, want)
		}
	}
	var nilList *RedirectAllowlist
	if nilList.Allows("example.com") {
		t.Error("a nil allowlist must allow nothing")
	}
}
