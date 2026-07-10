package sentinel

import (
	"strings"
	"testing"
	"time"
)

// hasIssue reports whether any issue touches the given field (prefix match,
// so "WAF.CustomRules" covers the per-rule fields) at the given severity.
func hasIssue(issues []ConfigIssue, severity IssueSeverity, fieldPrefix string) bool {
	for _, i := range issues {
		if i.Severity == severity && strings.HasPrefix(i.Field, fieldPrefix) {
			return true
		}
	}
	return false
}

func issueFields(issues []ConfigIssue) []string {
	out := make([]string, 0, len(issues))
	for _, i := range issues {
		out = append(out, string(i.Severity)+":"+i.Field)
	}
	return out
}

// A zero config must produce no errors — only the two insecure-default
// warnings. Anything more means ValidateConfig is too noisy to keep wired
// into Mount.
func TestValidateConfigZeroConfig(t *testing.T) {
	issues := ValidateConfig(Config{})
	for _, i := range issues {
		if i.Severity == IssueError {
			t.Errorf("zero config produced an error: %s", i)
		}
	}
	if !hasIssue(issues, IssueWarning, "Dashboard.Password") {
		t.Error("expected insecure-default password warning")
	}
	if !hasIssue(issues, IssueWarning, "Dashboard.SecretKey") {
		t.Error("expected insecure-default secret warning")
	}
}

// A fully-specified valid config must be completely clean.
func TestValidateConfigCleanConfig(t *testing.T) {
	cfg := Config{
		Dashboard: DashboardConfig{Password: "s3cret!", SecretKey: "jwt-secret"},
		Storage:   StorageConfig{Driver: Postgres, DSN: "postgres://..."},
		WAF: WAFConfig{
			Enabled:        true,
			Mode:           ModeBlock,
			TrustedProxies: []string{"10.0.0.0/8", "192.168.1.1"},
			ExcludeRoutes:  []string{"/health", "/v1/**", "/api/apps/*/products/**"},
			CustomRules: []WAFRule{
				{ID: "r1", Name: "block-admin", Pattern: `(?i)/wp-admin`, AppliesTo: []string{"path"}, Severity: SeverityHigh, Action: "block", Enabled: true},
			},
		},
		RateLimit: RateLimitConfig{
			Enabled: true,
			ByIP:    &Limit{Requests: 100, Window: time.Minute},
			ByRoute: map[string]Limit{"/api/auth/login": {Requests: 5, Window: 15 * time.Minute}},
		},
		AuthShield: AuthShieldConfig{Enabled: true, LoginRoute: "/api/auth/login"},
	}
	if issues := ValidateConfig(cfg); len(issues) != 0 {
		t.Errorf("clean config produced issues: %v", issueFields(issues))
	}
}

func TestValidateConfigCatchesSilentTraps(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		severity IssueSeverity
		field    string
	}{
		{
			"unknown storage driver falls back to memory",
			Config{Storage: StorageConfig{Driver: "postgress"}},
			IssueError, "Storage.Driver",
		},
		{
			"mysql driver not implemented",
			Config{Storage: StorageConfig{Driver: MySQL}},
			IssueError, "Storage.Driver",
		},
		{
			"malformed dashboard prefix",
			Config{Dashboard: DashboardConfig{Prefix: "sentinel"}},
			IssueError, "Dashboard.Prefix",
		},
		{
			"invalid trusted proxy silently dropped",
			Config{WAF: WAFConfig{TrustedProxies: []string{"not-an-ip"}}},
			IssueError, "WAF.TrustedProxies",
		},
		{
			"interior globstar in exclude route",
			Config{WAF: WAFConfig{ExcludeRoutes: []string{"/api/**/products"}}},
			IssueError, "WAF.ExcludeRoutes",
		},
		{
			"exclude route without leading slash",
			Config{WAF: WAFConfig{ExcludeRoutes: []string{"v1/*"}}},
			IssueWarning, "WAF.ExcludeRoutes",
		},
		{
			"custom rule with invalid regex",
			Config{WAF: WAFConfig{CustomRules: []WAFRule{{ID: "bad", Pattern: "([unclosed"}}}},
			IssueError, `WAF.CustomRules["bad"]`,
		},
		{
			"custom rule with empty pattern matches everything",
			Config{WAF: WAFConfig{CustomRules: []WAFRule{{ID: "empty", Pattern: ""}}}},
			IssueError, `WAF.CustomRules["empty"]`,
		},
		{
			"custom rule with unknown location",
			Config{WAF: WAFConfig{CustomRules: []WAFRule{{ID: "loc", Pattern: "x", AppliesTo: []string{"cookie"}}}}},
			IssueError, `WAF.CustomRules["loc"]`,
		},
		{
			"duplicate custom rule ids",
			Config{WAF: WAFConfig{CustomRules: []WAFRule{{ID: "dup", Pattern: "a"}, {ID: "dup", Pattern: "b"}}}},
			IssueError, `WAF.CustomRules["dup"]`,
		},
		{
			"rate limiting enabled with no limits",
			Config{RateLimit: RateLimitConfig{Enabled: true}},
			IssueWarning, "RateLimit",
		},
		{
			"per-user limit without extractor",
			Config{RateLimit: RateLimitConfig{Enabled: true, ByUser: &Limit{Requests: 10, Window: time.Minute}}},
			IssueError, "RateLimit.ByUser",
		},
		{
			"limit with zero window",
			Config{RateLimit: RateLimitConfig{Enabled: true, ByIP: &Limit{Requests: 10}}},
			IssueError, "RateLimit.ByIP",
		},
		{
			"wildcard byroute key that matches nothing",
			Config{RateLimit: RateLimitConfig{Enabled: true, ByRoute: map[string]Limit{"/v1/**/x": {Requests: 5, Window: time.Minute}}}},
			IssueError, "RateLimit.ByRoute",
		},
		{
			"authshield without login route",
			Config{AuthShield: AuthShieldConfig{Enabled: true}},
			IssueError, "AuthShield.LoginRoute",
		},
		{
			"captcha tier unreachable",
			Config{AuthShield: AuthShieldConfig{Enabled: true, LoginRoute: "/login", MaxFailedAttempts: 5, CAPTCHAThreshold: 5}},
			IssueWarning, "AuthShield.CAPTCHAThreshold",
		},
		{
			"multiple captcha providers",
			Config{CAPTCHA: CAPTCHAConfig{HCaptchaSecret: "a", TurnstileSecret: "b"}},
			IssueWarning, "CAPTCHA",
		},
		{
			"slack without webhook url",
			Config{Alerts: AlertConfig{Slack: &SlackConfig{}}},
			IssueError, "Alerts.Slack",
		},
		{
			"email without smtp host",
			Config{Alerts: AlertConfig{Email: &EmailConfig{Recipients: []string{"a@b.c"}}}},
			IssueError, "Alerts.Email",
		},
		{
			"email without recipients",
			Config{Alerts: AlertConfig{Email: &EmailConfig{SMTPHost: "smtp.example.com"}}},
			IssueError, "Alerts.Email",
		},
		{
			"webhook without url",
			Config{Alerts: AlertConfig{Webhook: &WebhookConfig{}}},
			IssueError, "Alerts.Webhook",
		},
		{
			"pagerduty without integration key",
			Config{Alerts: AlertConfig{PagerDuty: &PagerDutyConfig{}}},
			IssueError, "Alerts.PagerDuty",
		},
		{
			"ai without api key",
			Config{AI: &AIConfig{Provider: Claude}},
			IssueError, "AI.APIKey",
		},
		{
			"ai with unknown provider",
			Config{AI: &AIConfig{Provider: "chatgpt", APIKey: "sk-x"}},
			IssueError, "AI.Provider",
		},
		{
			"ip reputation without key",
			Config{IPReputation: IPReputationConfig{Enabled: true}},
			IssueError, "IPReputation.AbuseIPDBKey",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues := ValidateConfig(tc.cfg)
			if !hasIssue(issues, tc.severity, tc.field) {
				t.Errorf("expected %s on %s, got: %v", tc.severity, tc.field, issueFields(issues))
			}
		})
	}
}

// The re-exported matcher must support the downstream-test use case from
// issue #12: asserting concrete production paths against config patterns.
func TestNewRouteMatcherReexport(t *testing.T) {
	m := NewRouteMatcher([]string{"/api/apps/*/products/**"})
	if !m.Matches("/api/apps/13/products/9") {
		t.Error("re-exported matcher should match parameterised subtree")
	}
	if err := ValidateRoutePattern("/api/**/x"); err == nil {
		t.Error("re-exported ValidateRoutePattern should reject interior globstar")
	}
	if err := ValidateRoutePattern("/v1/**"); err != nil {
		t.Errorf("valid pattern rejected: %v", err)
	}
}
