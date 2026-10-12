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
			"mysql driver without a DSN",
			Config{Storage: StorageConfig{Driver: MySQL}},
			IssueError, "Storage.DSN",
		},
		{
			"postgres driver without a DSN",
			Config{Storage: StorageConfig{Driver: Postgres}},
			IssueError, "Storage.DSN",
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
		{
			"anomaly detection without a user extractor",
			Config{Anomaly: AnomalyConfig{Enabled: true}},
			IssueError, "Anomaly.Enabled",
		},
		{
			"audit retention below the PCI-DSS minimum",
			Config{Storage: StorageConfig{AuditRetentionDays: 90}},
			IssueWarning, "Storage.AuditRetentionDays",
		},
		{
			"negative retention deletes everything",
			Config{Storage: StorageConfig{RetentionDays: -1}},
			IssueError, "Storage.RetentionDays",
		},
		{
			"in-memory storage",
			Config{Storage: StorageConfig{Driver: Memory}},
			IssueWarning, "Storage.Driver",
		},
		{
			"blocklist feed that is not a URL",
			Config{IPReputation: IPReputationConfig{Feeds: []string{"spamhaus-drop.txt"}}},
			IssueError, "IPReputation.Feeds",
		},
		{
			"auto-block without reputation checks",
			Config{IPReputation: IPReputationConfig{AutoBlock: true}},
			IssueWarning, "IPReputation.AutoBlock",
		},
		{
			"short audit HMAC key",
			Config{Storage: StorageConfig{AuditKey: "short"}},
			IssueWarning, "Storage.AuditKey",
		},
		{
			"unknown WAF mode acts as log mode",
			Config{WAF: WAFConfig{Mode: "Block"}},
			IssueError, "WAF.Mode",
		},
		{
			"unknown rule sensitivity",
			Config{WAF: WAFConfig{Rules: RuleSet{SQLInjection: "paranoid"}}},
			IssueError, "WAF.Rules",
		},
		{
			"custom rule with unknown action",
			Config{WAF: WAFConfig{CustomRules: []WAFRule{{ID: "act", Pattern: "x", Action: "drop"}}}},
			IssueError, `WAF.CustomRules["act"]`,
		},
		{
			"unknown rate limit strategy",
			Config{RateLimit: RateLimitConfig{Strategy: "leaky_bucket"}},
			IssueError, "RateLimit.Strategy",
		},
		{
			"deprecated AI daily summary",
			Config{AI: &AIConfig{Provider: Claude, APIKey: "sk-x", DailySummary: true}},
			IssueWarning, "AI.DailySummary",
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

// An allowlist entry written as a URL never matches a host, so legitimate
// redirects keep being reported — and an allowlist with the rule off does
// nothing at all.
func TestValidateConfigAllowedRedirectHosts(t *testing.T) {
	bad := ValidateConfig(Config{WAF: WAFConfig{
		Enabled:              true,
		Mode:                 ModeBlock,
		AllowedRedirectHosts: []string{"https://example.com", "*example.com", " "},
	}})
	for _, field := range []string{"WAF.AllowedRedirectHosts[0]", "WAF.AllowedRedirectHosts[1]"} {
		if !hasIssue(bad, IssueError, field) {
			t.Errorf("expected an error for %s", field)
		}
	}
	if !hasIssue(bad, IssueWarning, "WAF.AllowedRedirectHosts[2]") {
		t.Error("expected a warning for an empty entry")
	}

	off := ValidateConfig(Config{WAF: WAFConfig{
		Enabled:              true,
		Mode:                 ModeBlock,
		Rules:                RuleSet{OpenRedirect: RuleOff},
		AllowedRedirectHosts: []string{"example.com"},
	}})
	if !hasIssue(off, IssueWarning, "WAF.AllowedRedirectHosts") {
		t.Error("an allowlist with OpenRedirect off should warn that it does nothing")
	}

	good := ValidateConfig(Config{WAF: WAFConfig{
		Enabled:              true,
		Mode:                 ModeBlock,
		AllowedRedirectHosts: []string{"example.com", "*.apps.example.com"},
	}})
	for _, issue := range good {
		if strings.HasPrefix(issue.Field, "WAF.AllowedRedirectHosts") {
			t.Errorf("a valid allowlist should be clean, got %s", issue)
		}
	}
}

// Issue #35: ApplyDefaults used to give CAPTCHAThreshold a reachable value
// whether or not a provider existed, and ValidateConfig only complained
// about more than one provider — so the default state was a tier that reads
// as a defence and can never fire.
func TestValidateConfigCAPTCHATierNeedsAProvider(t *testing.T) {
	shield := AuthShieldConfig{Enabled: true, LoginRoute: "/api/login", MaxFailedAttempts: 5}

	// The default no longer invents a threshold without a provider.
	var zero Config
	zero.AuthShield = shield
	zero.ApplyDefaults()
	if zero.AuthShield.CAPTCHAThreshold != 0 {
		t.Errorf("with no CAPTCHA provider the threshold should stay 0, got %d", zero.AuthShield.CAPTCHAThreshold)
	}

	// With a provider the tier exists and gets its default.
	withProvider := Config{AuthShield: shield, CAPTCHA: CAPTCHAConfig{TurnstileSecret: "secret"}}
	withProvider.ApplyDefaults()
	if withProvider.AuthShield.CAPTCHAThreshold != 2 {
		t.Errorf("with a provider the threshold should default to 2, got %d", withProvider.AuthShield.CAPTCHAThreshold)
	}

	// Setting a threshold by hand with no provider is the trap ValidateConfig
	// has to name.
	manual := shield
	manual.CAPTCHAThreshold = 3
	issues := ValidateConfig(Config{AuthShield: manual})
	if !hasIssue(issues, IssueWarning, "AuthShield.CAPTCHAThreshold") {
		t.Error("a CAPTCHA threshold with no provider configured must warn")
	}
	if hasIssue(ValidateConfig(Config{AuthShield: manual, CAPTCHA: CAPTCHAConfig{HCaptchaSecret: "s"}}),
		IssueWarning, "AuthShield.CAPTCHAThreshold") {
		t.Error("with a provider configured the threshold must not warn")
	}
}

// Issue #36: the lockout key, the exempt list, and the throttle are all
// config that silently does nothing when it is wrong.
func TestValidateConfigAuthShieldLockout(t *testing.T) {
	base := AuthShieldConfig{Enabled: true, LoginRoute: "/api/login", MaxFailedAttempts: 5, LockoutDuration: 15 * time.Minute}

	bad := base
	bad.LockoutKey = "address"
	if !hasIssue(ValidateConfig(Config{AuthShield: bad}), IssueError, "AuthShield.LockoutKey") {
		t.Error("an unknown lockout key must be an error")
	}

	exempt := base
	exempt.ExemptIPs = []string{"10.0.0.0/8", "not-an-ip", ""}
	issues := ValidateConfig(Config{AuthShield: exempt})
	if !hasIssue(issues, IssueError, "AuthShield.ExemptIPs[1]") {
		t.Error("an exempt entry that is neither an IP nor a CIDR must be an error")
	}
	if !hasIssue(issues, IssueWarning, "AuthShield.ExemptIPs[2]") {
		t.Error("an empty exempt entry must warn")
	}
	if hasIssue(issues, IssueError, "AuthShield.ExemptIPs[0]") {
		t.Error("a valid CIDR must be accepted")
	}

	// Locking addresses with no exemptions is legal but collective.
	byIP := base
	byIP.LockoutKey = LockoutIP
	if !hasIssue(ValidateConfig(Config{AuthShield: byIP}), IssueWarning, "AuthShield.LockoutKey") {
		t.Error(`LockoutKey "ip" with no exemptions should warn about shared addresses`)
	}

	tooSmall := base
	tooSmall.AddressFailureBudget = 2
	if !hasIssue(ValidateConfig(Config{AuthShield: tooSmall}), IssueWarning, "AuthShield.AddressFailureBudget") {
		t.Error("a budget below MaxFailedAttempts should warn")
	}
}

// WAF.ExcludeIPs has always been documented as taking CIDR ranges, and
// entries were compared as exact strings, so a range excluded nothing.
func TestValidateConfigWAFExcludeIPs(t *testing.T) {
	issues := ValidateConfig(Config{WAF: WAFConfig{
		Enabled:    true,
		Mode:       ModeBlock,
		ExcludeIPs: []string{"10.0.0.0/8", "192.0.2.4", "10.0.0.0/33"},
	}})
	if !hasIssue(issues, IssueError, "WAF.ExcludeIPs[2]") {
		t.Error("a malformed CIDR must be an error")
	}
	for _, field := range []string{"WAF.ExcludeIPs[0]", "WAF.ExcludeIPs[1]"} {
		if hasIssue(issues, IssueError, field) {
			t.Errorf("%s is valid and must not be reported", field)
		}
	}
}
