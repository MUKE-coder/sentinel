package sentinel

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/middleware"
)

// IssueSeverity classifies a ConfigIssue.
type IssueSeverity string

const (
	// IssueError marks config that a feature will silently ignore or that
	// disables a security control — the entry compiles, reads as correct,
	// and does nothing. These are exactly the shapes behind issues #7, #8,
	// #10 and #12.
	IssueError IssueSeverity = "error"

	// IssueWarning marks config that works but is probably not what the
	// operator intended (unreachable tiers, shadowed providers, insecure
	// defaults).
	IssueWarning IssueSeverity = "warning"
)

// ConfigIssue is a single finding from ValidateConfig.
type ConfigIssue struct {
	Severity IssueSeverity `json:"severity"`
	Field    string        `json:"field"`
	Message  string        `json:"message"`
}

// String renders the issue as a single log-friendly line.
func (i ConfigIssue) String() string {
	return fmt.Sprintf("%s: %s: %s", i.Severity, i.Field, i.Message)
}

// RouteMatcher matches request paths against the pattern shapes accepted by
// WAFConfig.ExcludeRoutes and RateLimitConfig.ByRoute. Re-exported so
// downstream test suites can assert that concrete production paths are
// covered by their exclusion patterns without importing the middleware
// package.
type RouteMatcher = middleware.RouteMatcher

// NewRouteMatcher compiles route patterns — see middleware.NewRouteMatcher.
//
//	m := sentinel.NewRouteMatcher(cfg.WAF.ExcludeRoutes)
//	if !m.Matches("/v1/payments/collect") {
//	    t.Fatal("payments endpoint is not excluded from the WAF")
//	}
func NewRouteMatcher(patterns []string) *RouteMatcher {
	return middleware.NewRouteMatcher(patterns)
}

// ValidateRoutePattern reports whether a single route pattern is supported —
// see middleware.ValidateRoutePattern.
func ValidateRoutePattern(pattern string) error {
	return middleware.ValidateRoutePattern(pattern)
}

// ValidateConfig inspects a Config for entries that would be silently
// ignored or silently disable a feature at runtime. It never rejects a
// config — Mount accepts everything it always accepted — it only reports.
//
// Defaults are applied to a copy first, so validating sentinel.Config{}
// flags only genuinely risky defaults (the built-in dashboard credentials),
// not absent optional features.
//
// Mount and MountE run this automatically and log each finding. Call it
// yourself in a startup check or test to fail a deploy before it ships:
//
//	for _, issue := range sentinel.ValidateConfig(cfg) {
//	    if issue.Severity == sentinel.IssueError {
//	        log.Fatalf("sentinel config: %s", issue)
//	    }
//	}
//
// To assert that a concrete production path is actually covered by your
// exclusion patterns, use ValidateRoutePattern / NewRouteMatcher directly.
func ValidateConfig(config Config) []ConfigIssue {
	config.ApplyDefaults()
	var issues []ConfigIssue
	report := func(sev IssueSeverity, field, format string, args ...any) {
		issues = append(issues, ConfigIssue{Severity: sev, Field: field, Message: fmt.Sprintf(format, args...)})
	}

	// --- Storage ---
	switch config.Storage.Driver {
	case SQLite, Postgres, Memory:
	case MySQL:
		report(IssueError, "Storage.Driver",
			"the MySQL driver is not implemented — Mount silently falls back to in-memory storage and all security data is lost on restart; use sqlite or postgres")
	default:
		report(IssueError, "Storage.Driver",
			"unknown driver %q — Mount silently falls back to in-memory storage and all security data is lost on restart", config.Storage.Driver)
	}

	// --- Dashboard ---
	if config.Dashboard.Prefix != "" && !strings.HasPrefix(config.Dashboard.Prefix, "/") {
		report(IssueError, "Dashboard.Prefix",
			"%q does not start with \"/\" — routes will be registered under a malformed path", config.Dashboard.Prefix)
	}
	if config.Dashboard.Password == core.DefaultInsecurePassword {
		report(IssueWarning, "Dashboard.Password",
			"using the built-in default password — fine for local development; Mount refuses to start with it in release mode")
	}
	if config.Dashboard.SecretKey == core.DefaultInsecureSecretKey {
		report(IssueWarning, "Dashboard.SecretKey",
			"using the built-in default JWT secret — dashboard tokens are forgeable; Mount refuses to start with it in release mode")
	}

	// --- WAF ---
	for _, entry := range config.WAF.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, errPrefix := netip.ParsePrefix(entry); errPrefix != nil {
			if _, errAddr := netip.ParseAddr(entry); errAddr != nil {
				report(IssueError, "WAF.TrustedProxies",
					"%q is neither an IP nor a CIDR — the entry is silently dropped and requests from that proxy keep their proxy-assigned client IP", entry)
			}
		}
	}
	validateRoutePatterns(report, "WAF.ExcludeRoutes", config.WAF.ExcludeRoutes)
	validateCustomRules(report, config.WAF.CustomRules)

	// --- Rate limiting ---
	if config.RateLimit.Enabled {
		if config.RateLimit.ByIP == nil && config.RateLimit.ByUser == nil &&
			config.RateLimit.Global == nil && len(config.RateLimit.ByRoute) == 0 {
			report(IssueWarning, "RateLimit",
				"rate limiting is enabled but no limit is configured (ByIP, ByUser, ByRoute, Global all unset) — the middleware does nothing")
		}
		if config.RateLimit.ByUser != nil && config.RateLimit.UserIDExtractor == nil {
			report(IssueError, "RateLimit.ByUser",
				"a per-user limit is set but UserIDExtractor is nil — the limit never applies")
		}
	}
	validateLimit(report, "RateLimit.ByIP", config.RateLimit.ByIP)
	validateLimit(report, "RateLimit.ByUser", config.RateLimit.ByUser)
	validateLimit(report, "RateLimit.Global", config.RateLimit.Global)
	validateRoutePatterns(report, "RateLimit.ExcludeRoutes", config.RateLimit.ExcludeRoutes)
	for pattern, limit := range config.RateLimit.ByRoute {
		if err := middleware.ValidateRoutePattern(pattern); err != nil {
			report(IssueError, "RateLimit.ByRoute", "%v — the entry rate-limits nothing", err)
		}
		l := limit
		validateLimit(report, fmt.Sprintf("RateLimit.ByRoute[%q]", pattern), &l)
	}

	// --- AuthShield ---
	if config.AuthShield.Enabled {
		if config.AuthShield.LoginRoute == "" {
			report(IssueError, "AuthShield.LoginRoute",
				"AuthShield is enabled but LoginRoute is empty — no route is protected and brute-force protection does nothing")
		}
		if config.AuthShield.CAPTCHAThreshold >= config.AuthShield.MaxFailedAttempts && config.AuthShield.CAPTCHAThreshold > 0 {
			report(IssueWarning, "AuthShield.CAPTCHAThreshold",
				"CAPTCHAThreshold (%d) >= MaxFailedAttempts (%d) — the lockout always fires first and the CAPTCHA tier is unreachable",
				config.AuthShield.CAPTCHAThreshold, config.AuthShield.MaxFailedAttempts)
		}
	}

	// --- CAPTCHA ---
	captchaProviders := 0
	for _, secret := range []string{
		config.CAPTCHA.HCaptchaSecret, config.CAPTCHA.TurnstileSecret,
		config.CAPTCHA.RecaptchaSecret, config.CAPTCHA.SelfHostedSecret,
	} {
		if secret != "" {
			captchaProviders++
		}
	}
	if captchaProviders > 1 {
		report(IssueWarning, "CAPTCHA",
			"%d CAPTCHA providers configured — only the first by precedence is used (hCaptcha > Turnstile > reCAPTCHA > self-hosted)", captchaProviders)
	}

	// --- Alerts ---
	if config.Alerts.Slack != nil && config.Alerts.Slack.WebhookURL == "" {
		report(IssueError, "Alerts.Slack",
			"SlackConfig is set but WebhookURL is empty — the provider is silently skipped and no Slack alerts are sent")
	}
	if config.Alerts.Email != nil {
		if config.Alerts.Email.SMTPHost == "" {
			report(IssueError, "Alerts.Email",
				"EmailConfig is set but SMTPHost is empty — the provider is silently skipped and no email alerts are sent")
		} else if len(config.Alerts.Email.Recipients) == 0 {
			report(IssueError, "Alerts.Email",
				"EmailConfig has no Recipients — alerts are generated but delivered to nobody")
		}
	}
	if config.Alerts.Webhook != nil && config.Alerts.Webhook.URL == "" {
		report(IssueError, "Alerts.Webhook",
			"WebhookConfig is set but URL is empty — the provider is silently skipped and no webhook alerts are sent")
	}
	if config.Alerts.PagerDuty != nil && config.Alerts.PagerDuty.IntegrationKey == "" {
		report(IssueError, "Alerts.PagerDuty",
			"PagerDutyConfig is set but IntegrationKey is empty — the provider is silently skipped and nobody gets paged")
	}

	// --- AI ---
	if config.AI != nil {
		if config.AI.APIKey == "" {
			report(IssueError, "AI.APIKey",
				"AIConfig is set but APIKey is empty — the AI provider is silently disabled")
		}
		switch config.AI.Provider {
		case Claude, OpenAI, Gemini:
		default:
			report(IssueError, "AI.Provider",
				"unknown provider %q — the AI provider is silently disabled; use sentinel.Claude, sentinel.OpenAI, or sentinel.Gemini", config.AI.Provider)
		}
	}

	// --- IP reputation ---
	if config.IPReputation.Enabled && config.IPReputation.AbuseIPDBKey == "" {
		report(IssueError, "IPReputation.AbuseIPDBKey",
			"IP reputation is enabled but AbuseIPDBKey is empty — every reputation check silently returns nothing")
	}

	return issues
}

func validateRoutePatterns(report func(IssueSeverity, string, string, ...any), field string, patterns []string) {
	for _, p := range patterns {
		if err := middleware.ValidateRoutePattern(p); err != nil {
			report(IssueError, field, "%v — the entry matches nothing", err)
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(p), "/") {
			report(IssueWarning, field,
				"%q does not start with \"/\" — request paths always do, so this entry is unlikely to ever match", p)
		}
	}
}

func validateLimit(report func(IssueSeverity, string, string, ...any), field string, limit *Limit) {
	if limit == nil {
		return
	}
	if limit.Requests <= 0 {
		report(IssueError, field, "Requests is %d — every request over this dimension is rate-limited immediately", limit.Requests)
	}
	if limit.Window <= 0 {
		report(IssueError, field, "Window is %s — the counter resets on every request and the limit never triggers", limit.Window)
	}
}

func validateCustomRules(report func(IssueSeverity, string, string, ...any), rules []WAFRule) {
	validLocations := map[string]bool{"path": true, "query": true, "header": true, "body": true}
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		field := fmt.Sprintf("WAF.CustomRules[%q]", rule.ID)
		if rule.ID == "" {
			report(IssueWarning, "WAF.CustomRules", "a rule has an empty ID — rules are keyed by ID, so it can collide and cannot be deleted via the API")
		} else if seen[rule.ID] {
			report(IssueError, field, "duplicate rule ID — the later rule silently replaces the earlier one")
		}
		seen[rule.ID] = true

		if rule.Pattern == "" {
			report(IssueError, field, "empty Pattern compiles to a regex that matches every request — in block mode this takes down every route the WAF inspects")
		} else if _, err := regexp.Compile(rule.Pattern); err != nil {
			report(IssueError, field, "Pattern does not compile (%v) — the rule is silently dropped at mount", err)
		}

		for _, loc := range rule.AppliesTo {
			if !validLocations[loc] {
				report(IssueError, field,
					"AppliesTo location %q is not one of path/query/header/body — that location is silently never scanned", loc)
			}
		}
	}
}
