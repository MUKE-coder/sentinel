package api

import (
	"strings"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// parseSeverity accepts a severity name in any case and returns its
// canonical form.
func parseSeverity(s string) (sentinel.Severity, bool) {
	for _, sev := range []sentinel.Severity{sentinel.SeverityLow, sentinel.SeverityMedium, sentinel.SeverityHigh, sentinel.SeverityCritical} {
		if strings.EqualFold(s, string(sev)) {
			return sev, true
		}
	}
	return "", false
}

// mergeRuleSet applies the non-empty fields of update onto base, so a request
// can change one category without restating — or resetting — the others.
func mergeRuleSet(base, update sentinel.RuleSet) sentinel.RuleSet {
	pick := func(current, next sentinel.RuleSensitivity) sentinel.RuleSensitivity {
		if next != "" {
			return next
		}
		return current
	}
	return sentinel.RuleSet{
		SQLInjection:     pick(base.SQLInjection, update.SQLInjection),
		XSS:              pick(base.XSS, update.XSS),
		PathTraversal:    pick(base.PathTraversal, update.PathTraversal),
		CommandInjection: pick(base.CommandInjection, update.CommandInjection),
		SSRF:             pick(base.SSRF, update.SSRF),
		XXE:              pick(base.XXE, update.XXE),
		LFI:              pick(base.LFI, update.LFI),
		OpenRedirect:     pick(base.OpenRedirect, update.OpenRedirect),
	}
}
