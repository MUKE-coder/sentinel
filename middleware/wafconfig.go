package middleware

import (
	"fmt"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// ValidWAFMode reports whether mode is one the WAF acts on. Any other value
// falls through to log mode, so a typo such as "Block" silently stops all
// blocking.
func ValidWAFMode(mode sentinel.WAFMode) bool {
	switch mode {
	case sentinel.ModeLog, sentinel.ModeBlock, sentinel.ModeChallenge:
		return true
	}
	return false
}

// ValidRuleSensitivity reports whether s is a sensitivity level. Empty is
// accepted and means strict.
func ValidRuleSensitivity(s sentinel.RuleSensitivity) bool {
	switch s {
	case "", sentinel.RuleOff, sentinel.RuleLow, sentinel.RuleMedium, sentinel.RuleStrict:
		return true
	}
	return false
}

// ValidateRuleSet reports the first RuleSet field that is not a sensitivity
// level. An unknown value is enforced as strict.
func ValidateRuleSet(rules sentinel.RuleSet) error {
	for _, f := range []struct {
		name  string
		value sentinel.RuleSensitivity
	}{
		{"SQLInjection", rules.SQLInjection},
		{"XSS", rules.XSS},
		{"PathTraversal", rules.PathTraversal},
		{"CommandInjection", rules.CommandInjection},
		{"SSRF", rules.SSRF},
		{"XXE", rules.XXE},
		{"LFI", rules.LFI},
		{"OpenRedirect", rules.OpenRedirect},
	} {
		if !ValidRuleSensitivity(f.value) {
			return fmt.Errorf("%s: unknown sensitivity %q (use off, low, medium, or strict)", f.name, f.value)
		}
	}
	return nil
}
