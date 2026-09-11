package detection

import sentinel "github.com/MUKE-coder/sentinel/v2/core"

// Pattern confidence floors for each sensitivity level. The built-in
// patterns carry confidences from 50 (SQLi_Comment) to 85: "low" keeps only
// the most precise patterns, "medium" drops the noisiest, "strict" keeps
// every one. The default RuleSet (strict everywhere, medium for SSRF and
// open redirect) keeps every pattern the WAF ran before sensitivity was
// enforced.
const (
	lowMinConfidence    = 80
	mediumMinConfidence = 60
)

// Custom rule actions. "block" (or empty) lets the WAF mode decide what
// happens to a matching request; "log" records the match but never blocks.
const (
	RuleActionBlock = "block"
	RuleActionLog   = "log"
)

// ValidRuleAction reports whether action is a custom rule action Sentinel
// understands. Any other value is enforced as if it were "block".
func ValidRuleAction(action string) bool {
	return action == "" || action == RuleActionBlock || action == RuleActionLog
}

// ApplySensitivity drops built-in matches that the per-category sensitivity
// in rules excludes: every match for a category set to "off", and matches
// from patterns whose confidence is below the level's floor. Custom-rule
// matches and threat types without a RuleSet entry pass through unchanged.
// An empty sensitivity means strict.
func ApplySensitivity(matches []ThreatMatch, rules sentinel.RuleSet) []ThreatMatch {
	kept := make([]ThreatMatch, 0, len(matches))
	for _, m := range matches {
		level, ok := sensitivityFor(m.ThreatType, rules)
		if !ok || keptAt(level, m.BaseConfidence) {
			kept = append(kept, m)
		}
	}
	return kept
}

// AnyEnforced reports whether any match should be enforced by the WAF mode.
// It is false when every match came from a custom rule with Action "log".
func AnyEnforced(matches []ThreatMatch) bool {
	for _, m := range matches {
		if !m.LogOnly {
			return true
		}
	}
	return false
}

func keptAt(level sentinel.RuleSensitivity, confidence int) bool {
	switch level {
	case sentinel.RuleOff:
		return false
	case sentinel.RuleLow:
		return confidence >= lowMinConfidence
	case sentinel.RuleMedium:
		return confidence >= mediumMinConfidence
	default: // strict, or unset
		return true
	}
}

func sensitivityFor(t sentinel.ThreatType, rules sentinel.RuleSet) (sentinel.RuleSensitivity, bool) {
	switch t {
	case sentinel.ThreatSQLi:
		return rules.SQLInjection, true
	case sentinel.ThreatXSS:
		return rules.XSS, true
	case sentinel.ThreatPathTraversal:
		return rules.PathTraversal, true
	case sentinel.ThreatCommandInjection:
		return rules.CommandInjection, true
	case sentinel.ThreatSSRF:
		return rules.SSRF, true
	case sentinel.ThreatXXE:
		return rules.XXE, true
	case sentinel.ThreatLFI:
		return rules.LFI, true
	case sentinel.ThreatOpenRedirect:
		return rules.OpenRedirect, true
	}
	return "", false
}
