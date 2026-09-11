package detection

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func match(t sentinel.ThreatType, confidence int) ThreatMatch {
	return ThreatMatch{ThreatType: t, BaseConfidence: confidence}
}

func TestApplySensitivity_Levels(t *testing.T) {
	matches := []ThreatMatch{
		match(sentinel.ThreatSQLi, 85), // SQLi_Stacked
		match(sentinel.ThreatSQLi, 75), // SQLi_Blind
		match(sentinel.ThreatSQLi, 50), // SQLi_Comment
		match("CustomRule", 85),
		match(sentinel.ThreatPrototypePollution, 75), // no RuleSet entry
	}

	cases := []struct {
		level sentinel.RuleSensitivity
		want  int // matches kept, including the two that are never filtered
	}{
		{sentinel.RuleOff, 2},
		{sentinel.RuleLow, 3},
		{sentinel.RuleMedium, 4},
		{sentinel.RuleStrict, 5},
		{"", 5}, // unset means strict
	}
	for _, tc := range cases {
		got := ApplySensitivity(matches, sentinel.RuleSet{SQLInjection: tc.level})
		if len(got) != tc.want {
			t.Errorf("SQLInjection=%q: kept %d matches, want %d", tc.level, len(got), tc.want)
		}
	}
}

// TestApplySensitivity_DefaultsKeepEveryPattern pins the compatibility
// promise: enforcing WAF.Rules must not silently switch off a pattern the
// WAF ran under the default config before v2.3.0.
func TestApplySensitivity_DefaultsKeepEveryPattern(t *testing.T) {
	var cfg sentinel.Config
	cfg.ApplyDefaults()

	var matches []ThreatMatch
	for _, p := range Patterns {
		matches = append(matches, ThreatMatch{PatternName: p.Name, ThreatType: p.ThreatType, BaseConfidence: p.BaseConfidence})
	}
	kept := ApplySensitivity(matches, cfg.WAF.Rules)
	if len(kept) != len(matches) {
		keptNames := map[string]bool{}
		for _, m := range kept {
			keptNames[m.PatternName] = true
		}
		for _, m := range matches {
			if !keptNames[m.PatternName] {
				t.Errorf("default RuleSet drops pattern %s (confidence %d)", m.PatternName, m.BaseConfidence)
			}
		}
	}
}

func TestCustomRule_LogOnlyAction(t *testing.T) {
	e := NewCustomRuleEngine([]sentinel.WAFRule{
		{ID: "watch", Name: "watch-admin", Pattern: `/wp-admin`, AppliesTo: []string{"path"}, Action: RuleActionLog, Enabled: true},
		{ID: "enforce", Name: "block-env", Pattern: `/\.env`, AppliesTo: []string{"path"}, Action: RuleActionBlock, Enabled: true},
	})

	logOnly := e.ClassifyRequest(sentinel.InspectedRequest{Path: "/wp-admin"})
	if len(logOnly) != 1 || !logOnly[0].LogOnly || AnyEnforced(logOnly) {
		t.Errorf("a log-action rule must produce a log-only match, got %+v", logOnly)
	}
	enforced := e.ClassifyRequest(sentinel.InspectedRequest{Path: "/.env"})
	if len(enforced) != 1 || enforced[0].LogOnly || !AnyEnforced(enforced) {
		t.Errorf("a block-action rule must be enforced, got %+v", enforced)
	}
	if !AnyEnforced(append(logOnly, enforced...)) {
		t.Error("a mix of log-only and enforced matches must be enforced")
	}
}

func TestValidRuleAction(t *testing.T) {
	for _, a := range []string{"", "block", "log"} {
		if !ValidRuleAction(a) {
			t.Errorf("%q should be valid", a)
		}
	}
	for _, a := range []string{"Block", "challenge", "drop"} {
		if ValidRuleAction(a) {
			t.Errorf("%q should be invalid", a)
		}
	}
}
