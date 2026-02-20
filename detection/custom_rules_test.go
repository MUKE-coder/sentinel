package detection_test

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/detection"
)

func TestCustomRuleEngine_AddAndMatch(t *testing.T) {
	engine := detection.NewCustomRuleEngine(nil)

	rule := sentinel.WAFRule{
		ID:        "rule-1",
		Name:      "Block admin endpoint",
		Pattern:   `(?i)/admin/secret`,
		AppliesTo: []string{"path"},
		Severity:  sentinel.SeverityCritical,
		Action:    "block",
		Enabled:   true,
	}

	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	req := sentinel.InspectedRequest{
		Path: "/admin/secret/page",
	}

	matches := engine.ClassifyRequest(req)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].PatternName != "Block admin endpoint" {
		t.Errorf("expected pattern name 'Block admin endpoint', got '%s'", matches[0].PatternName)
	}
	if matches[0].Location != "path" {
		t.Errorf("expected location 'path', got '%s'", matches[0].Location)
	}
}

func TestCustomRuleEngine_DisabledRule(t *testing.T) {
	engine := detection.NewCustomRuleEngine(nil)

	rule := sentinel.WAFRule{
		ID:      "rule-2",
		Name:    "Disabled rule",
		Pattern: `test`,
		Enabled: false,
	}
	engine.AddRule(rule)

	req := sentinel.InspectedRequest{
		Path: "/test",
	}

	matches := engine.ClassifyRequest(req)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for disabled rule, got %d", len(matches))
	}
}

func TestCustomRuleEngine_RemoveRule(t *testing.T) {
	engine := detection.NewCustomRuleEngine(nil)

	engine.AddRule(sentinel.WAFRule{
		ID:      "rule-3",
		Name:    "Temp rule",
		Pattern: `danger`,
		Enabled: true,
	})

	if len(engine.ListRules()) != 1 {
		t.Fatal("expected 1 rule")
	}

	if !engine.RemoveRule("rule-3") {
		t.Error("expected RemoveRule to return true")
	}

	if len(engine.ListRules()) != 0 {
		t.Error("expected 0 rules after removal")
	}

	if engine.RemoveRule("nonexistent") {
		t.Error("expected RemoveRule to return false for nonexistent rule")
	}
}

func TestCustomRuleEngine_InvalidRegex(t *testing.T) {
	engine := detection.NewCustomRuleEngine(nil)

	err := engine.AddRule(sentinel.WAFRule{
		ID:      "bad",
		Name:    "Bad regex",
		Pattern: `(?P<invalid`,
		Enabled: true,
	})

	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestCustomRuleEngine_TestPayload(t *testing.T) {
	engine := detection.NewCustomRuleEngine(nil)

	engine.AddRule(sentinel.WAFRule{
		ID:      "rule-4",
		Name:    "Block eval",
		Pattern: `eval\s*\(`,
		Enabled: true,
	})

	// Test a payload that matches both built-in XSS and custom rule
	matches := engine.TestPayload("eval('alert(1)')")
	if len(matches) == 0 {
		t.Error("expected at least 1 match for eval payload")
	}

	// Check that at least the custom rule matched
	found := false
	for _, m := range matches {
		if m.PatternName == "Block eval" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected custom rule 'Block eval' to match")
	}
}

func TestCustomRuleEngine_InitialRules(t *testing.T) {
	initial := []sentinel.WAFRule{
		{ID: "init-1", Name: "Rule A", Pattern: `foo`, Enabled: true},
		{ID: "init-2", Name: "Rule B", Pattern: `bar`, Enabled: true},
	}

	engine := detection.NewCustomRuleEngine(initial)
	rules := engine.ListRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 initial rules, got %d", len(rules))
	}
}

func TestCustomRuleEngine_AppliesTo(t *testing.T) {
	engine := detection.NewCustomRuleEngine(nil)

	// Rule that only applies to body
	engine.AddRule(sentinel.WAFRule{
		ID:        "body-only",
		Name:      "Body only rule",
		Pattern:   `secret_token`,
		AppliesTo: []string{"body"},
		Enabled:   true,
	})

	// Match in path should NOT trigger
	reqPath := sentinel.InspectedRequest{Path: "/secret_token"}
	if len(engine.ClassifyRequest(reqPath)) != 0 {
		t.Error("expected no match for path when rule only applies to body")
	}

	// Match in body SHOULD trigger
	reqBody := sentinel.InspectedRequest{Body: "data=secret_token"}
	if len(engine.ClassifyRequest(reqBody)) != 1 {
		t.Error("expected 1 match for body")
	}
}
