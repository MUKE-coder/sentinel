package detection

import (
	"regexp"
	"sync"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// CompiledRule is a custom WAF rule with a compiled regex.
type CompiledRule struct {
	Rule  sentinel.WAFRule
	Regex *regexp.Regexp
}

// CustomRuleEngine manages custom WAF rules that can be added/removed at runtime.
type CustomRuleEngine struct {
	mu    sync.RWMutex
	rules map[string]*CompiledRule // keyed by rule ID
}

// NewCustomRuleEngine creates a new custom rule engine with optional initial rules.
func NewCustomRuleEngine(initial []sentinel.WAFRule) *CustomRuleEngine {
	e := &CustomRuleEngine{
		rules: make(map[string]*CompiledRule),
	}
	for _, r := range initial {
		e.AddRule(r) // ignore errors on init
	}
	return e
}

// AddRule compiles and adds a custom rule. Returns error if regex is invalid.
func (e *CustomRuleEngine) AddRule(rule sentinel.WAFRule) error {
	compiled, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules[rule.ID] = &CompiledRule{Rule: rule, Regex: compiled}
	return nil
}

// RemoveRule removes a custom rule by ID.
func (e *CustomRuleEngine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, exists := e.rules[id]
	delete(e.rules, id)
	return exists
}

// ListRules returns all custom rules.
func (e *CustomRuleEngine) ListRules() []sentinel.WAFRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]sentinel.WAFRule, 0, len(e.rules))
	for _, cr := range e.rules {
		result = append(result, cr.Rule)
	}
	return result
}

// GetRule returns a single custom rule by ID.
func (e *CustomRuleEngine) GetRule(id string) (sentinel.WAFRule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cr, ok := e.rules[id]
	if !ok {
		return sentinel.WAFRule{}, false
	}
	return cr.Rule, true
}

// ClassifyRequest scans a request against all enabled custom rules.
func (e *CustomRuleEngine) ClassifyRequest(req sentinel.InspectedRequest) []ThreatMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []ThreatMatch
	for _, cr := range e.rules {
		if !cr.Rule.Enabled {
			continue
		}
		matches = append(matches, e.scanRule(cr, req)...)
	}
	return matches
}

// TestPayload tests a string against all enabled custom rules and built-in patterns.
func (e *CustomRuleEngine) TestPayload(payload string) []ThreatMatch {
	req := sentinel.InspectedRequest{
		Path:     payload,
		RawQuery: payload,
		Body:     payload,
	}

	// Check built-in patterns
	builtinMatches := ClassifyRequest(req)

	// Check custom rules
	customMatches := e.ClassifyRequest(req)

	return append(builtinMatches, customMatches...)
}

func (e *CustomRuleEngine) scanRule(cr *CompiledRule, req sentinel.InspectedRequest) []ThreatMatch {
	var matches []ThreatMatch
	appliesTo := make(map[string]bool)
	for _, a := range cr.Rule.AppliesTo {
		appliesTo[a] = true
	}

	// If AppliesTo is empty, check everything
	checkAll := len(appliesTo) == 0

	if checkAll || appliesTo["path"] {
		if m := cr.Regex.FindString(req.Path); m != "" {
			matches = append(matches, ThreatMatch{
				PatternName:    cr.Rule.Name,
				ThreatType:     sentinel.ThreatType("CustomRule"),
				Matched:        truncate(m, 200),
				Location:       "path",
				BaseSeverity:   cr.Rule.Severity,
				BaseConfidence: 85,
			})
		}
	}

	if checkAll || appliesTo["query"] {
		if req.RawQuery != "" {
			if m := cr.Regex.FindString(req.RawQuery); m != "" {
				matches = append(matches, ThreatMatch{
					PatternName:    cr.Rule.Name,
					ThreatType:     sentinel.ThreatType("CustomRule"),
					Matched:        truncate(m, 200),
					Location:       "query",
					BaseSeverity:   cr.Rule.Severity,
					BaseConfidence: 85,
				})
			}
		}
	}

	if checkAll || appliesTo["header"] {
		for _, values := range req.Headers {
			for _, val := range values {
				if m := cr.Regex.FindString(val); m != "" {
					matches = append(matches, ThreatMatch{
						PatternName:    cr.Rule.Name,
						ThreatType:     sentinel.ThreatType("CustomRule"),
						Matched:        truncate(m, 200),
						Location:       "header",
						BaseSeverity:   cr.Rule.Severity,
						BaseConfidence: 85,
					})
				}
			}
		}
	}

	if checkAll || appliesTo["body"] {
		if req.Body != "" {
			if m := cr.Regex.FindString(req.Body); m != "" {
				matches = append(matches, ThreatMatch{
					PatternName:    cr.Rule.Name,
					ThreatType:     sentinel.ThreatType("CustomRule"),
					Matched:        truncate(m, 200),
					Location:       "body",
					BaseSeverity:   cr.Rule.Severity,
					BaseConfidence: 85,
				})
			}
		}
	}

	return matches
}
