package core

import "time"

// LiveSettings is the set of settings the dashboard can change while the
// application runs: the WAF's mode and sensitivity, its custom rules, the
// per-route rate limits, and the alert threshold.
//
// Before v2.6.0 a change applied to the process that served the request and
// nowhere else. It was lost on the next restart, and behind more than one
// replica the dashboard showed one value while the other replicas went on
// enforcing another. A stored document fixes both: each replica applies it
// and polls for newer revisions.
//
// A document is a complete snapshot, not a patch. It is written from the
// running state after a change, so an empty RouteLimits means "no route
// limits", not "unchanged". Stored settings win over the values in Config,
// so a dashboard change survives a deploy; DELETE /api/settings/live
// discards them and restores what Config says.
type LiveSettings struct {
	// Revision increases with every save. A replica applies a stored
	// document only when its revision is newer than the one it last applied.
	Revision int64 `json:"revision"`

	UpdatedAt time.Time `json:"updated_at"`

	// UpdatedBy is the dashboard user who made the change.
	UpdatedBy string `json:"updated_by,omitempty"`

	WAFMode  WAFMode `json:"waf_mode,omitempty"`
	WAFRules RuleSet `json:"waf_rules,omitempty"`

	// CustomRules replaces the running custom rule set.
	CustomRules []WAFRule `json:"custom_rules"`

	// RouteLimits replaces the running RateLimit.ByRoute table.
	RouteLimits map[string]Limit `json:"route_limits"`

	AlertMinSeverity Severity `json:"alert_min_severity,omitempty"`
}

// Clone returns a copy that shares no map or slice with s, so a stored
// document can't be mutated through a value handed to a caller.
func (s *LiveSettings) Clone() *LiveSettings {
	if s == nil {
		return nil
	}
	out := *s
	if s.CustomRules != nil {
		out.CustomRules = make([]WAFRule, len(s.CustomRules))
		copy(out.CustomRules, s.CustomRules)
	}
	if s.RouteLimits != nil {
		out.RouteLimits = make(map[string]Limit, len(s.RouteLimits))
		for k, v := range s.RouteLimits {
			out.RouteLimits[k] = v
		}
	}
	return &out
}
