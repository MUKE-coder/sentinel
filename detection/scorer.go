package detection

import (
	sentinel "github.com/MUKE-coder/sentinel/core"
)

// ScoreThreats analyzes a set of threat matches and returns
// the overall severity and confidence score.
func ScoreThreats(matches []ThreatMatch) (sentinel.Severity, int) {
	if len(matches) == 0 {
		return "", 0
	}

	// Track unique threat types and their max confidence
	typeMaxConf := make(map[sentinel.ThreatType]int)
	maxSeverity := sentinel.SeverityLow
	totalConfidence := 0

	for _, m := range matches {
		if severityLevel(m.BaseSeverity) > severityLevel(maxSeverity) {
			maxSeverity = m.BaseSeverity
		}
		if m.BaseConfidence > typeMaxConf[m.ThreatType] {
			typeMaxConf[m.ThreatType] = m.BaseConfidence
		}
		totalConfidence += m.BaseConfidence
	}

	// Multiple matches of the same type increase confidence
	avgConfidence := totalConfidence / len(matches)
	confidence := avgConfidence

	// Boost confidence for multiple matches
	if len(matches) > 1 {
		confidence += len(matches) * 3
	}

	// Multiple different threat types increase severity
	uniqueTypes := len(typeMaxConf)
	if uniqueTypes >= 3 {
		maxSeverity = sentinel.SeverityCritical
		confidence += 15
	} else if uniqueTypes >= 2 {
		if severityLevel(maxSeverity) < severityLevel(sentinel.SeverityHigh) {
			maxSeverity = sentinel.SeverityHigh
		}
		confidence += 10
	}

	// Certain critical combos auto-elevate
	_, hasSQLi := typeMaxConf[sentinel.ThreatSQLi]
	_, hasCmdInj := typeMaxConf[sentinel.ThreatCommandInjection]
	if hasSQLi && hasCmdInj {
		maxSeverity = sentinel.SeverityCritical
		confidence += 20
	}

	// Cap confidence at 100
	if confidence > 100 {
		confidence = 100
	}

	return maxSeverity, confidence
}

// MatchesToEvidence converts threat matches to evidence entries for storage.
func MatchesToEvidence(matches []ThreatMatch) []sentinel.Evidence {
	evidence := make([]sentinel.Evidence, 0, len(matches))
	for _, m := range matches {
		evidence = append(evidence, sentinel.Evidence{
			Pattern:   m.PatternName,
			Matched:   m.Matched,
			Location:  m.Location,
			Parameter: m.Parameter,
		})
	}
	return evidence
}

// MatchesToThreatTypes extracts unique threat type strings from matches.
func MatchesToThreatTypes(matches []ThreatMatch) []string {
	seen := make(map[sentinel.ThreatType]bool)
	var types []string
	for _, m := range matches {
		if !seen[m.ThreatType] {
			seen[m.ThreatType] = true
			types = append(types, string(m.ThreatType))
		}
	}
	return types
}

func severityLevel(s sentinel.Severity) int {
	switch s {
	case sentinel.SeverityLow:
		return 1
	case sentinel.SeverityMedium:
		return 2
	case sentinel.SeverityHigh:
		return 3
	case sentinel.SeverityCritical:
		return 4
	default:
		return 0
	}
}
