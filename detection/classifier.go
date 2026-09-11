package detection

import (
	"net/url"
	"strings"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// ThreatMatch represents a single pattern match during classification.
type ThreatMatch struct {
	// PatternName is the name of the pattern that matched.
	PatternName string

	// ThreatType is the category of threat detected.
	ThreatType sentinel.ThreatType

	// Matched is the string that triggered the match.
	Matched string

	// Location is where the match was found (path, query, body, header).
	Location string

	// Parameter is the specific parameter name, if applicable.
	Parameter string

	// BaseSeverity is the severity from the pattern definition.
	BaseSeverity sentinel.Severity

	// BaseConfidence is the confidence from the pattern definition.
	BaseConfidence int

	// LogOnly marks a match from a custom rule with Action "log": recorded,
	// never enforced by the WAF mode.
	LogOnly bool
}

// ClassifyRequest scans all input vectors of a request and returns all matches.
func ClassifyRequest(req sentinel.InspectedRequest) []ThreatMatch {
	var matches []ThreatMatch

	// Scan URL path, and any percent-encoding left in it after the router
	// decoded it once.
	matches = append(matches, scanLayers(req.Path, "path", "", false)...)

	// Scan raw query string
	if req.RawQuery != "" {
		matches = append(matches, scanInput(req.RawQuery, "query", "")...)

		// Also scan individual query parameter names and values, decoded —
		// and decoded again where encoding is left over.
		params, _ := url.ParseQuery(req.RawQuery)
		for key, values := range params {
			matches = append(matches, scanLayers(key, "query", key, true)...)
			for _, val := range values {
				matches = append(matches, scanLayers(val, "query", key, true)...)
			}
		}
	}

	// Scan headers (only interesting ones, skip common harmless headers)
	interestingHeaders := map[string]bool{
		"referer":         true,
		"user-agent":      true,
		"cookie":          true,
		"x-forwarded-for": true,
		"content-type":    true,
		"origin":          true,
	}
	for name, values := range req.Headers {
		if !interestingHeaders[strings.ToLower(name)] {
			continue
		}
		for _, val := range values {
			matches = append(matches, scanInput(val, "header", name)...)
		}
	}

	// Scan body (first 10KB already truncated in InspectedRequest). Form
	// posts arrive percent-encoded, so the body's decoded layers count too.
	if req.Body != "" {
		matches = append(matches, scanLayers(req.Body, "body", "", true)...)
	}

	return matches
}

// scanLayers scans input and each further layer of percent-decoding in it
// (see decodedLayers).
func scanLayers(input, location, parameter string, plusAsSpace bool) []ThreatMatch {
	matches := scanInput(input, location, parameter)
	for _, layer := range decodedLayers(input, plusAsSpace) {
		matches = append(matches, scanInput(layer, location, parameter)...)
	}
	return matches
}

// scanInput checks a single string against all patterns that apply to the
// given location. Patterns scoped via Locations are skipped elsewhere — e.g.
// SSRF host patterns never run against User-Agent or Cookie values.
func scanInput(input, location, parameter string) []ThreatMatch {
	var matches []ThreatMatch
	for _, pattern := range Patterns {
		if !pattern.AppliesTo(location) {
			continue
		}
		loc := pattern.Regex.FindString(input)
		if loc != "" {
			matches = append(matches, ThreatMatch{
				PatternName:    pattern.Name,
				ThreatType:     pattern.ThreatType,
				Matched:        truncate(loc, 200),
				Location:       location,
				Parameter:      parameter,
				BaseSeverity:   pattern.BaseSeverity,
				BaseConfidence: pattern.BaseConfidence,
			})
		}
	}
	return matches
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
