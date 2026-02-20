package detection

import (
	"net/url"
	"strings"

	sentinel "github.com/MUKE-coder/sentinel/core"
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
}

// ClassifyRequest scans all input vectors of a request and returns all matches.
func ClassifyRequest(req sentinel.InspectedRequest) []ThreatMatch {
	var matches []ThreatMatch

	// Scan URL path
	matches = append(matches, scanInput(req.Path, "path", "")...)

	// Scan raw query string
	if req.RawQuery != "" {
		matches = append(matches, scanInput(req.RawQuery, "query", "")...)

		// Also scan individual query parameter values
		params, _ := url.ParseQuery(req.RawQuery)
		for key, values := range params {
			for _, val := range values {
				matches = append(matches, scanInput(val, "query", key)...)
			}
		}
	}

	// Scan headers (only interesting ones, skip common harmless headers)
	interestingHeaders := map[string]bool{
		"referer":       true,
		"user-agent":    true,
		"cookie":        true,
		"x-forwarded-for": true,
		"content-type":  true,
		"origin":        true,
	}
	for name, values := range req.Headers {
		if !interestingHeaders[strings.ToLower(name)] {
			continue
		}
		for _, val := range values {
			matches = append(matches, scanInput(val, "header", name)...)
		}
	}

	// Scan body (first 10KB already truncated in InspectedRequest)
	if req.Body != "" {
		matches = append(matches, scanInput(req.Body, "body", "")...)
	}

	return matches
}

// scanInput checks a single string against all patterns.
func scanInput(input, location, parameter string) []ThreatMatch {
	var matches []ThreatMatch
	for _, pattern := range Patterns {
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
