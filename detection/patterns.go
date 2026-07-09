// Package detection provides threat detection patterns, classification,
// and confidence scoring for the Sentinel WAF engine.
package detection

import (
	"regexp"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// PatternDef defines a compiled detection pattern with metadata.
type PatternDef struct {
	// Name is a human-readable name for this pattern.
	Name string

	// Regex is the compiled regular expression.
	Regex *regexp.Regexp

	// ThreatType is the category of threat this pattern detects.
	ThreatType sentinel.ThreatType

	// BaseSeverity is the default severity for matches of this pattern.
	BaseSeverity sentinel.Severity

	// BaseConfidence is the default confidence score (0-100) for this pattern.
	BaseConfidence int

	// Locations restricts which request locations this pattern is evaluated
	// against: "path", "query", "header", "body". Empty means all locations.
	// Patterns for vulnerabilities that only exist in attacker-supplied URLs
	// or documents (SSRF, XXE, open redirect) must not scan high-cardinality
	// strings like User-Agent or Cookie — that is how "Chrome/140.0.0.0"
	// ends up classified as an SSRF attack (issue #8).
	Locations []string
}

// AppliesTo reports whether this pattern should be evaluated against input
// found at the given location.
func (p PatternDef) AppliesTo(location string) bool {
	if len(p.Locations) == 0 {
		return true
	}
	for _, l := range p.Locations {
		if l == location {
			return true
		}
	}
	return false
}

// Patterns contains all compiled detection patterns, organized by threat type.
// Patterns are compiled at package init time, not per-request.
var Patterns []PatternDef

func init() {
	Patterns = []PatternDef{
		// --- SQL Injection ---
		// SQL reaches the database through query parameters and bodies —
		// never through an opaque bearer cookie or a User-Agent string, so
		// SQLi patterns are scoped away from headers. Unscoped, the bare
		// "--" alternative matched inside base64url tokens: a ~400-char
		// cookie holding two JWTs contains "--" with probability ~9%, which
		// in ModeBlock 403'd roughly one session in ten at random (issue #10).
		{
			Name: "SQLi_Basic",
			// "--" only counts when it terminates a statement (followed by
			// whitespace or end of input), the way SQLi_Comment already
			// requires — never inside a hyphenated slug or token. "0x..."
			// must not start mid-word, so hex inside base64 text is ignored.
			Regex:          regexp.MustCompile(`(?i)(union\s+select|drop\s+table|insert\s+into|--(?:\s|$)|;--|'\s*or\s*'1'\s*=\s*'1|xp_cmdshell|exec\s*\(|cast\s*\(|convert\s*\(|char\s*\(|nchar\s*\(|varchar\s*\(|(?:^|\W)0x[0-9a-fA-F]{4,})`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
			Locations:      []string{"query", "body"},
		},
		{
			Name:           "SQLi_Blind",
			Regex:          regexp.MustCompile(`(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep|and\s+\d+\s*=\s*\d+|or\s+\d+\s*=\s*\d+)`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 75,
			Locations:      []string{"query", "body"},
		},
		{
			Name:           "SQLi_Comment",
			Regex:          regexp.MustCompile(`(?i)(/\*.*\*/|--\s|#\s*$)`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 50,
			Locations:      []string{"query", "body"},
		},
		{
			Name:           "SQLi_Stacked",
			Regex:          regexp.MustCompile(`(?i)(;\s*(select|insert|update|delete|drop|alter|create|exec|execute)\s)`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 85,
			Locations:      []string{"query", "body"},
		},

		// --- Cross-Site Scripting (XSS) ---
		// XSS is the one family that legitimately scans headers: an app that
		// reflects the Referer unescaped is exploitable through it, and
		// markup never occurs naturally in header values the way "--" or
		// dotted numbers do. Locations are still explicit — every pattern in
		// this set must declare where it applies, so a new pattern can't
		// silently inherit scan-everything (issue #10).
		{
			Name:           "XSS_Basic",
			Regex:          regexp.MustCompile(`(?i)(<script[^>]*>|javascript\s*:|vbscript\s*:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=|onblur\s*=|eval\s*\(|document\.cookie|document\.write|window\.location)`),
			ThreatType:     sentinel.ThreatXSS,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
			Locations:      []string{"path", "query", "header", "body"},
		},
		{
			Name:           "XSS_Encoded",
			Regex:          regexp.MustCompile(`(?i)(%3cscript|%3c%2fscript|&#x3[cC];script|&lt;script|%253cscript)`),
			ThreatType:     sentinel.ThreatXSS,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 85,
			Locations:      []string{"path", "query", "header", "body"},
		},
		{
			Name:           "XSS_SVG",
			Regex:          regexp.MustCompile(`(?i)(<svg[^>]*onload|<img[^>]*onerror|<iframe[^>]*src|<object[^>]*data|<embed[^>]*src)`),
			ThreatType:     sentinel.ThreatXSS,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 75,
			Locations:      []string{"path", "query", "header", "body"},
		},

		// --- Path Traversal ---
		{
			Name:           "PathTraversal",
			Regex:          regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f|%c0%ae%c0%ae|%uff0e%uff0e)`),
			ThreatType:     sentinel.ThreatPathTraversal,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 85,
			Locations:      []string{"path", "query", "body"},
		},

		// --- Command Injection ---
		{
			Name:           "CommandInject",
			Regex:          regexp.MustCompile("(?i)(;\\s*ls|;\\s*cat\\s|;\\s*whoami|;\\s*id\\b|;\\s*uname|\\|\\s*nc\\s|wget\\s+https?:|curl\\s+https?:|bash\\s+-[ic]|/etc/passwd|/etc/shadow|\\$\\(|`[^`]+`)"),
			ThreatType:     sentinel.ThreatCommandInjection,
			BaseSeverity:   sentinel.SeverityCritical,
			BaseConfidence: 85,
			Locations:      []string{"query", "body"},
		},

		// --- SSRF ---
		{
			Name: "SSRF",
			// Internal hosts must appear as a standalone token or URL host —
			// bounded by non-hostname characters — so they can never match
			// inside a longer dotted number. Unanchored, `0\.0\.0\.0` matches
			// inside "Chrome/140.0.0.0" and `10\.\d+\.\d+\.\d+` inside
			// "110.0.0.0", blocking every stable-channel browser (issue #8).
			// `::1` requires brackets for the same reason: the bare form
			// matches any string containing "::1".
			Regex:          regexp.MustCompile(`(?i)((?:^|[^\w.-])(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[::1\]|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^\w.-]|$)|file:\/\/|dict:\/\/|gopher:\/\/|ftp:\/\/[^.]*localhost)`),
			ThreatType:     sentinel.ThreatSSRF,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 70,
			Locations:      []string{"query", "body"},
		},

		// --- XXE ---
		{
			Name:           "XXE",
			Regex:          regexp.MustCompile(`(?i)(<!ENTITY|<!DOCTYPE[^>]*\[|SYSTEM\s+["']|PUBLIC\s+["']|%[a-z]+;)`),
			ThreatType:     sentinel.ThreatXXE,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
			Locations:      []string{"query", "body"},
		},

		// --- Local File Inclusion (LFI) ---
		{
			Name:           "LFI",
			Regex:          regexp.MustCompile(`(?i)(etc[/\\]passwd|etc[/\\]shadow|proc[/\\]self|var[/\\]log|windows[/\\]system32|boot\.ini|web\.config|\.htaccess|\.env)`),
			ThreatType:     sentinel.ThreatLFI,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
			Locations:      []string{"path", "query", "body"},
		},

		// --- Open Redirect ---
		{
			Name:           "OpenRedirect",
			Regex:          regexp.MustCompile(`(?i)(=\s*//[^/]|=\s*https?://|redirect.*=.*https?://|next.*=.*https?://|url.*=.*https?://|return.*=.*https?://|goto.*=.*https?://)`),
			ThreatType:     sentinel.ThreatOpenRedirect,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 60,
			// Referer headers routinely embed full URLs in their own query
			// strings ("?url=https://..."), so this must never scan headers.
			Locations:      []string{"query"},
		},

		// --- Prototype Pollution ---
		{
			Name:           "PrototypePollution",
			Regex:          regexp.MustCompile(`(?i)(__proto__|constructor\s*\[|prototype\s*\[)`),
			ThreatType:     sentinel.ThreatPrototypePollution,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 75,
			Locations:      []string{"query", "body"},
		},
	}
}
