// Package detection provides threat detection patterns, classification,
// and confidence scoring for the Sentinel WAF engine.
package detection

import (
	"regexp"

	sentinel "github.com/MUKE-coder/sentinel/core"
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
}

// Patterns contains all compiled detection patterns, organized by threat type.
// Patterns are compiled at package init time, not per-request.
var Patterns []PatternDef

func init() {
	Patterns = []PatternDef{
		// --- SQL Injection ---
		{
			Name:           "SQLi_Basic",
			Regex:          regexp.MustCompile(`(?i)(union\s+select|drop\s+table|insert\s+into|--|;--|'\s*or\s*'1'\s*=\s*'1|xp_cmdshell|exec\s*\(|cast\s*\(|convert\s*\(|char\s*\(|nchar\s*\(|varchar\s*\(|0x[0-9a-fA-F]{4,})`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
		},
		{
			Name:           "SQLi_Blind",
			Regex:          regexp.MustCompile(`(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep|and\s+\d+\s*=\s*\d+|or\s+\d+\s*=\s*\d+)`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 75,
		},
		{
			Name:           "SQLi_Comment",
			Regex:          regexp.MustCompile(`(?i)(/\*.*\*/|--\s|#\s*$)`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 50,
		},
		{
			Name:           "SQLi_Stacked",
			Regex:          regexp.MustCompile(`(?i)(;\s*(select|insert|update|delete|drop|alter|create|exec|execute)\s)`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 85,
		},

		// --- Cross-Site Scripting (XSS) ---
		{
			Name:           "XSS_Basic",
			Regex:          regexp.MustCompile(`(?i)(<script[^>]*>|javascript\s*:|vbscript\s*:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=|onblur\s*=|eval\s*\(|document\.cookie|document\.write|window\.location)`),
			ThreatType:     sentinel.ThreatXSS,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
		},
		{
			Name:           "XSS_Encoded",
			Regex:          regexp.MustCompile(`(?i)(%3cscript|%3c%2fscript|&#x3[cC];script|&lt;script|%253cscript)`),
			ThreatType:     sentinel.ThreatXSS,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 85,
		},
		{
			Name:           "XSS_SVG",
			Regex:          regexp.MustCompile(`(?i)(<svg[^>]*onload|<img[^>]*onerror|<iframe[^>]*src|<object[^>]*data|<embed[^>]*src)`),
			ThreatType:     sentinel.ThreatXSS,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 75,
		},

		// --- Path Traversal ---
		{
			Name:           "PathTraversal",
			Regex:          regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f|%c0%ae%c0%ae|%uff0e%uff0e)`),
			ThreatType:     sentinel.ThreatPathTraversal,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 85,
		},

		// --- Command Injection ---
		{
			Name:           "CommandInject",
			Regex:          regexp.MustCompile("(?i)(;\\s*ls|;\\s*cat\\s|;\\s*whoami|;\\s*id\\b|;\\s*uname|\\|\\s*nc\\s|wget\\s+https?:|curl\\s+https?:|bash\\s+-[ic]|/etc/passwd|/etc/shadow|\\$\\(|`[^`]+`)"),
			ThreatType:     sentinel.ThreatCommandInjection,
			BaseSeverity:   sentinel.SeverityCritical,
			BaseConfidence: 85,
		},

		// --- SSRF ---
		{
			Name:           "SSRF",
			Regex:          regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|file:\/\/|dict:\/\/|gopher:\/\/|ftp:\/\/[^.]*localhost)`),
			ThreatType:     sentinel.ThreatSSRF,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 70,
		},

		// --- XXE ---
		{
			Name:           "XXE",
			Regex:          regexp.MustCompile(`(?i)(<!ENTITY|<!DOCTYPE[^>]*\[|SYSTEM\s+["']|PUBLIC\s+["']|%[a-z]+;)`),
			ThreatType:     sentinel.ThreatXXE,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
		},

		// --- Local File Inclusion (LFI) ---
		{
			Name:           "LFI",
			Regex:          regexp.MustCompile(`(?i)(etc[/\\]passwd|etc[/\\]shadow|proc[/\\]self|var[/\\]log|windows[/\\]system32|boot\.ini|web\.config|\.htaccess|\.env)`),
			ThreatType:     sentinel.ThreatLFI,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
		},

		// --- Open Redirect ---
		{
			Name:           "OpenRedirect",
			Regex:          regexp.MustCompile(`(?i)(=\s*//[^/]|=\s*https?://|redirect.*=.*https?://|next.*=.*https?://|url.*=.*https?://|return.*=.*https?://|goto.*=.*https?://)`),
			ThreatType:     sentinel.ThreatOpenRedirect,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 60,
		},

		// --- Prototype Pollution ---
		{
			Name:           "PrototypePollution",
			Regex:          regexp.MustCompile(`(?i)(__proto__|constructor\s*\[|prototype\s*\[)`),
			ThreatType:     sentinel.ThreatPrototypePollution,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 75,
		},
	}
}
