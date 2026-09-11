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
//
// testdata/benign.tsv and testdata/attacks.tsv measure these patterns
// (TestCorpus): tighten a pattern only with a sample in each corpus showing
// what it stops flagging and what it still catches.
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
			// Keywords that are also English ("drop table", "insert into",
			// "convert (", "char(") only count in statement shape: a table
			// name then a terminator, a column list or VALUES, a type
			// argument. "--" only counts right after a quote, paren or digit
			// — where it cuts off the rest of a query — never as a dash in
			// prose ("rock -- n -- roll") or inside a slug or token. A hex
			// literal must be a whole value or sit in SQL, not start a word
			// ("0x1F600 emoji").
			Regex:          regexp.MustCompile(`(?i)(union\s+(?:all\s+)?select|drop\s+table\s+(?:if\s+exists\s+)?[\w.\x60"\[\]]+\s*(?:;|--|#|/\*|$)|insert\s+into\s+[\w.\x60"\[\]]+\s*(?:\(|values\b|select\b)|(?:['")]\s*|\d)--(?:\s|$)|;--|'\s*or\s*'1'\s*=\s*'1|xp_cmdshell|exec\s*\(\s*['"@]|cast\s*\([^)]{1,80}\s+as\s+\w|convert\s*\(\s*\w+\s*,|n?char\s*\(\s*(?:\d+\s*,|0x)|varchar\s*\(|(?:^|[=\s(,])0x[0-9a-f]{4,}(?:$|[&),;]|--|\s+(?:and|or|union|from|limit)\b))`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
			Locations:      []string{"query", "body"},
		},
		{
			Name: "SQLi_Blind",
			// Delay functions count after a SQL operator or quote, or as the
			// entire value ("id=sleep(5)"), not when named in a sentence. An
			// "and 1=1" tautology counts where a query would end, not
			// mid-sentence ("1 = 1 is true").
			Regex:          regexp.MustCompile(`(?i)((?:\b(?:and|or|select|if|then|when)\b|[;'"(,]|\|\|)\s*(?:sleep|benchmark|pg_sleep)\s*\(|(?:^|=)\s*(?:sleep|benchmark)\s*\([^)]*\)\s*(?:$|&|--|#|;)|pg_sleep\s*\(|waitfor\s+delay|\b(?:and|or)\s+\d+\s*=\s*\d+\s*(?:$|&|--|#|/\*|;|'|"|\)))`),
			ThreatType:     sentinel.ThreatSQLi,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 75,
			Locations:      []string{"query", "body"},
		},
		{
			Name: "SQLi_Comment",
			// An inline /**/ counts between SQL tokens ("UNION/**/SELECT"),
			// not inside a glob ("src/**/*.go"); MySQL's /*! executable
			// comments always count. Same terminator rule as SQLi_Basic,
			// and "#" needs a quote, paren or digit before it, so "C# vs F#"
			// is not a MySQL comment.
			Regex:          regexp.MustCompile(`(?i)(['")\w]/\*[^/]*?\*/\s*['"(\w]|/\*!|(?:['")]\s*|\d)--\s|['")\d]\s*#\s*$)`),
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
			Name: "XSS_Basic",
			// eval( and document.cookie only count where they break out of a
			// string or call ("';eval(", "(document.cookie"); named in a
			// sentence they are a question about JavaScript, not a payload.
			Regex:          regexp.MustCompile(`(?i)(<script[^>]*>|javascript\s*:|vbscript\s*:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=|onblur\s*=|[;'"(+]\s*(?:eval\s*\(|document\.(?:cookie|write)|window\.location))`),
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
			Name: "CommandInject",
			// $( and backticks count where a shell would start a new word
			// after an injection point (a value's start, =, ;, |, &, a quote)
			// — not inside Markdown prose ("run `ls -la` to see"). A bare
			// /etc/passwd is a file reference, left to LFI.
			Regex:          regexp.MustCompile("(?i)(;\\s*ls|;\\s*cat\\s|;\\s*whoami|;\\s*id\\b|;\\s*uname|\\|\\s*nc\\s|wget\\s+https?:|curl\\s+https?:|bash\\s+-[ic]|(?:^|[=;|&\"'(])\\s*(?:\\$\\(|`[^`]+`))"),
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
			// matches any string containing "::1". The host must end the
			// value or be followed by a port, path, quote or separator — a
			// URL or a host field, not words ("localhost:3000 setup guide").
			Regex:          regexp.MustCompile(`(?i)((?:^|[^\w.-])(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[::1\]|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:[/"'&?#,;\\]|$)|file:\/\/|dict:\/\/|gopher:\/\/|ftp:\/\/[^.]*localhost)`),
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
			Name: "LFI",
			// Dotfiles and web.config count as a whole path segment or value
			// ("/.env", "file=.env.local", "/.git/config"), not as part of a
			// longer name ("report.env.pdf", "web.config-explained").
			Regex:          regexp.MustCompile(`(?i)(etc[/\\]passwd|etc[/\\]shadow|proc[/\\]self|var[/\\]log|windows[/\\]system32|boot\.ini|(?:^|[/\\=])(?:web\.config|\.htaccess|\.htpasswd|\.git|\.env(?:\.[\w-]+)?)(?:$|[/?&#"'\s;,]))`),
			ThreatType:     sentinel.ThreatLFI,
			BaseSeverity:   sentinel.SeverityHigh,
			BaseConfidence: 80,
			Locations:      []string{"path", "query", "body"},
		},

		// --- Open Redirect ---
		{
			Name: "OpenRedirect",
			// Only parameters named for a redirect target, holding an
			// absolute or scheme-relative URL (plain or percent-encoded).
			// Any "=https://" used to count, so "avatar=https://cdn..." was
			// an attack. Sentinel can't tell your own host from someone
			// else's, so a legitimate absolute callback still matches — set
			// this rule to low if your redirect parameters carry them.
			Regex:          regexp.MustCompile(`(?i)(?:^|[?&;])(?:[\w.-]*(?:redir|return|next|goto|continue|dest|forward|callback|relaystate|success|cancel|service)[\w.-]*|url|uri|to|out|target|r|u|link|go)=\s*(?:https?(?::|%3a))?(?://|%2f%2f|/\\|%2f%5c)`),
			ThreatType:     sentinel.ThreatOpenRedirect,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 60,
			// Referer headers routinely embed full URLs in their own query
			// strings ("?url=https://..."), so this must never scan headers.
			Locations: []string{"query"},
		},

		// --- Prototype Pollution ---
		{
			Name: "PrototypePollution",
			// __proto__ counts as a key or property access, not a word in a
			// search; constructor → prototype counts in any nesting —
			// brackets, dots or JSON objects.
			Regex:          regexp.MustCompile(`(?i)(__proto__\s*(?:\[|\]|\.|["']\s*:|%5b|%5d|%2e|=)|constructor\W{1,6}prototype|constructor\s*\[|prototype\s*\[)`),
			ThreatType:     sentinel.ThreatPrototypePollution,
			BaseSeverity:   sentinel.SeverityMedium,
			BaseConfidence: 75,
			Locations:      []string{"query", "body"},
		},
	}
}
