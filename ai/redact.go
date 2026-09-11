package ai

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// Redactor masks personal data and secrets in threat data before it is sent
// to an AI provider. What it masks is set by sentinel.AIRedaction; the zero
// value is the most private.
type Redactor struct {
	opts sentinel.AIRedaction
}

// NewRedactor creates a Redactor for the given options.
func NewRedactor(opts sentinel.AIRedaction) *Redactor {
	return &Redactor{opts: opts}
}

type scrubRule struct {
	re   *regexp.Regexp
	repl string
}

// scrubRules run in order over every free-text field. Tokens go first so a
// later rule never leaves half of one behind.
var scrubRules = []scrubRule{
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`), "[jwt]"},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "$1 [token]"},
	{regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`), "[email]"},
	{regexp.MustCompile(`(?i)\b((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth|session(?:id)?|cookie|credential)s?)("?\s*[=:]\s*"?)([^\s&"',;}]+)`), "$1$2[redacted]"},
	{regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`), "[secret]"},
	{regexp.MustCompile(`\b[A-Za-z0-9_-]{40,}\b`), "[secret]"},
}

// cardCandidate finds 13–19 digit runs, optionally split by spaces or dashes;
// only those passing the Luhn check are treated as card numbers.
var cardCandidate = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)

// Text scrubs emails, tokens, card numbers, and secret-looking values from
// one free-text value.
func (r *Redactor) Text(s string) string {
	if s == "" || r.opts.DisableScrubbing {
		return s
	}
	s = cardCandidate.ReplaceAllStringFunc(s, func(m string) string {
		digits := strings.Map(func(c rune) rune {
			if c >= '0' && c <= '9' {
				return c
			}
			return -1
		}, m)
		if luhnValid(digits) {
			return "[card]"
		}
		return m
	})
	for _, rule := range scrubRules {
		s = rule.re.ReplaceAllString(s, rule.repl)
	}
	return s
}

func luhnValid(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// IP truncates an address: IPv4 loses its last octet, IPv6 keeps its /48.
func (r *Redactor) IP(ip string) string {
	if ip == "" || r.opts.SendFullIPs {
		return ip
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "[ip]"
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.x", b[0], b[1], b[2])
	}
	p, err := addr.Prefix(48)
	if err != nil {
		return "[ip]"
	}
	return p.String()
}

// Query masks query-string values and keeps parameter names, unless
// SendPayloads is set.
func (r *Redactor) Query(q string) string {
	if q == "" {
		return ""
	}
	if r.opts.SendPayloads {
		return r.Text(q)
	}
	values, err := url.ParseQuery(q)
	if err != nil || len(values) == 0 {
		return fmt.Sprintf("[redacted: %d bytes]", len(q))
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, r.Text(k)+"=[redacted]")
	}
	return strings.Join(parts, "&")
}

// Body drops a request-body snippet, unless SendPayloads is set.
func (r *Redactor) Body(b string) string {
	if b == "" {
		return ""
	}
	if !r.opts.SendPayloads {
		return fmt.Sprintf("[omitted: %d bytes]", len(b))
	}
	return r.Text(b)
}

// Threat returns a redacted copy of a threat event.
func (r *Redactor) Threat(t *sentinel.ThreatEvent) *sentinel.ThreatEvent {
	if t == nil {
		return nil
	}
	c := *t
	c.IP = r.IP(t.IP)
	c.ActorID = ""
	c.UserID = ""
	c.Path = r.Text(t.Path)
	c.QueryParams = r.Query(t.QueryParams)
	c.BodySnippet = r.Body(t.BodySnippet)
	c.UserAgent = r.Text(t.UserAgent)
	c.Referer = r.Text(t.Referer)
	c.Headers = nil
	if !r.opts.SendFullIPs {
		c.City, c.Lat, c.Lng = "", 0, 0
	}
	if len(t.Evidence) > 0 {
		c.Evidence = make([]sentinel.Evidence, len(t.Evidence))
		for i, e := range t.Evidence {
			e.Matched = r.Text(e.Matched)
			e.Parameter = r.Text(e.Parameter)
			c.Evidence[i] = e
		}
	}
	return &c
}

// Threats redacts a list of threat events.
func (r *Redactor) Threats(ts []*sentinel.ThreatEvent) []*sentinel.ThreatEvent {
	if ts == nil {
		return nil
	}
	out := make([]*sentinel.ThreatEvent, len(ts))
	for i, t := range ts {
		out[i] = r.Threat(t)
	}
	return out
}

// Actor returns a redacted copy of a threat actor profile.
func (r *Redactor) Actor(a *sentinel.ThreatActor) *sentinel.ThreatActor {
	if a == nil {
		return nil
	}
	c := *a
	c.ID = ""
	c.IP = r.IP(a.IP)
	if !r.opts.SendFullIPs {
		c.City, c.Lat, c.Lng = "", 0, 0
	}
	if len(a.TargetedRoutes) > 0 {
		c.TargetedRoutes = make([]string, len(a.TargetedRoutes))
		for i, route := range a.TargetedRoutes {
			c.TargetedRoutes[i] = r.Text(route)
		}
	}
	return &c
}

// Actors redacts a list of actor profiles.
func (r *Redactor) Actors(as []*sentinel.ThreatActor) []*sentinel.ThreatActor {
	if as == nil {
		return nil
	}
	out := make([]*sentinel.ThreatActor, len(as))
	for i, a := range as {
		out[i] = r.Actor(a)
	}
	return out
}

// RedactingProvider redacts every threat, actor, and security context before
// passing it to the wrapped provider — the last step before data leaves the
// process. NewProvider always installs it.
type RedactingProvider struct {
	provider Provider
	r        *Redactor
}

// NewRedactingProvider wraps a Provider with redaction.
func NewRedactingProvider(p Provider, opts sentinel.AIRedaction) *RedactingProvider {
	return &RedactingProvider{provider: p, r: NewRedactor(opts)}
}

// AnalyzeThreat redacts the threat and actor, then delegates.
func (p *RedactingProvider) AnalyzeThreat(ctx context.Context, threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) (*ThreatAnalysis, error) {
	return p.provider.AnalyzeThreat(ctx, p.r.Threat(threat), p.r.Actor(actor))
}

// AnalyzeActor redacts the actor and its events, then delegates.
func (p *RedactingProvider) AnalyzeActor(ctx context.Context, actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) (*ActorAnalysis, error) {
	return p.provider.AnalyzeActor(ctx, p.r.Actor(actor), p.r.Threats(recentEvents))
}

// GenerateDailySummary delegates unchanged: the stats are aggregate counts.
func (p *RedactingProvider) GenerateDailySummary(ctx context.Context, stats *sentinel.ThreatStats) (*DailySummary, error) {
	return p.provider.GenerateDailySummary(ctx, stats)
}

// NaturalLanguageQuery redacts the security context, then delegates. The
// question itself is sent as the operator typed it.
func (p *RedactingProvider) NaturalLanguageQuery(ctx context.Context, query string, secCtx *SecurityContext) (*QueryResult, error) {
	if secCtx != nil {
		redacted := *secCtx
		redacted.RecentThreats = p.r.Threats(secCtx.RecentThreats)
		redacted.TopActors = p.r.Actors(secCtx.TopActors)
		secCtx = &redacted
	}
	return p.provider.NaturalLanguageQuery(ctx, query, secCtx)
}

// RecommendWAFRules redacts the threats, then delegates.
func (p *RedactingProvider) RecommendWAFRules(ctx context.Context, recentThreats []*sentinel.ThreatEvent) ([]*WAFRecommendation, error) {
	return p.provider.RecommendWAFRules(ctx, p.r.Threats(recentThreats))
}
