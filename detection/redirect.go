package detection

import (
	"net/url"
	"strings"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// RedirectAllowlist holds the hosts an application owns, so an absolute URL
// in a redirect parameter can be told apart from an open redirect. Sentinel
// cannot know your hostnames on its own, and the two look identical:
// "callback=https://app.example.com/oauth" is the shape of the attack and
// the shape of an ordinary OAuth callback. Build one from
// WAFConfig.AllowedRedirectHosts.
type RedirectAllowlist struct {
	exact    map[string]bool
	suffixes []string // ".example.com" for a "*.example.com" entry
}

// NewRedirectAllowlist compiles hosts into an allowlist. An entry may be a
// host ("example.com", matched exactly, port ignored) or a wildcard
// ("*.example.com", matching any subdomain but not the bare domain). It
// returns nil for an empty list, which allows nothing — every absolute
// redirect target stays suspicious, the behavior before v2.6.0.
func NewRedirectAllowlist(hosts []string) *RedirectAllowlist {
	a := &RedirectAllowlist{exact: make(map[string]bool, len(hosts))}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(h, "*."); ok {
			a.suffixes = append(a.suffixes, "."+rest)
			continue
		}
		a.exact[h] = true
	}
	if len(a.exact) == 0 && len(a.suffixes) == 0 {
		return nil
	}
	return a
}

// Allows reports whether host is one the application owns.
func (a *RedirectAllowlist) Allows(host string) bool {
	if a == nil {
		return false
	}
	host = strings.ToLower(host)
	if a.exact[host] {
		return true
	}
	for _, suffix := range a.suffixes {
		// The leading dot keeps "evil-example.com" from matching
		// "*.example.com".
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// FilterRedirects drops built-in open-redirect matches when every absolute
// URL in the request's query points at a host the application owns. A
// request that carries even one outside target keeps its match, and so does
// one whose target can't be parsed — a redirect Sentinel can't read is not
// a redirect it should vouch for.
func FilterRedirects(matches []ThreatMatch, req sentinel.InspectedRequest, allow *RedirectAllowlist) []ThreatMatch {
	if allow == nil || len(matches) == 0 {
		return matches
	}
	found := false
	for _, m := range matches {
		if m.PatternName == "OpenRedirect" {
			found = true
			break
		}
	}
	if !found {
		return matches
	}

	targets := queryTargetHosts(req.RawQuery)
	if len(targets) == 0 {
		return matches
	}
	for _, host := range targets {
		if !allow.Allows(host) {
			return matches
		}
	}

	kept := make([]ThreatMatch, 0, len(matches))
	for _, m := range matches {
		if m.PatternName == "OpenRedirect" {
			continue
		}
		kept = append(kept, m)
	}
	return kept
}

// queryTargetHosts returns the host of every absolute or scheme-relative URL
// in a query string, including ones that take another round of decoding.
func queryTargetHosts(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	params, err := url.ParseQuery(rawQuery)
	if err != nil && len(params) == 0 {
		return nil
	}
	var hosts []string
	for _, values := range params {
		for _, value := range values {
			candidates := append([]string{value}, decodedLayers(value, true)...)
			for _, candidate := range candidates {
				if host, ok := absoluteURLHost(candidate); ok {
					hosts = append(hosts, host)
				}
			}
		}
	}
	return hosts
}

// absoluteURLHost returns the host of an absolute or scheme-relative URL.
func absoluteURLHost(value string) (string, bool) {
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, "//"):
		value = "http:" + value
	case !strings.Contains(value, "://"):
		return "", false
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	return strings.ToLower(u.Hostname()), true
}
