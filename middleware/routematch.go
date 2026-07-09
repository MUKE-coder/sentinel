package middleware

import (
	"log"
	"path"
	"strings"
)

// RouteMatcher matches request paths against a set of route patterns.
// Entry shapes, checked in this order:
//
//   - exact:         "/health"                  — matches only that path
//   - prefix:        "/v1/*" or "/v1/**"        — matches "/v1" and anything under "/v1/"
//   - segment glob:  "/api/apps/*/products"     — path.Match semantics; "*" spans one segment
//
// Before v2.1.0, WAFConfig.ExcludeRoutes did exact string lookup only, so a
// wildcard entry was silent dead code — callers believed "/v1/**" excluded
// their payment endpoints while the WAF kept inspecting (and blocking) them
// (issues #7, #8). A "**" anywhere except the end of a pattern is not
// supported and is logged at construction instead of failing silently.
type RouteMatcher struct {
	exact    map[string]struct{}
	prefixes []string
	globs    []string
}

// NewRouteMatcher compiles a pattern list. Invalid glob patterns are dropped
// with a warning rather than matching nothing silently.
func NewRouteMatcher(patterns []string) *RouteMatcher {
	m := &RouteMatcher{exact: make(map[string]struct{}, len(patterns))}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		switch {
		case strings.HasSuffix(p, "/**"):
			m.prefixes = append(m.prefixes, strings.TrimSuffix(p, "**"))
		case strings.HasSuffix(p, "/*") && strings.Count(p, "*") == 1:
			m.prefixes = append(m.prefixes, strings.TrimSuffix(p, "*"))
		case strings.Contains(p, "**"):
			log.Printf("[sentinel] route pattern %q: \"**\" is only supported at the end of a pattern — entry ignored", p)
		case strings.Contains(p, "*") || strings.Contains(p, "?") || strings.Contains(p, "["):
			if _, err := path.Match(p, "/"); err != nil {
				log.Printf("[sentinel] route pattern %q is not a valid glob (%v) — entry ignored", p, err)
				continue
			}
			m.globs = append(m.globs, p)
		default:
			m.exact[p] = struct{}{}
		}
	}
	return m
}

// Matches reports whether the request path matches any pattern.
func (m *RouteMatcher) Matches(reqPath string) bool {
	if _, ok := m.exact[reqPath]; ok {
		return true
	}
	for _, prefix := range m.prefixes {
		// "/v1/*" matches "/v1/x" and "/v1" itself, but never "/v1x".
		if strings.HasPrefix(reqPath, prefix) || reqPath == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	for _, glob := range m.globs {
		if ok, _ := path.Match(glob, reqPath); ok {
			return true
		}
	}
	return false
}

// Empty reports whether no patterns were registered.
func (m *RouteMatcher) Empty() bool {
	return len(m.exact) == 0 && len(m.prefixes) == 0 && len(m.globs) == 0
}
