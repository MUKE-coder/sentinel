package middleware

import (
	"errors"
	"fmt"
	"log"
	"path"
	"strings"
)

// RouteMatcher matches request paths against a set of route patterns.
// Entry shapes:
//
//   - exact:         "/health"                    — matches only that path
//   - prefix:        "/v1/*" or "/v1/**"          — matches "/v1" and anything under "/v1/"
//   - segment glob:  "/api/apps/*/products"       — path.Match semantics; "*" spans one segment
//   - globstar:      "/api/apps/*/products/**"    — segment wildcards, then any depth below
//
// Before v2.1.0, WAFConfig.ExcludeRoutes did exact string lookup only, so a
// wildcard entry was silent dead code (issues #7, #8). Before v2.1.2, a
// trailing "/**" combined with an interior "*" compiled to a literal prefix
// that could never match — the same silent-dead-config failure, one layer up
// (issue #12); those patterns now get a real segment-by-segment matcher.
// A "**" anywhere except the end of a pattern remains unsupported and is
// logged at construction instead of failing silently.
type RouteMatcher struct {
	exact    map[string]struct{}
	prefixes []string
	globs    []string
	segments []segmentPattern
}

// segmentPattern matches a path segment by segment: each pattern segment is
// a path.Match glob consuming exactly one path segment, and a trailing "**"
// (globstar=true) consumes any remainder, including none — so
// "/api/apps/*/products/**" matches "/api/apps/13/products" itself and
// everything below it.
type segmentPattern struct {
	parts    []string
	globstar bool
}

func (sp segmentPattern) matches(reqPath string) bool {
	got := splitPathSegments(reqPath)
	if sp.globstar {
		if len(got) < len(sp.parts) {
			return false
		}
	} else if len(got) != len(sp.parts) {
		return false
	}
	for i, want := range sp.parts {
		if ok, _ := path.Match(want, got[i]); !ok {
			return false
		}
	}
	return true
}

func splitPathSegments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// ErrUnsupportedPattern is wrapped by ValidateRoutePattern errors for
// patterns RouteMatcher would drop at construction.
var ErrUnsupportedPattern = errors.New("unsupported route pattern")

// ValidateRoutePattern reports whether a route pattern is one RouteMatcher
// supports. It returns nil for exact paths, trailing-wildcard prefixes,
// segment globs, and globstar patterns, and a descriptive error (wrapping
// ErrUnsupportedPattern) for anything NewRouteMatcher would warn about and
// drop. Use it in config validation or your own tests to catch dead
// exclusion entries before they reach production.
func ValidateRoutePattern(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("%w: empty pattern", ErrUnsupportedPattern)
	}
	if !strings.ContainsAny(p, "*?[") {
		return nil
	}
	if strings.HasSuffix(p, "/**") {
		base := strings.TrimSuffix(p, "/**")
		if strings.Contains(base, "**") {
			return fmt.Errorf("%w: %q — \"**\" is only supported at the end of a pattern", ErrUnsupportedPattern, p)
		}
		for _, seg := range splitPathSegments(base) {
			if _, err := path.Match(seg, "x"); err != nil {
				return fmt.Errorf("%w: %q — segment %q is not a valid glob (%v)", ErrUnsupportedPattern, p, seg, err)
			}
		}
		return nil
	}
	if strings.Contains(p, "**") {
		return fmt.Errorf("%w: %q — \"**\" is only supported at the end of a pattern", ErrUnsupportedPattern, p)
	}
	if _, err := path.Match(p, "/"); err != nil {
		return fmt.Errorf("%w: %q is not a valid glob (%v)", ErrUnsupportedPattern, p, err)
	}
	return nil
}

// NewRouteMatcher compiles a pattern list. Invalid or unsupported patterns
// (anything ValidateRoutePattern rejects) are dropped with a warning rather
// than matching nothing silently.
func NewRouteMatcher(patterns []string) *RouteMatcher {
	m := &RouteMatcher{exact: make(map[string]struct{}, len(patterns))}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := ValidateRoutePattern(p); err != nil {
			log.Printf("[sentinel] %v — entry ignored", err)
			continue
		}

		switch {
		case !strings.ContainsAny(p, "*?["):
			m.exact[p] = struct{}{}

		case strings.HasSuffix(p, "/**"):
			base := strings.TrimSuffix(p, "/**")
			if !strings.ContainsAny(base, "*?[") {
				// Plain subtree — cheap prefix compare.
				m.prefixes = append(m.prefixes, base+"/")
				continue
			}
			// Wildcards before the globstar ("/api/apps/*/products/**"):
			// a literal prefix can never match these, so compile a
			// segment matcher instead (issue #12).
			m.segments = append(m.segments, segmentPattern{parts: splitPathSegments(base), globstar: true})

		case strings.HasSuffix(p, "/*") && strings.Count(p, "*") == 1 && !strings.ContainsAny(strings.TrimSuffix(p, "/*"), "*?["):
			m.prefixes = append(m.prefixes, strings.TrimSuffix(p, "*"))

		default:
			m.globs = append(m.globs, p)
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
	for _, sp := range m.segments {
		if sp.matches(reqPath) {
			return true
		}
	}
	return false
}

// Empty reports whether no patterns were registered.
func (m *RouteMatcher) Empty() bool {
	return len(m.exact) == 0 && len(m.prefixes) == 0 && len(m.globs) == 0 && len(m.segments) == 0
}
