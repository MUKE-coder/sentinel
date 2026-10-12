package middleware

import (
	"net"
	"strings"
)

// IPMatcher matches a client address against a list of addresses and CIDR
// ranges. WAFConfig.ExcludeIPs and AuthShieldConfig.ExemptIPs are both
// documented to accept either; before v2.7.0 the WAF compared exclusions as
// exact strings, so a "10.0.0.0/8" entry matched nothing at all.
type IPMatcher struct {
	exact map[string]bool
	nets  []*net.IPNet
}

// NewIPMatcher compiles entries into a matcher. An entry that is neither an
// address nor a CIDR is kept as an exact string, so a hostname-ish entry
// behaves as it did before rather than disappearing. A nil matcher matches
// nothing.
func NewIPMatcher(entries []string) *IPMatcher {
	if len(entries) == 0 {
		return nil
	}
	m := &IPMatcher{exact: make(map[string]bool, len(entries))}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			m.nets = append(m.nets, network)
			continue
		}
		m.exact[entry] = true
	}
	if len(m.exact) == 0 && len(m.nets) == 0 {
		return nil
	}
	return m
}

// Matches reports whether ip is covered by the matcher.
func (m *IPMatcher) Matches(ip string) bool {
	if m == nil {
		return false
	}
	if m.exact[ip] {
		return true
	}
	if len(m.nets) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range m.nets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// Empty reports whether the matcher has no entries.
func (m *IPMatcher) Empty() bool { return m == nil || (len(m.exact) == 0 && len(m.nets) == 0) }
