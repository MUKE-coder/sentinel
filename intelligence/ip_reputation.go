package intelligence

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/MUKE-coder/sentinel/storage"
)

// IPManager maintains an in-memory cache of blocked and whitelisted IPs,
// syncing from storage periodically for fast per-request lookups.
type IPManager struct {
	store      storage.Store
	mu         sync.RWMutex
	blockedIPs map[string]bool
	blockedCIDRs []*net.IPNet
	whitelistedIPs map[string]bool
	stopCh     chan struct{}
}

// NewIPManager creates a new IP manager that caches blocked/whitelisted IPs.
func NewIPManager(store storage.Store) *IPManager {
	mgr := &IPManager{
		store:          store,
		blockedIPs:     make(map[string]bool),
		whitelistedIPs: make(map[string]bool),
		stopCh:         make(chan struct{}),
	}
	// Initial sync
	mgr.sync()
	// Background sync every 30 seconds
	go mgr.backgroundSync()
	return mgr
}

// Stop stops the background sync goroutine.
func (m *IPManager) Stop() {
	close(m.stopCh)
}

// IsBlocked checks if an IP is blocked (exact match or CIDR membership).
func (m *IPManager) IsBlocked(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.blockedIPs[ip] {
		return true
	}

	// Check CIDR ranges
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		for _, cidr := range m.blockedCIDRs {
			if cidr.Contains(parsedIP) {
				return true
			}
		}
	}

	return false
}

// IsWhitelisted checks if an IP is whitelisted.
func (m *IPManager) IsWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.whitelistedIPs[ip]
}

// BlockIP blocks an IP with immediate cache update.
func (m *IPManager) BlockIP(ctx context.Context, ip, reason string, expiry *time.Time) error {
	if err := m.store.BlockIP(ctx, ip, reason, expiry); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.Contains(ip, "/") {
		_, cidr, err := net.ParseCIDR(ip)
		if err == nil {
			m.blockedCIDRs = append(m.blockedCIDRs, cidr)
		}
	} else {
		m.blockedIPs[ip] = true
	}

	return nil
}

// UnblockIP removes a block with immediate cache update.
func (m *IPManager) UnblockIP(ctx context.Context, ip string) error {
	if err := m.store.UnblockIP(ctx, ip); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blockedIPs, ip)

	// Remove CIDR if applicable
	if strings.Contains(ip, "/") {
		var filtered []*net.IPNet
		for _, cidr := range m.blockedCIDRs {
			if cidr.String() != ip {
				filtered = append(filtered, cidr)
			}
		}
		m.blockedCIDRs = filtered
	}

	return nil
}

// WhitelistIP adds an IP to the whitelist with immediate cache update.
func (m *IPManager) WhitelistIP(ctx context.Context, ip string) error {
	if err := m.store.WhitelistIP(ctx, ip); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.whitelistedIPs[ip] = true
	return nil
}

func (m *IPManager) sync() {
	ctx := context.Background()

	// Sync blocked IPs
	blocked, err := m.store.ListBlockedIPs(ctx)
	if err != nil {
		return
	}

	newBlocked := make(map[string]bool)
	var newCIDRs []*net.IPNet
	for _, b := range blocked {
		if strings.Contains(b.IP, "/") {
			_, cidr, err := net.ParseCIDR(b.IP)
			if err == nil {
				newCIDRs = append(newCIDRs, cidr)
			}
		} else {
			newBlocked[b.IP] = true
		}
	}

	m.mu.Lock()
	m.blockedIPs = newBlocked
	m.blockedCIDRs = newCIDRs
	m.mu.Unlock()
}

func (m *IPManager) backgroundSync() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sync()
		}
	}
}
