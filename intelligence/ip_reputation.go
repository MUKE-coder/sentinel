package intelligence

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/MUKE-coder/sentinel/v2/storage"
)

// DefaultSyncInterval is how often an IPManager rebuilds its cache from
// storage. It bounds how long a block or whitelist entry made elsewhere — by
// another replica, or straight in the database — takes to apply here; the
// replica that made the change applies it immediately. It was 30s before
// v2.5.1, which is a long time to keep serving an attacker another replica
// has already blocked.
const DefaultSyncInterval = 5 * time.Second

// IPManager maintains an in-memory cache of blocked and whitelisted IPs,
// syncing from storage periodically for fast per-request lookups.
type IPManager struct {
	store          storage.Store
	interval       time.Duration
	mu             sync.RWMutex
	blockedIPs     map[string]bool
	blockedCIDRs   []*net.IPNet
	whitelistedIPs map[string]bool
	stopCh         chan struct{}
}

// NewIPManager creates a new IP manager that caches blocked/whitelisted IPs
// and refreshes them every DefaultSyncInterval.
func NewIPManager(store storage.Store) *IPManager {
	return NewIPManagerWithSync(store, DefaultSyncInterval)
}

// NewIPManagerWithSync creates an IP manager that rebuilds its cache from
// storage every interval. A non-positive interval syncs once at startup and
// then only when the process changes something itself.
func NewIPManagerWithSync(store storage.Store, interval time.Duration) *IPManager {
	mgr := &IPManager{
		store:          store,
		interval:       interval,
		blockedIPs:     make(map[string]bool),
		whitelistedIPs: make(map[string]bool),
		stopCh:         make(chan struct{}),
	}
	mgr.sync()
	if interval > 0 {
		go mgr.backgroundSync()
	}
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

	// Sync blocked IPs. A failed read keeps the cache as it is rather than
	// unblocking everyone, and does not stop the whitelist from refreshing.
	if blocked, err := m.store.ListBlockedIPs(ctx); err == nil {
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

	// Sync the whitelist, which is only refreshable when the store can list
	// it. Without storage.WhitelistLister the cache keeps just what this
	// process whitelisted itself — entries are lost on restart and never
	// reach other replicas.
	lister, ok := m.store.(storage.WhitelistLister)
	if !ok {
		return
	}
	white, err := lister.ListWhitelistedIPs(ctx)
	if err != nil {
		return
	}
	newWhite := make(map[string]bool, len(white))
	for _, w := range white {
		newWhite[w.IP] = true
	}

	m.mu.Lock()
	m.whitelistedIPs = newWhite
	m.mu.Unlock()
}

func (m *IPManager) backgroundSync() {
	ticker := time.NewTicker(m.interval)
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
