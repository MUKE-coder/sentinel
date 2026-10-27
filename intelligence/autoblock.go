package intelligence

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/google/uuid"
)

// autoBlockPrefix namespaces the per-address threat counters.
const autoBlockPrefix = "ab:threats:"

// IPBlocker is the part of IPManager AutoBlocker needs: block an address,
// and know whether it is already blocked or whitelisted.
type IPBlocker interface {
	BlockIP(ctx context.Context, ip, reason string, expiry *time.Time) error
	IsBlocked(ip string) bool
	IsWhitelisted(ip string) bool
}

// AutoBlocker blocks an address that keeps attacking. It runs as a pipeline
// handler: every threat event counts against the address that caused it,
// and once a configured number land inside the window the address is
// blocked.
//
// This is the answer to a scanner walking a list of paths — the ".env",
// ".git/config", "wp-login.php" traffic that fills a threat log with
// thousands of rows from a handful of addresses. Blocking on behaviour
// stops that in seconds, where IPReputation.AutoBlock waits on what a third
// party already knows about the address.
//
// Counting runs through the shared CounterStore, so threats spread across
// replicas add up to one total, and a block made on any replica is enforced
// by all of them.
type AutoBlocker struct {
	config   sentinel.AutoBlockConfig
	blocker  IPBlocker
	counters sentinel.CounterStore
	pipe     *pipeline.Pipeline
	exempt   *middleware.IPMatcher
	now      func() time.Time

	mu        sync.Mutex
	lastError time.Time
}

// NewAutoBlocker returns a blocker for the given configuration. counters
// should be the same store the rest of Sentinel uses, so replicas share
// their counts.
func NewAutoBlocker(config sentinel.AutoBlockConfig, blocker IPBlocker, counters sentinel.CounterStore, pipe *pipeline.Pipeline) *AutoBlocker {
	return &AutoBlocker{
		config:   config,
		blocker:  blocker,
		counters: counters,
		pipe:     pipe,
		exempt:   middleware.NewIPMatcher(config.ExemptIPs),
		now:      time.Now,
	}
}

// Handle implements pipeline.Handler.
func (b *AutoBlocker) Handle(ctx context.Context, event pipeline.Event) error {
	if !b.config.Enabled || event.Type != pipeline.EventThreat {
		return nil
	}
	threat, ok := event.Payload.(*sentinel.ThreatEvent)
	if !ok || threat == nil || threat.IP == "" {
		return nil
	}
	if !threat.Severity.AtLeast(b.config.MinSeverity) {
		return nil
	}
	if b.exempt.Matches(threat.IP) || b.blocker.IsWhitelisted(threat.IP) || b.blocker.IsBlocked(threat.IP) {
		return nil
	}

	// Each threat counts once, by its own ID: a replica replaying an event
	// cannot inflate the count, and the set expires with the window.
	id := threat.ID
	if id == "" {
		id = uuid.NewString()
	}
	count, err := b.counters.Record(ctx, autoBlockPrefix+threat.IP, id, b.config.Window, b.now())
	if err != nil {
		b.logThrottled("auto-block counter store: %v (addresses are not auto-blocked until it recovers)", err)
		return nil
	}
	if count < b.config.Threats {
		return nil
	}

	reason := fmt.Sprintf("auto-blocked: %d threats in %s", count, b.config.Window)
	var expiry *time.Time
	if b.config.Duration > 0 {
		until := b.now().Add(b.config.Duration)
		expiry = &until
	}
	if err := b.blocker.BlockIP(ctx, threat.IP, reason, expiry); err != nil {
		b.logThrottled("auto-block: %v", err)
		return nil
	}
	b.audit(threat, reason, count, expiry)
	return nil
}

// audit records the block, so an automatic one is as visible in the audit
// trail as one somebody made from the dashboard.
func (b *AutoBlocker) audit(threat *sentinel.ThreatEvent, reason string, count int, expiry *time.Time) {
	if b.pipe == nil {
		return
	}
	after := sentinel.JSONMap{
		"ip":       threat.IP,
		"reason":   reason,
		"threats":  count,
		"window":   b.config.Window.String(),
		"severity": string(threat.Severity),
	}
	if expiry != nil {
		after["expires_at"] = expiry.Format(time.RFC3339)
	}
	b.pipe.EmitAudit(&sentinel.AuditLog{
		ID:         uuid.NewString(),
		Timestamp:  b.now(),
		UserID:     "sentinel",
		UserRole:   "system",
		Action:     "BLOCK_IP",
		Resource:   "sentinel.ip_block",
		ResourceID: threat.IP,
		IP:         threat.IP,
		Success:    true,
		After:      after,
	})
}

func (b *AutoBlocker) logThrottled(format string, args ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := b.now(); now.Sub(b.lastError) >= time.Minute {
		b.lastError = now
		log.Printf("[sentinel] "+format, args...)
	}
}
