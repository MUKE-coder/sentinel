package intelligence

import (
	"context"
	"sync"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
)

type fakeBlocker struct {
	mu          sync.Mutex
	blocked     map[string]string
	expiries    map[string]*time.Time
	whitelisted map[string]bool
	calls       int
}

func newFakeBlocker() *fakeBlocker {
	return &fakeBlocker{
		blocked:     map[string]string{},
		expiries:    map[string]*time.Time{},
		whitelisted: map[string]bool{},
	}
}

func (f *fakeBlocker) BlockIP(_ context.Context, ip, reason string, expiry *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.blocked[ip] = reason
	f.expiries[ip] = expiry
	return nil
}

func (f *fakeBlocker) IsBlocked(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.blocked[ip]
	return ok
}

func (f *fakeBlocker) IsWhitelisted(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.whitelisted[ip]
}

func (f *fakeBlocker) reasonFor(ip string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blocked[ip]
}

func autoBlockThreat(ip string, severity sentinel.Severity, id string) pipeline.Event {
	return pipeline.Event{
		Type:    pipeline.EventThreat,
		Payload: &sentinel.ThreatEvent{ID: id, IP: ip, Severity: severity},
	}
}

func autoBlockConfig() sentinel.AutoBlockConfig {
	return sentinel.AutoBlockConfig{
		Enabled:     true,
		Threats:     3,
		Window:      10 * time.Minute,
		Duration:    24 * time.Hour,
		MinSeverity: sentinel.SeverityHigh,
	}
}

// A scanner walking a list of paths trips the threshold and is blocked,
// with an expiry and a reason that says why.
func TestAutoBlockerBlocksRepeatOffender(t *testing.T) {
	ctx := context.Background()
	blocker := newFakeBlocker()
	ab := NewAutoBlocker(autoBlockConfig(), blocker, middleware.NewMemoryCounterStore(), nil)

	for i := 0; i < 2; i++ {
		if err := ab.Handle(ctx, autoBlockThreat("203.0.113.5", sentinel.SeverityHigh, uuidish(i))); err != nil {
			t.Fatal(err)
		}
	}
	if blocker.IsBlocked("203.0.113.5") {
		t.Fatal("blocked before reaching the threshold")
	}

	if err := ab.Handle(ctx, autoBlockThreat("203.0.113.5", sentinel.SeverityHigh, uuidish(2))); err != nil {
		t.Fatal(err)
	}
	if !blocker.IsBlocked("203.0.113.5") {
		t.Fatal("the third threat should have blocked the address")
	}
	if reason := blocker.reasonFor("203.0.113.5"); reason == "" {
		t.Error("the block should carry a reason")
	}
	blocker.mu.Lock()
	expiry := blocker.expiries["203.0.113.5"]
	blocker.mu.Unlock()
	if expiry == nil {
		t.Error("a 24h Duration must give the block an expiry")
	}

	// Further threats must not re-block: one address, one block.
	before := blocker.calls
	_ = ab.Handle(ctx, autoBlockThreat("203.0.113.5", sentinel.SeverityHigh, uuidish(3)))
	if blocker.calls != before {
		t.Error("an address that is already blocked must not be blocked again")
	}
}

// Only threats at or above MinSeverity count, so a stream of low-severity
// oddities never accumulates into a block.
func TestAutoBlockerIgnoresLowSeverity(t *testing.T) {
	ctx := context.Background()
	blocker := newFakeBlocker()
	ab := NewAutoBlocker(autoBlockConfig(), blocker, middleware.NewMemoryCounterStore(), nil)

	for i := 0; i < 10; i++ {
		_ = ab.Handle(ctx, autoBlockThreat("203.0.113.6", sentinel.SeverityMedium, uuidish(i)))
	}
	if blocker.IsBlocked("203.0.113.6") {
		t.Error("medium-severity threats must not reach a High threshold")
	}
}

// Whitelisted and exempt addresses are never blocked, however much they
// trip detection: your own monitoring must not be able to lock itself out.
func TestAutoBlockerRespectsExemptions(t *testing.T) {
	ctx := context.Background()
	blocker := newFakeBlocker()
	blocker.whitelisted["198.51.100.9"] = true

	config := autoBlockConfig()
	config.ExemptIPs = []string{"10.0.0.0/8"}
	ab := NewAutoBlocker(config, blocker, middleware.NewMemoryCounterStore(), nil)

	for i := 0; i < 5; i++ {
		_ = ab.Handle(ctx, autoBlockThreat("198.51.100.9", sentinel.SeverityCritical, uuidish(i)))
		_ = ab.Handle(ctx, autoBlockThreat("10.1.2.3", sentinel.SeverityCritical, uuidish(100+i)))
	}
	if blocker.IsBlocked("198.51.100.9") {
		t.Error("a whitelisted address must never be auto-blocked")
	}
	if blocker.IsBlocked("10.1.2.3") {
		t.Error("an exempt CIDR must never be auto-blocked")
	}
}

// Replicas share the count, so a scanner spreading its requests over
// several instances is blocked on the same total, not N times over.
func TestAutoBlockerCountsAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	shared := middleware.NewMemoryCounterStore()
	defer shared.Close()

	blocker := newFakeBlocker()
	replicas := []*AutoBlocker{
		NewAutoBlocker(autoBlockConfig(), blocker, shared, nil),
		NewAutoBlocker(autoBlockConfig(), blocker, shared, nil),
	}
	for i := 0; i < 3; i++ {
		_ = replicas[i%2].Handle(ctx, autoBlockThreat("203.0.113.7", sentinel.SeverityHigh, uuidish(i)))
	}
	if !blocker.IsBlocked("203.0.113.7") {
		t.Error("three threats split across two replicas must still reach a threshold of three")
	}
}

// The same threat event seen twice counts once: a replayed event cannot
// inflate the count towards a block.
func TestAutoBlockerCountsEachThreatOnce(t *testing.T) {
	ctx := context.Background()
	blocker := newFakeBlocker()
	ab := NewAutoBlocker(autoBlockConfig(), blocker, middleware.NewMemoryCounterStore(), nil)

	for i := 0; i < 5; i++ {
		_ = ab.Handle(ctx, autoBlockThreat("203.0.113.8", sentinel.SeverityHigh, "same-threat-id"))
	}
	if blocker.IsBlocked("203.0.113.8") {
		t.Error("one threat recorded five times must not reach a threshold of three")
	}
}

// Turned off, it does nothing at all.
func TestAutoBlockerDisabled(t *testing.T) {
	ctx := context.Background()
	blocker := newFakeBlocker()
	config := autoBlockConfig()
	config.Enabled = false
	ab := NewAutoBlocker(config, blocker, middleware.NewMemoryCounterStore(), nil)

	for i := 0; i < 10; i++ {
		_ = ab.Handle(ctx, autoBlockThreat("203.0.113.10", sentinel.SeverityCritical, uuidish(i)))
	}
	if blocker.IsBlocked("203.0.113.10") {
		t.Error("a disabled auto-blocker must not block anything")
	}
}

func uuidish(i int) string {
	return "threat-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
}
