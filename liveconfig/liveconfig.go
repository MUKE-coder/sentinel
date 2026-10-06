// Package liveconfig keeps the settings the dashboard changes at runtime in
// storage, so a change outlives the process that served the request and
// reaches every replica.
//
// A change goes: apply it to the running components, then store a snapshot
// of them. Each replica polls for a newer revision and applies what it
// finds, so a change made on one replica takes effect on the others within
// Storage.SyncInterval. Stored settings also win at startup, which is what
// makes a dashboard change survive a restart or a deploy; Reset discards
// them and puts the configured values back.
package liveconfig

import (
	"context"
	"log"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/storage"
)

// WAFTarget is the running WAF's mode and per-category sensitivity. The
// setters validate, so a stored document written by an older or newer
// version can be rejected one field at a time rather than taken on trust.
type WAFTarget interface {
	Mode() sentinel.WAFMode
	Rules() sentinel.RuleSet
	SetMode(mode sentinel.WAFMode) error
	SetRules(rules sentinel.RuleSet) error
}

// CustomRuleTarget is the running custom-rule set. AddRule replaces a rule
// with the same ID, so applying a snapshot twice is harmless.
type CustomRuleTarget interface {
	ListRules() []sentinel.WAFRule
	AddRule(rule sentinel.WAFRule) error
	RemoveRule(id string) bool
}

// LimiterTarget is the running rate limiter's per-route limits.
type LimiterTarget interface {
	RouteLimits() map[string]sentinel.Limit
	SetRouteLimits(byRoute map[string]sentinel.Limit)
}

// AlertTarget is the running alert dispatcher's severity threshold.
type AlertTarget interface {
	MinSeverity() sentinel.Severity
	SetMinSeverity(severity sentinel.Severity)
}

// Targets are the running components a Manager reads snapshots from and
// applies stored settings to. A nil target is skipped — a disabled WAF has
// no mode to apply.
type Targets struct {
	WAF         WAFTarget
	CustomRules CustomRuleTarget
	Limiter     LimiterTarget
	Alerts      AlertTarget
}

// Manager applies stored settings to the running components and persists
// changes made through the dashboard.
type Manager struct {
	store   storage.SettingsStore
	targets Targets

	mu      sync.Mutex
	applied int64 // revision last applied here; 0 means "the configured values"

	// epoch counts local changes (saves and resets). A poll reads storage
	// without the lock held, so it stamps the epoch first and drops its
	// result if a local change landed meanwhile — otherwise a read already
	// in flight can put back settings that were just discarded.
	epoch int64

	// baseline is what Config asked for, captured before any stored
	// document is applied, so Reset has something to go back to.
	baseline sentinel.LiveSettings

	stopOnce sync.Once
	stop     chan struct{}

	logf func(format string, args ...any)
}

// New returns a Manager for the running components in targets. Call it after
// the components are built from Config and before applying anything stored:
// the configured state is the baseline Reset returns to.
func New(store storage.SettingsStore, targets Targets) *Manager {
	m := &Manager{
		store:   store,
		targets: targets,
		stop:    make(chan struct{}),
		logf:    log.Printf,
	}
	m.baseline = m.snapshot()
	return m
}

// Load applies the stored document, if there is one, and reports whether it
// applied anything.
func (m *Manager) Load(ctx context.Context) (bool, error) {
	doc, err := m.store.LiveSettings(ctx)
	if err != nil || doc == nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apply(*doc)
	m.applied = doc.Revision
	return true, nil
}

// Save stores a snapshot of the running components. Call it after applying a
// change to them: by names the dashboard user who made it.
func (m *Manager) Save(ctx context.Context, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc := m.snapshot()
	doc.UpdatedBy = by
	m.epoch++
	if err := m.store.SaveLiveSettings(ctx, &doc); err != nil {
		return err
	}
	m.applied = doc.Revision
	return nil
}

// Reset discards the stored document and puts the configured values back,
// here and — on their next poll — on every other replica.
func (m *Manager) Reset(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epoch++
	if err := m.store.ClearLiveSettings(ctx); err != nil {
		return err
	}
	m.apply(m.baseline)
	m.applied = 0
	return nil
}

// Stored returns the stored document, or nil when the configured values are
// in force.
func (m *Manager) Stored(ctx context.Context) (*sentinel.LiveSettings, error) {
	return m.store.LiveSettings(ctx)
}

// Baseline returns the settings Config asked for.
func (m *Manager) Baseline() sentinel.LiveSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.baseline.Clone()
}

// Watch polls storage every interval and applies settings changed on another
// replica, until ctx is done or Stop is called. A non-positive interval
// doesn't poll: this replica then only sees its own changes.
func (m *Manager) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stop:
			return
		case <-ticker.C:
			m.poll(ctx)
		}
	}
}

// Stop ends Watch.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stop) })
}

// poll applies a newer stored document, or the configured values if the
// document was cleared. A read error keeps what is running: the next tick
// retries.
func (m *Manager) poll(ctx context.Context) {
	m.mu.Lock()
	epoch := m.epoch
	m.mu.Unlock()

	doc, err := m.store.LiveSettings(ctx)
	if err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epoch != epoch {
		// A save or reset here landed while this read was in flight; that
		// change already applied what it wanted, so this read is stale.
		return
	}
	switch {
	case doc == nil && m.applied != 0:
		m.apply(m.baseline)
		m.applied = 0
		m.logf("[sentinel] dashboard settings were cleared elsewhere; configured values restored")
	case doc != nil && doc.Revision > m.applied:
		m.apply(*doc)
		m.applied = doc.Revision
		m.logf("[sentinel] applied dashboard settings revision %d (changed by %q)", doc.Revision, doc.UpdatedBy)
	}
}

// snapshot reads the running settings. The caller holds m.mu, except in New.
func (m *Manager) snapshot() sentinel.LiveSettings {
	var doc sentinel.LiveSettings
	if t := m.targets.WAF; t != nil {
		doc.WAFMode, doc.WAFRules = t.Mode(), t.Rules()
	}
	if t := m.targets.CustomRules; t != nil {
		doc.CustomRules = t.ListRules()
	}
	if t := m.targets.Limiter; t != nil {
		doc.RouteLimits = t.RouteLimits()
	}
	if t := m.targets.Alerts; t != nil {
		doc.AlertMinSeverity = t.MinSeverity()
	}
	return doc
}

// apply writes doc onto the running components. The caller holds m.mu.
func (m *Manager) apply(doc sentinel.LiveSettings) {
	if t := m.targets.WAF; t != nil {
		if doc.WAFMode != "" {
			if err := t.SetMode(doc.WAFMode); err != nil {
				m.logf("[sentinel] dashboard settings: WAF mode %q not applied: %v", doc.WAFMode, err)
			}
		}
		if doc.WAFRules != (sentinel.RuleSet{}) {
			if err := t.SetRules(doc.WAFRules); err != nil {
				m.logf("[sentinel] dashboard settings: WAF sensitivity not applied: %v", err)
			}
		}
	}
	if t := m.targets.CustomRules; t != nil && doc.CustomRules != nil {
		// The snapshot is the whole rule set: a rule deleted on another
		// replica has to disappear here too.
		keep := make(map[string]bool, len(doc.CustomRules))
		for _, rule := range doc.CustomRules {
			keep[rule.ID] = true
			if err := t.AddRule(rule); err != nil {
				m.logf("[sentinel] dashboard settings: custom rule %q not applied: %v", rule.ID, err)
			}
		}
		for _, rule := range t.ListRules() {
			if !keep[rule.ID] {
				t.RemoveRule(rule.ID)
			}
		}
	}
	if t := m.targets.Limiter; t != nil && doc.RouteLimits != nil {
		t.SetRouteLimits(doc.RouteLimits)
	}
	if t := m.targets.Alerts; t != nil && doc.AlertMinSeverity != "" {
		t.SetMinSeverity(doc.AlertMinSeverity)
	}
}
