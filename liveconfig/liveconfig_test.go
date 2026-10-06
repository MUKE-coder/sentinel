package liveconfig

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/storage"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
)

// The fakes lock like the real components do: Watch applies settings from
// its own goroutine while a test reads them.
type fakeWAF struct {
	mu       sync.Mutex
	mode     sentinel.WAFMode
	rules    sentinel.RuleSet
	modeErr  error
	rulesErr error
}

func (f *fakeWAF) Mode() sentinel.WAFMode {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode
}

func (f *fakeWAF) Rules() sentinel.RuleSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules
}

func (f *fakeWAF) SetMode(m sentinel.WAFMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modeErr != nil {
		return f.modeErr
	}
	f.mode = m
	return nil
}

func (f *fakeWAF) SetRules(r sentinel.RuleSet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rulesErr != nil {
		return f.rulesErr
	}
	f.rules = r
	return nil
}

func (f *fakeWAF) setModeErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modeErr = err
}

type fakeRules struct {
	mu    sync.Mutex
	rules map[string]sentinel.WAFRule
}

func newFakeRules(initial ...sentinel.WAFRule) *fakeRules {
	f := &fakeRules{rules: map[string]sentinel.WAFRule{}}
	for _, r := range initial {
		f.rules[r.ID] = r
	}
	return f
}
func (f *fakeRules) ListRules() []sentinel.WAFRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]sentinel.WAFRule, 0, len(f.rules))
	for _, r := range f.rules {
		out = append(out, r)
	}
	return out
}
func (f *fakeRules) AddRule(r sentinel.WAFRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[r.ID] = r
	return nil
}
func (f *fakeRules) RemoveRule(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.rules[id]
	delete(f.rules, id)
	return ok
}
func (f *fakeRules) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.rules[id]
	return ok
}

type fakeLimiter struct {
	mu     sync.Mutex
	routes map[string]sentinel.Limit
}

func (f *fakeLimiter) RouteLimits() map[string]sentinel.Limit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.routes
}
func (f *fakeLimiter) SetRouteLimits(r map[string]sentinel.Limit) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = r
}
func (f *fakeLimiter) limit(route string) sentinel.Limit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.routes[route]
}

type fakeAlerts struct {
	mu  sync.Mutex
	sev sentinel.Severity
}

func (f *fakeAlerts) MinSeverity() sentinel.Severity {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sev
}
func (f *fakeAlerts) SetMinSeverity(s sentinel.Severity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sev = s
}

// replica builds a manager over its own components, as a second process
// would, sharing one store.
func replica(store storage.SettingsStore) (*Manager, *fakeWAF, *fakeRules, *fakeLimiter, *fakeAlerts) {
	waf := &fakeWAF{mode: sentinel.ModeLog, rules: sentinel.RuleSet{SQLInjection: sentinel.RuleStrict}}
	rules := newFakeRules(sentinel.WAFRule{ID: "configured", Pattern: "evil"})
	limiter := &fakeLimiter{routes: map[string]sentinel.Limit{}}
	alerts := &fakeAlerts{sev: sentinel.SeverityHigh}
	m := New(store, Targets{WAF: waf, CustomRules: rules, Limiter: limiter, Alerts: alerts})
	return m, waf, rules, limiter, alerts
}

// A change saved on one replica reaches another, and a restart keeps it.
func TestSettingsReachOtherReplicas(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	a, wafA, rulesA, limiterA, alertsA := replica(store)
	b, wafB, rulesB, limiterB, alertsB := replica(store)

	// Replica A: the dashboard changes the mode, a rule, a route limit and
	// the alert threshold, each applied to A's components before the save.
	if err := wafA.SetMode(sentinel.ModeBlock); err != nil {
		t.Fatal(err)
	}
	if err := rulesA.AddRule(sentinel.WAFRule{ID: "added", Pattern: "worse"}); err != nil {
		t.Fatal(err)
	}
	limiterA.SetRouteLimits(map[string]sentinel.Limit{"/api/login": {Requests: 5, Window: time.Minute}})
	alertsA.SetMinSeverity(sentinel.SeverityCritical)
	if err := a.Save(ctx, "admin"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Replica B knows nothing until it polls.
	if wafB.Mode() != sentinel.ModeLog {
		t.Fatalf("replica B mode before polling: %s", wafB.Mode())
	}
	b.poll(ctx)

	if wafB.Mode() != sentinel.ModeBlock {
		t.Errorf("replica B mode: %s, want block", wafB.Mode())
	}
	if !rulesB.has("added") {
		t.Error("replica B is missing the custom rule added on A")
	}
	if got := limiterB.limit("/api/login"); got.Requests != 5 {
		t.Errorf("replica B route limit: %+v, want 5 requests", got)
	}
	if alertsB.MinSeverity() != sentinel.SeverityCritical {
		t.Errorf("replica B alert threshold: %s, want Critical", alertsB.MinSeverity())
	}

	// A restart is a fresh manager over freshly configured components.
	restarted, wafR, rulesR, _, _ := replica(store)
	applied, err := restarted.Load(ctx)
	if err != nil || !applied {
		t.Fatalf("Load after restart: applied=%v err=%v", applied, err)
	}
	if wafR.Mode() != sentinel.ModeBlock {
		t.Errorf("after a restart the mode is %s, want the stored block", wafR.Mode())
	}
	if !rulesR.has("added") {
		t.Error("after a restart the stored custom rule is missing")
	}
}

// A rule deleted on one replica disappears on the others: the stored
// document is the whole rule set, not a list of additions.
func TestDeletedCustomRuleDisappearsEverywhere(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	a, _, rulesA, _, _ := replica(store)
	b, _, rulesB, _, _ := replica(store)

	rulesA.RemoveRule("configured")
	if err := a.Save(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	b.poll(ctx)

	if rulesB.has("configured") {
		t.Error("a rule deleted on replica A is still live on replica B")
	}
}

// Reset discards the stored settings; every replica goes back to what Config
// asked for.
func TestResetRestoresConfiguredValues(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	a, wafA, _, _, _ := replica(store)
	b, wafB, rulesB, _, _ := replica(store)

	if err := wafA.SetMode(sentinel.ModeBlock); err != nil {
		t.Fatal(err)
	}
	if err := a.Save(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	b.poll(ctx)
	if wafB.Mode() != sentinel.ModeBlock {
		t.Fatalf("replica B did not pick up the change: %s", wafB.Mode())
	}

	if err := a.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if wafA.Mode() != sentinel.ModeLog {
		t.Errorf("replica A after reset: %s, want the configured log", wafA.Mode())
	}

	b.poll(ctx)
	if wafB.Mode() != sentinel.ModeLog {
		t.Errorf("replica B after reset: %s, want the configured log", wafB.Mode())
	}
	if !rulesB.has("configured") {
		t.Error("the configured custom rule is missing after a reset")
	}
}

// Watch applies changes without anyone calling poll.
func TestWatchAppliesChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memory.New()

	a, wafA, _, _, _ := replica(store)
	b, wafB, _, _, _ := replica(store)
	go b.Watch(ctx, 5*time.Millisecond)
	defer b.Stop()

	if err := wafA.SetMode(sentinel.ModeBlock); err != nil {
		t.Fatal(err)
	}
	if err := a.Save(ctx, "admin"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for wafB.Mode() != sentinel.ModeBlock {
		if time.Now().After(deadline) {
			t.Fatal("Watch did not apply the change within 2s")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A setting the running component rejects is logged and skipped; the rest of
// the document still applies.
func TestRejectedSettingDoesNotBlockTheRest(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	a, wafA, _, _, alertsA := replica(store)

	if err := wafA.SetMode(sentinel.ModeBlock); err != nil {
		t.Fatal(err)
	}
	alertsA.SetMinSeverity(sentinel.SeverityLow)
	if err := a.Save(ctx, "admin"); err != nil {
		t.Fatal(err)
	}

	b, wafB, _, _, alertsB := replica(store)
	wafB.setModeErr(errors.New("mode not supported in this build"))
	var logged int
	b.logf = func(string, ...any) { logged++ }

	if _, err := b.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if wafB.Mode() == sentinel.ModeBlock {
		t.Error("a rejected mode must not be applied")
	}
	if alertsB.MinSeverity() != sentinel.SeverityLow {
		t.Errorf("the rest of the document must still apply, alert threshold is %s", alertsB.MinSeverity())
	}
	if logged == 0 {
		t.Error("a rejected setting must be logged")
	}
}

// hookStore runs a function at the moment a read returns, to land another
// operation in the middle of a poll.
type hookStore struct {
	storage.SettingsStore
	onRead func()
}

func (h *hookStore) LiveSettings(ctx context.Context) (*sentinel.LiveSettings, error) {
	doc, err := h.SettingsStore.LiveSettings(ctx)
	if h.onRead != nil {
		h.onRead()
	}
	return doc, err
}

// A poll reads storage without the lock held. If settings are discarded
// while that read is in flight, the stale read must not put them back.
func TestPollDoesNotResurrectDiscardedSettings(t *testing.T) {
	ctx := context.Background()
	store := &hookStore{SettingsStore: memory.New()}
	m, waf, _, _, _ := replica(store)

	if err := waf.SetMode(sentinel.ModeBlock); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(ctx, "admin"); err != nil {
		t.Fatal(err)
	}

	// The next read returns the stored document, but by the time it does,
	// the settings have been discarded.
	var once bool
	store.onRead = func() {
		if once {
			return
		}
		once = true
		if err := m.Reset(ctx); err != nil {
			t.Errorf("Reset: %v", err)
		}
	}

	m.poll(ctx)

	if got := waf.Mode(); got != sentinel.ModeLog {
		t.Errorf("mode is %s: a stale poll put back settings that were discarded", got)
	}
}
