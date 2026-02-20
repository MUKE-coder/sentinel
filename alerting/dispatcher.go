// Package alerting provides alert dispatch to Slack, email, and webhooks.
package alerting

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
)

// AlertProvider sends alerts to a specific channel.
type AlertProvider interface {
	// Name returns the provider name (e.g. "slack", "email", "webhook").
	Name() string
	// Send sends an alert for the given threat event.
	Send(ctx context.Context, te *sentinel.ThreatEvent) error
}

// Dispatcher subscribes to the pipeline for threat events with severity >= configured minimum,
// dispatches to all configured providers concurrently, and handles deduplication and retry.
type Dispatcher struct {
	providers   []AlertProvider
	config      sentinel.AlertConfig
	dedup       map[string]time.Time // key: "ip:threat_type" -> last alert time
	mu          sync.Mutex
	dedupWindow time.Duration
	maxRetries  int
	history     []*sentinel.AlertHistory
	historyMu   sync.RWMutex
}

// NewDispatcher creates a new alert dispatcher.
func NewDispatcher(config sentinel.AlertConfig) *Dispatcher {
	return &Dispatcher{
		config:      config,
		dedup:       make(map[string]time.Time),
		dedupWindow: 5 * time.Minute,
		maxRetries:  3,
	}
}

// AddProvider registers an alert provider.
func (d *Dispatcher) AddProvider(p AlertProvider) {
	d.providers = append(d.providers, p)
}

// Handle processes pipeline events and dispatches alerts for qualifying threats.
func (d *Dispatcher) Handle(ctx context.Context, event pipeline.Event) error {
	if event.Type != pipeline.EventThreat {
		return nil
	}

	te, ok := event.Payload.(*sentinel.ThreatEvent)
	if !ok || te == nil {
		return nil
	}

	// Check severity threshold
	if !d.meetsSeverityThreshold(te.Severity) {
		return nil
	}

	// Check dedup
	dedupKey := d.dedupKey(te)
	if d.isDuplicate(dedupKey) {
		return nil
	}

	// Mark as sent
	d.markSent(dedupKey)

	// Dispatch to all providers concurrently
	var wg sync.WaitGroup
	for _, provider := range d.providers {
		wg.Add(1)
		go func(p AlertProvider) {
			defer wg.Done()
			d.sendWithRetry(ctx, p, te)
		}(provider)
	}
	wg.Wait()

	return nil
}

func (d *Dispatcher) sendWithRetry(ctx context.Context, provider AlertProvider, te *sentinel.ThreatEvent) {
	var lastErr error
	for attempt := 0; attempt < d.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				d.recordHistory(te, provider.Name(), false, ctx.Err().Error())
				return
			case <-time.After(backoff):
			}
		}

		if err := provider.Send(ctx, te); err != nil {
			lastErr = err
			log.Printf("[sentinel] alert: %s failed (attempt %d/%d): %v", provider.Name(), attempt+1, d.maxRetries, err)
			continue
		}

		d.recordHistory(te, provider.Name(), true, "")
		return
	}

	errMsg := ""
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	d.recordHistory(te, provider.Name(), false, errMsg)
	log.Printf("[sentinel] alert: %s failed after %d retries for threat %s", provider.Name(), d.maxRetries, te.ID)
}

func (d *Dispatcher) recordHistory(te *sentinel.ThreatEvent, channel string, success bool, errMsg string) {
	threatType := ""
	if len(te.ThreatTypes) > 0 {
		threatType = te.ThreatTypes[0]
	}
	h := &sentinel.AlertHistory{
		ID:         fmt.Sprintf("alert-%s-%s-%d", channel, te.ID, time.Now().UnixNano()),
		Timestamp:  time.Now(),
		ThreatID:   te.ID,
		Channel:    channel,
		Severity:   te.Severity,
		IP:         te.IP,
		ThreatType: threatType,
		Success:    success,
		Error:      errMsg,
	}

	d.historyMu.Lock()
	d.history = append(d.history, h)
	// Keep last 1000 history entries
	if len(d.history) > 1000 {
		d.history = d.history[len(d.history)-1000:]
	}
	d.historyMu.Unlock()
}

// GetHistory returns the alert history.
func (d *Dispatcher) GetHistory() []*sentinel.AlertHistory {
	d.historyMu.RLock()
	defer d.historyMu.RUnlock()
	result := make([]*sentinel.AlertHistory, len(d.history))
	copy(result, d.history)
	return result
}

func (d *Dispatcher) dedupKey(te *sentinel.ThreatEvent) string {
	threatType := ""
	if len(te.ThreatTypes) > 0 {
		threatType = te.ThreatTypes[0]
	}
	return te.IP + ":" + threatType
}

func (d *Dispatcher) isDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if lastSent, ok := d.dedup[key]; ok {
		if time.Since(lastSent) < d.dedupWindow {
			return true
		}
	}
	return false
}

func (d *Dispatcher) markSent(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dedup[key] = time.Now()
}

func (d *Dispatcher) meetsSeverityThreshold(sev sentinel.Severity) bool {
	order := map[sentinel.Severity]int{
		sentinel.SeverityLow:      1,
		sentinel.SeverityMedium:   2,
		sentinel.SeverityHigh:     3,
		sentinel.SeverityCritical: 4,
	}
	return order[sev] >= order[d.config.MinSeverity]
}

// ProviderCount returns the number of registered providers.
func (d *Dispatcher) ProviderCount() int {
	return len(d.providers)
}
