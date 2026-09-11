package intelligence

import (
	"context"
	"log"
	"net/netip"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage"
)

// DefaultReputationChecksPerDay keeps live checks under AbuseIPDB's free
// plan (1,000 checks a day), leaving room for dashboard lookups.
const DefaultReputationChecksPerDay = 900

// reputationQueueSize bounds IPs waiting for a check; beyond it new IPs are
// dropped and picked up the next time they attack.
const reputationQueueSize = 1024

// ReputationWatcher checks the reputation of attacking IPs as threat events
// arrive, instead of only when someone looks an IP up in the dashboard. It
// runs as a pipeline handler; checks happen on a background goroutine under
// a daily quota, so a slow or rate-limited AbuseIPDB never stalls the
// pipeline. Results update the actor's AbuseScore and IsKnownBadActor, and
// the checker's AutoBlock applies as usual.
type ReputationWatcher struct {
	checker   *ReputationChecker
	store     storage.Store
	maxPerDay int
	queue     chan string
	stop      chan struct{}
	stopOnce  sync.Once

	mu            sync.Mutex
	day           int64
	used          int
	seen          map[string]bool // queued or checked today
	budgetWarned  bool
	lastErrLogged time.Time
}

// NewReputationWatcher starts a watcher. maxPerDay <= 0 uses
// DefaultReputationChecksPerDay. Call Stop to end its goroutine.
func NewReputationWatcher(checker *ReputationChecker, store storage.Store, maxPerDay int) *ReputationWatcher {
	if maxPerDay <= 0 {
		maxPerDay = DefaultReputationChecksPerDay
	}
	w := &ReputationWatcher{
		checker:   checker,
		store:     store,
		maxPerDay: maxPerDay,
		queue:     make(chan string, reputationQueueSize),
		stop:      make(chan struct{}),
		seen:      make(map[string]bool),
		day:       currentReputationDay(),
	}
	go w.run()
	return w
}

// Stop ends the background goroutine.
func (w *ReputationWatcher) Stop() {
	w.stopOnce.Do(func() { close(w.stop) })
}

// Handle queues the source IP of each threat event for a check.
func (w *ReputationWatcher) Handle(_ context.Context, event pipeline.Event) error {
	if event.Type != pipeline.EventThreat {
		return nil
	}
	if te, ok := event.Payload.(*sentinel.ThreatEvent); ok && te != nil {
		w.enqueue(te.IP)
	}
	return nil
}

func (w *ReputationWatcher) enqueue(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	addr = addr.Unmap()
	// A private, loopback, or link-local address has no public reputation;
	// checking it would only spend quota.
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return
	}
	ip = addr.String()

	w.mu.Lock()
	w.rollDay()
	if w.seen[ip] {
		w.mu.Unlock()
		return
	}
	w.seen[ip] = true
	w.mu.Unlock()

	select {
	case w.queue <- ip:
	default:
		// Queue full: forget it so the next attack from this IP retries.
		w.mu.Lock()
		delete(w.seen, ip)
		w.mu.Unlock()
	}
}

func (w *ReputationWatcher) run() {
	for {
		select {
		case <-w.stop:
			return
		case ip := <-w.queue:
			w.check(ip)
		}
	}
}

func (w *ReputationWatcher) check(ip string) {
	if !w.spend(ip) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := w.checker.CheckReputation(ctx, ip)
	if err != nil {
		w.logThrottled("[sentinel] reputation: live check failed: %v", err)
		return
	}
	if result == nil {
		return
	}

	actor, err := w.store.GetActor(ctx, ip)
	if err != nil || actor == nil {
		return
	}
	// Update a copy: a store may hand out a pointer other goroutines are
	// reading (the in-memory store does).
	updated := *actor
	updated.AbuseScore = result.AbuseScore
	updated.IsKnownBadActor = result.AbuseScore >= w.checker.config.MinAbuseScore
	if updated.ISP == "" {
		updated.ISP = result.ISP
	}
	updated.RiskScore = ComputeRiskScore(&updated)
	if err := w.store.UpsertActor(ctx, &updated); err != nil {
		w.logThrottled("[sentinel] reputation: failed to update actor %s: %v", ip, err)
	}
}

// spend reserves one API call from today's quota. A fresh cached result
// costs nothing.
func (w *ReputationWatcher) spend(ip string) bool {
	if w.checker.cachedFresh(ip) {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rollDay()
	if w.used >= w.maxPerDay {
		if !w.budgetWarned {
			w.budgetWarned = true
			log.Printf("[sentinel] reputation: daily quota of %d live checks spent; resuming at 00:00 UTC", w.maxPerDay)
		}
		return false
	}
	w.used++
	return true
}

// UsedToday returns how many live checks have spent quota today.
func (w *ReputationWatcher) UsedToday() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rollDay()
	return w.used
}

// rollDay resets the quota and seen set at the UTC day boundary. Callers
// hold w.mu.
func (w *ReputationWatcher) rollDay() {
	if day := currentReputationDay(); day != w.day {
		w.day, w.used, w.budgetWarned = day, 0, false
		w.seen = make(map[string]bool)
	}
}

func (w *ReputationWatcher) logThrottled(format string, args ...any) {
	w.mu.Lock()
	skip := time.Since(w.lastErrLogged) < time.Minute
	if !skip {
		w.lastErrLogged = time.Now()
	}
	w.mu.Unlock()
	if !skip {
		log.Printf(format, args...)
	}
}

func currentReputationDay() int64 {
	return time.Now().UTC().Truncate(24 * time.Hour).Unix()
}
