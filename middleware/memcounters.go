package middleware

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// MemoryCounterStore is the in-process sentinel.CounterStore, used when
// Config.Counters is nil. Each process keeps its own counters, so replicas
// don't share rate limits or lockouts — use redisstore for that.
type MemoryCounterStore struct {
	mu        sync.Mutex
	entries   map[string]*counterEntry        // Take, Usage
	sets      map[string]map[string]time.Time // Record, Count
	setExpiry map[string]time.Time
	untils    map[string]time.Time // SetUntil, Until
	stopCh    chan struct{}
	stopOnce  sync.Once
}

var _ sentinel.CounterStore = (*MemoryCounterStore)(nil)

// NewMemoryCounterStore creates an in-process store. A background goroutine
// drops expired counters every 30 seconds until Close is called.
func NewMemoryCounterStore() *MemoryCounterStore {
	s := &MemoryCounterStore{
		entries:   make(map[string]*counterEntry),
		sets:      make(map[string]map[string]time.Time),
		setExpiry: make(map[string]time.Time),
		untils:    make(map[string]time.Time),
		stopCh:    make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Close stops the cleanup goroutine. The store keeps working, but expired
// counters are no longer dropped.
func (s *MemoryCounterStore) Close() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Take implements sentinel.CounterStore.
func (s *MemoryCounterStore) Take(_ context.Context, key string, limit int, window time.Duration, strategy sentinel.RateLimitStrategy, now time.Time) (bool, error) {
	if window <= 0 {
		// A non-positive window never accumulates anything; ValidateConfig
		// reports it.
		return true, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.entries[key]
	if e == nil {
		e = &counterEntry{}
		s.entries[key] = e
	}
	e.limit, e.window = limit, window
	switch strategy {
	case sentinel.FixedWindow:
		return e.takeFixed(now), nil
	case sentinel.TokenBucket:
		return e.takeToken(now), nil
	default:
		return e.takeSliding(now), nil
	}
}

// Usage implements sentinel.CounterStore.
func (s *MemoryCounterStore) Usage(_ context.Context, key string, strategy sentinel.RateLimitStrategy, now time.Time) (sentinel.CounterUsage, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[key]
	if e == nil || !now.Before(e.expires) {
		return sentinel.CounterUsage{}, false, nil
	}
	return e.usageAt(strategy, now), true, nil
}

// Record implements sentinel.CounterStore.
func (s *MemoryCounterStore) Record(_ context.Context, key, member string, window time.Duration, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.sets[key]
	if set == nil {
		set = make(map[string]time.Time)
		s.sets[key] = set
	}
	cutoff := now.Add(-window)
	for m, t := range set {
		if !t.After(cutoff) {
			delete(set, m)
		}
	}
	set[member] = now
	s.setExpiry[key] = now.Add(window)
	return len(set), nil
}

// Count implements sentinel.CounterStore.
func (s *MemoryCounterStore) Count(_ context.Context, key string, window time.Duration, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-window)
	n := 0
	for _, t := range s.sets[key] {
		if t.After(cutoff) {
			n++
		}
	}
	return n, nil
}

// SetUntil implements sentinel.CounterStore.
func (s *MemoryCounterStore) SetUntil(_ context.Context, key string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.untils[key] = until
	return nil
}

// Until implements sentinel.CounterStore.
func (s *MemoryCounterStore) Until(_ context.Context, key string, now time.Time) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.untils[key]; ok && now.Before(t) {
		return t, nil
	}
	return time.Time{}, nil
}

// Delete implements sentinel.CounterStore.
func (s *MemoryCounterStore) Delete(_ context.Context, keys ...string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existed := false
	for _, k := range keys {
		if _, ok := s.entries[k]; ok {
			delete(s.entries, k)
			existed = true
		}
		if _, ok := s.sets[k]; ok {
			delete(s.sets, k)
			delete(s.setExpiry, k)
			existed = true
		}
		if _, ok := s.untils[k]; ok {
			delete(s.untils, k)
			existed = true
		}
	}
	return existed, nil
}

// Keys implements sentinel.CounterStore.
func (s *MemoryCounterStore) Keys(_ context.Context, prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for k := range s.entries {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	for k := range s.sets {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	for k := range s.untils {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (s *MemoryCounterStore) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.dropExpired(time.Now())
		}
	}
}

func (s *MemoryCounterStore) dropExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
	for k, exp := range s.setExpiry {
		if !now.Before(exp) {
			delete(s.sets, k)
			delete(s.setExpiry, k)
		}
	}
	for k, t := range s.untils {
		if !now.Before(t) {
			delete(s.untils, k)
		}
	}
}

// counterEntry is one rate-limit counter's state. Which fields are live
// depends on the strategy it is taken with.
type counterEntry struct {
	limit      int
	window     time.Duration
	count      int       // fixed, sliding: requests counted in the current window
	prevCount  int       // sliding: requests counted in the previous window
	windowEnd  time.Time // fixed, sliding: end of the current window
	tokens     float64   // token bucket: tokens available as of lastRefill
	lastRefill time.Time // token bucket
	expires    time.Time // after this the entry affects no decision and can be dropped
}

// takeFixed counts the request against the current fixed window, which
// starts at the first request after the previous one ended.
func (e *counterEntry) takeFixed(now time.Time) bool {
	if !now.Before(e.windowEnd) {
		e.count = 0
		e.windowEnd = now.Add(e.window)
	}
	e.count++
	e.expires = e.windowEnd
	return e.count <= e.limit
}

// takeSliding approximates a true sliding window from two fixed windows: the
// previous window's count, weighted by how much of it still overlaps the
// window ending now, plus the current window's count. Rejected requests are
// not counted.
func (e *counterEntry) takeSliding(now time.Time) bool {
	e.roll(now)
	if e.slidingUsage(now) >= float64(e.limit) {
		return false
	}
	e.count++
	e.expires = e.windowEnd.Add(e.window)
	return true
}

// roll advances the sliding window to the one containing now.
func (e *counterEntry) roll(now time.Time) {
	if e.windowEnd.IsZero() {
		e.windowEnd = now.Add(e.window)
		return
	}
	if now.Before(e.windowEnd) {
		return
	}
	passed := now.Sub(e.windowEnd)/e.window + 1
	if passed == 1 {
		e.prevCount = e.count
	} else {
		e.prevCount = 0
	}
	e.count = 0
	e.windowEnd = e.windowEnd.Add(passed * e.window)
}

func (e *counterEntry) slidingUsage(now time.Time) float64 {
	overlap := float64(e.windowEnd.Sub(now)) / float64(e.window)
	return float64(e.prevCount)*math.Max(0, math.Min(1, overlap)) + float64(e.count)
}

// takeToken spends a token from a bucket that holds up to limit tokens and
// refills at limit tokens per window.
func (e *counterEntry) takeToken(now time.Time) bool {
	e.refill(now)
	allowed := e.tokens >= 1
	if allowed {
		e.tokens--
	}
	e.expires = now.Add(e.untilFull())
	return allowed
}

func (e *counterEntry) refill(now time.Time) {
	if e.lastRefill.IsZero() {
		e.tokens = float64(e.limit)
	} else {
		perNano := float64(e.limit) / float64(e.window)
		e.tokens = math.Min(float64(e.limit), e.tokens+float64(now.Sub(e.lastRefill))*perNano)
	}
	e.lastRefill = now
}

// untilFull is how long the bucket takes to refill completely.
func (e *counterEntry) untilFull() time.Duration {
	if e.limit <= 0 {
		return 0
	}
	return time.Duration((float64(e.limit) - e.tokens) / float64(e.limit) * float64(e.window))
}

// usageAt reports the entry's state as of now. It works on a copy, so it
// never changes the counter.
func (e counterEntry) usageAt(strategy sentinel.RateLimitStrategy, now time.Time) sentinel.CounterUsage {
	u := sentinel.CounterUsage{Limit: e.limit, WindowEnd: e.windowEnd}
	if e.window <= 0 {
		return u
	}
	switch strategy {
	case sentinel.FixedWindow:
		if now.Before(e.windowEnd) {
			u.Used = float64(e.count)
		}
	case sentinel.TokenBucket:
		e.refill(now)
		u.Used = float64(e.limit) - e.tokens
		u.WindowEnd = e.expires
	default:
		e.roll(now)
		u.Used = e.slidingUsage(now)
		u.WindowEnd = e.windowEnd
	}
	return u
}
