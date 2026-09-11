package core

import (
	"context"
	"time"
)

// CounterStore keeps the counters behind rate limiting and AuthShield.
//
// The default store lives in process memory, so every replica counts on its
// own: behind N instances a client gets N times each rate limit and N times
// AuthShield's failed-login budget. Set Config.Counters to a shared store —
// redisstore.New for Redis — and every replica counts against the same
// numbers.
//
// Implementations must be safe for concurrent use. The caller passes the
// current time, so one request's operations share one clock reading. Package
// countertest checks an implementation against the in-memory store's
// behavior.
type CounterStore interface {
	// Take counts one request against key and reports whether it is within
	// limit per window under strategy, with the same semantics as the
	// in-memory limiter: SlidingWindow and TokenBucket don't count a
	// rejected request, FixedWindow counts every attempt.
	Take(ctx context.Context, key string, limit int, window time.Duration, strategy RateLimitStrategy, now time.Time) (bool, error)

	// Usage reports how much of key's limit is used as of now, the limit it
	// was last taken with, and when the current window ends (FixedWindow,
	// SlidingWindow) or the bucket is full again (TokenBucket). ok is false
	// when key has no live counter.
	Usage(ctx context.Context, key string, strategy RateLimitStrategy, now time.Time) (u CounterUsage, ok bool, err error)

	// Record drops the members of the set at key stamped at or before
	// now-window, adds member stamped now (refreshing its stamp if it is
	// already there), and returns how many members the set holds.
	Record(ctx context.Context, key, member string, window time.Duration, now time.Time) (int, error)

	// Count returns how many members of the set at key were stamped after
	// now-window.
	Count(ctx context.Context, key string, window time.Duration, now time.Time) (int, error)

	// SetUntil stores a deadline at key. It disappears once it has passed.
	SetUntil(ctx context.Context, key string, until time.Time) error

	// Until returns the deadline at key, or the zero time if there is none
	// or it has passed.
	Until(ctx context.Context, key string, now time.Time) (time.Time, error)

	// Delete removes keys of any kind and reports whether any existed.
	Delete(ctx context.Context, keys ...string) (bool, error)

	// Keys lists keys starting with prefix, for dashboard views. It may
	// include keys that expired moments ago; Usage, Count, and Until report
	// those as empty.
	Keys(ctx context.Context, prefix string) ([]string, error)
}

// CounterUsage is a rate-limit counter's state, returned by CounterStore.Usage.
type CounterUsage struct {
	Limit     int
	Used      float64
	WindowEnd time.Time
}
