// Package countertest is a conformance suite for sentinel.CounterStore
// implementations. Run it from your store's tests:
//
//	func TestConformance(t *testing.T) {
//	    countertest.Run(t, func(t *testing.T) sentinel.CounterStore {
//	        return newStore(t)
//	    })
//	}
//
// The in-memory store and redisstore both pass it, so the rate limiter and
// AuthShield make the same decisions on either.
package countertest

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// Run checks a CounterStore's semantics. newStore must return an empty store.
func Run(t *testing.T, newStore func(t *testing.T) sentinel.CounterStore) {
	// Whole milliseconds near the real clock: Redis stores milliseconds and
	// expires keys on its own clock.
	base := time.Now().Truncate(time.Millisecond)
	ctx := context.Background()

	takeN := func(t *testing.T, s sentinel.CounterStore, key string, limit int, window time.Duration, strategy sentinel.RateLimitStrategy, at time.Time, n int) int {
		t.Helper()
		allowed := 0
		for i := 0; i < n; i++ {
			ok, err := s.Take(ctx, key, limit, window, strategy, at)
			if err != nil {
				t.Fatalf("Take: %v", err)
			}
			if ok {
				allowed++
			}
		}
		return allowed
	}

	t.Run("SlidingWindow", func(t *testing.T) {
		s := newStore(t)
		w := time.Minute
		if got := takeN(t, s, "k", 3, w, sentinel.SlidingWindow, base, 4); got != 3 {
			t.Fatalf("4 requests under a limit of 3: %d allowed", got)
		}
		// Half a window into the next window, the previous one still counts
		// for half: 1.5 used, so two more fit.
		if got := takeN(t, s, "k", 3, w, sentinel.SlidingWindow, base.Add(w*3/2), 3); got != 2 {
			t.Errorf("with the previous window weighted by half: %d allowed, want 2", got)
		}
		// Once a whole window has passed with no requests, nothing counts.
		if got := takeN(t, s, "k", 3, w, sentinel.SlidingWindow, base.Add(4*w), 4); got != 3 {
			t.Errorf("after an idle window: %d allowed, want 3", got)
		}
	})

	t.Run("FixedWindow", func(t *testing.T) {
		s := newStore(t)
		w := time.Minute
		if got := takeN(t, s, "k", 3, w, sentinel.FixedWindow, base, 4); got != 3 {
			t.Fatalf("4 requests under a limit of 3: %d allowed", got)
		}
		if got := takeN(t, s, "k", 3, w, sentinel.FixedWindow, base.Add(w/2), 1); got != 0 {
			t.Errorf("later in the same window: %d allowed, want 0", got)
		}
		if got := takeN(t, s, "k", 3, w, sentinel.FixedWindow, base.Add(w), 4); got != 3 {
			t.Errorf("in the next window: %d allowed, want 3", got)
		}
	})

	t.Run("TokenBucket", func(t *testing.T) {
		s := newStore(t)
		w := time.Second
		if got := takeN(t, s, "k", 2, w, sentinel.TokenBucket, base, 3); got != 2 {
			t.Fatalf("a burst of 3 into a bucket of 2: %d allowed", got)
		}
		// Refills at 2 tokens per second: one token after 500ms.
		if got := takeN(t, s, "k", 2, w, sentinel.TokenBucket, base.Add(500*time.Millisecond), 2); got != 1 {
			t.Errorf("after half a second: %d allowed, want 1", got)
		}
	})

	t.Run("NonPositiveWindowAllows", func(t *testing.T) {
		s := newStore(t)
		if got := takeN(t, s, "k", 1, 0, sentinel.SlidingWindow, base, 3); got != 3 {
			t.Errorf("zero window: %d of 3 allowed, want all", got)
		}
	})

	t.Run("Usage", func(t *testing.T) {
		s := newStore(t)
		if _, ok, err := s.Usage(ctx, "none", sentinel.SlidingWindow, base); err != nil || ok {
			t.Fatalf("unknown key: ok=%v err=%v", ok, err)
		}
		takeN(t, s, "k", 5, time.Minute, sentinel.SlidingWindow, base, 2)
		u, ok, err := s.Usage(ctx, "k", sentinel.SlidingWindow, base)
		if err != nil || !ok {
			t.Fatalf("Usage: ok=%v err=%v", ok, err)
		}
		if u.Used != 2 || u.Limit != 5 || !u.WindowEnd.Equal(base.Add(time.Minute)) {
			t.Errorf("usage = %+v, want 2 of 5 until %v", u, base.Add(time.Minute))
		}
		if _, ok, _ := s.Usage(ctx, "k", sentinel.SlidingWindow, base.Add(2*time.Minute)); ok {
			t.Error("a counter idle for two windows is still reported")
		}
	})

	t.Run("RecordAndCount", func(t *testing.T) {
		s := newStore(t)
		w := time.Minute
		record := func(member string, at time.Duration, want int) {
			t.Helper()
			n, err := s.Record(ctx, "set", member, w, base.Add(at))
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if n != want {
				t.Errorf("Record(%s at +%v) = %d, want %d", member, at, n, want)
			}
		}
		count := func(at time.Duration, want int) {
			t.Helper()
			n, err := s.Count(ctx, "set", w, base.Add(at))
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if n != want {
				t.Errorf("Count at +%v = %d, want %d", at, n, want)
			}
		}
		record("a", 0, 1)
		record("b", 10*time.Second, 2)
		record("a", 20*time.Second, 2) // refreshes a
		count(65*time.Second, 2)       // a@20s and b@10s are both within the minute
		count(75*time.Second, 1)       // b@10s has aged out
		record("c", 90*time.Second, 1) // a and b are dropped
		count(90*time.Second, 1)
		if n, err := s.Count(ctx, "missing", w, base); err != nil || n != 0 {
			t.Errorf("Count on a missing set = %d, %v", n, err)
		}
	})

	t.Run("Until", func(t *testing.T) {
		s := newStore(t)
		if got, err := s.Until(ctx, "lock", base); err != nil || !got.IsZero() {
			t.Fatalf("missing deadline = %v, %v", got, err)
		}
		deadline := base.Add(time.Minute)
		if err := s.SetUntil(ctx, "lock", deadline); err != nil {
			t.Fatalf("SetUntil: %v", err)
		}
		if got, _ := s.Until(ctx, "lock", base); got.UnixMilli() != deadline.UnixMilli() {
			t.Errorf("Until = %v, want %v", got, deadline)
		}
		if got, _ := s.Until(ctx, "lock", deadline); !got.IsZero() {
			t.Errorf("a passed deadline is still reported: %v", got)
		}
	})

	t.Run("KeysAndDelete", func(t *testing.T) {
		s := newStore(t)
		takeN(t, s, "rl:a", 5, time.Minute, sentinel.SlidingWindow, base, 1)
		takeN(t, s, "rl:b", 5, time.Minute, sentinel.SlidingWindow, base, 1)
		if _, err := s.Record(ctx, "as:x", "m", time.Minute, base); err != nil {
			t.Fatal(err)
		}
		if err := s.SetUntil(ctx, "as:y", base.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		keys := func(prefix string) []string {
			t.Helper()
			k, err := s.Keys(ctx, prefix)
			if err != nil {
				t.Fatalf("Keys: %v", err)
			}
			sort.Strings(k)
			return k
		}
		if got := keys("rl:"); len(got) != 2 || got[0] != "rl:a" || got[1] != "rl:b" {
			t.Errorf(`Keys("rl:") = %v`, got)
		}
		if got := keys("as:"); len(got) != 2 || got[0] != "as:x" || got[1] != "as:y" {
			t.Errorf(`Keys("as:") = %v`, got)
		}
		if existed, err := s.Delete(ctx, "rl:a", "as:x"); err != nil || !existed {
			t.Errorf("Delete of existing keys = %v, %v", existed, err)
		}
		if existed, err := s.Delete(ctx, "missing"); err != nil || existed {
			t.Errorf("Delete of a missing key = %v, %v", existed, err)
		}
		if got := keys("rl:"); len(got) != 1 || got[0] != "rl:b" {
			t.Errorf(`Keys("rl:") after delete = %v`, got)
		}
		if got := keys("as:"); len(got) != 1 || got[0] != "as:y" {
			t.Errorf(`Keys("as:") after delete = %v`, got)
		}
	})

	t.Run("ConcurrentTakes", func(t *testing.T) {
		s := newStore(t)
		var allowed atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := s.Take(ctx, "c", 10, time.Minute, sentinel.SlidingWindow, base)
				if err != nil {
					t.Errorf("Take: %v", err)
				}
				if ok {
					allowed.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := allowed.Load(); got != 10 {
			t.Errorf("50 concurrent requests under a limit of 10: %d allowed", got)
		}
	})
}
