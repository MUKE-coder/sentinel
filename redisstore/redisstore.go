// Package redisstore is a Redis-backed sentinel.CounterStore: rate limits and
// AuthShield lockouts that hold across every replica of an application.
//
//	client := redis.NewClient(&redis.Options{Addr: "redis:6379"})
//	sentinel.Mount(r, nil, sentinel.Config{
//	    Counters:  redisstore.New(client),
//	    RateLimit: sentinel.RateLimitConfig{Enabled: true, ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute}},
//	})
//
// Each rate-limit decision is one Lua script, so two replicas can't both
// take the last slot. Times are stored in milliseconds. When Redis is
// unreachable, the rate limiter and AuthShield fail open and log the error
// at most once a minute; the client's own timeouts bound how long a request
// waits first.
package redisstore

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/redis/go-redis/v9"
)

// Store is a sentinel.CounterStore backed by Redis. It works with a single
// server, Sentinel failover, or a cluster: every script touches one key.
type Store struct {
	client redis.UniversalClient
	prefix string
}

var _ sentinel.CounterStore = (*Store)(nil)

// Option configures a Store.
type Option func(*Store)

// WithPrefix sets the prefix of every key the store writes (default
// "sentinel:"). Give each application that shares a Redis its own prefix.
func WithPrefix(prefix string) Option {
	return func(s *Store) { s.prefix = prefix }
}

// New returns a Store that keeps its counters in client.
func New(client redis.UniversalClient, opts ...Option) *Store {
	s := &Store{client: client, prefix: "sentinel:"}
	for _, o := range opts {
		o(s)
	}
	return s
}

// takeScript makes one rate-limit decision. It is the in-memory limiter's
// arithmetic (middleware/memcounters.go) in milliseconds; package
// countertest holds the two to the same results.
var takeScript = redis.NewScript(`
local strategy = ARGV[1]
local limit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local h = redis.call('HMGET', KEYS[1], 'count', 'prev', 'end', 'tokens', 'last')
local count = tonumber(h[1]) or 0
local prev = tonumber(h[2]) or 0
local wend = tonumber(h[3]) or 0
local tokens = tonumber(h[4]) or 0
local last = tonumber(h[5]) or 0
local allowed = 0
local exp
if strategy == 'fixed_window' then
  if now >= wend then
    count = 0
    wend = now + window
  end
  count = count + 1
  if count <= limit then allowed = 1 end
  exp = wend
elseif strategy == 'token_bucket' then
  if last == 0 then
    tokens = limit
  else
    tokens = math.min(limit, tokens + (now - last) * limit / window)
  end
  last = now
  if tokens >= 1 then
    tokens = tokens - 1
    allowed = 1
  end
  exp = now
  if limit > 0 then exp = now + math.ceil((limit - tokens) / limit * window) end
else
  if wend == 0 then
    wend = now + window
  elseif now >= wend then
    local passed = math.floor((now - wend) / window) + 1
    if passed == 1 then prev = count else prev = 0 end
    count = 0
    wend = wend + passed * window
  end
  local overlap = (wend - now) / window
  if overlap < 0 then overlap = 0 elseif overlap > 1 then overlap = 1 end
  if prev * overlap + count < limit then
    count = count + 1
    allowed = 1
  end
  exp = wend + window
end
redis.call('HSET', KEYS[1], 'count', count, 'prev', prev, 'end', wend, 'tokens', tostring(tokens),
  'last', last, 'limit', limit, 'window', window, 'exp', exp)
local ttl = exp - now
if ttl < 1 then ttl = 1 end
redis.call('PEXPIRE', KEYS[1], math.ceil(ttl))
return allowed
`)

// recordScript drops set members at or before the cutoff, adds one, and
// returns the set's size.
var recordScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[3])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return redis.call('ZCARD', KEYS[1])
`)

// Take implements sentinel.CounterStore.
func (s *Store) Take(ctx context.Context, key string, limit int, window time.Duration, strategy sentinel.RateLimitStrategy, now time.Time) (bool, error) {
	if window <= 0 {
		return true, nil
	}
	n, err := takeScript.Run(ctx, s.client, []string{s.prefix + key},
		string(strategy), limit, millis(window), now.UnixMilli()).Int()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Usage implements sentinel.CounterStore.
func (s *Store) Usage(ctx context.Context, key string, strategy sentinel.RateLimitStrategy, now time.Time) (sentinel.CounterUsage, bool, error) {
	vals, err := s.client.HMGet(ctx, s.prefix+key, "count", "prev", "end", "tokens", "last", "limit", "window", "exp").Result()
	if err != nil {
		return sentinel.CounterUsage{}, false, err
	}
	if vals[5] == nil {
		return sentinel.CounterUsage{}, false, nil
	}
	num := func(i int) float64 {
		str, _ := vals[i].(string)
		v, _ := strconv.ParseFloat(str, 64)
		return v
	}
	count, prev, end, tokens, last := num(0), num(1), num(2), num(3), num(4)
	limit, window, exp := num(5), num(6), num(7)
	nowMs := float64(now.UnixMilli())
	if nowMs >= exp || window <= 0 {
		return sentinel.CounterUsage{}, false, nil
	}

	u := sentinel.CounterUsage{Limit: int(limit), WindowEnd: time.UnixMilli(int64(end))}
	switch strategy {
	case sentinel.FixedWindow:
		if nowMs < end {
			u.Used = count
		}
	case sentinel.TokenBucket:
		if last == 0 {
			tokens = limit
		} else {
			tokens = math.Min(limit, tokens+(nowMs-last)*limit/window)
		}
		u.Used = limit - tokens
		u.WindowEnd = time.UnixMilli(int64(exp))
	default:
		if end == 0 {
			end = nowMs + window
		} else if nowMs >= end {
			passed := math.Floor((nowMs-end)/window) + 1
			if passed == 1 {
				prev = count
			} else {
				prev = 0
			}
			count = 0
			end += passed * window
		}
		u.Used = prev*math.Max(0, math.Min(1, (end-nowMs)/window)) + count
		u.WindowEnd = time.UnixMilli(int64(end))
	}
	return u, true, nil
}

// Record implements sentinel.CounterStore.
func (s *Store) Record(ctx context.Context, key, member string, window time.Duration, now time.Time) (int, error) {
	nowMs := now.UnixMilli()
	return recordScript.Run(ctx, s.client, []string{s.prefix + key},
		member, nowMs, nowMs-window.Milliseconds(), millis(window)).Int()
}

// Count implements sentinel.CounterStore.
func (s *Store) Count(ctx context.Context, key string, window time.Duration, now time.Time) (int, error) {
	cutoff := now.UnixMilli() - window.Milliseconds()
	n, err := s.client.ZCount(ctx, s.prefix+key, "("+strconv.FormatInt(cutoff, 10), "+inf").Result()
	return int(n), err
}

// SetUntil implements sentinel.CounterStore.
func (s *Store) SetUntil(ctx context.Context, key string, until time.Time) error {
	ttl := time.Until(until)
	if ttl <= 0 {
		return s.client.Del(ctx, s.prefix+key).Err()
	}
	return s.client.Set(ctx, s.prefix+key, until.UnixMilli(), ttl).Err()
}

// Until implements sentinel.CounterStore.
func (s *Store) Until(ctx context.Context, key string, now time.Time) (time.Time, error) {
	ms, err := s.client.Get(ctx, s.prefix+key).Int64()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	until := time.UnixMilli(ms)
	if !now.Before(until) {
		return time.Time{}, nil
	}
	return until, nil
}

// Delete implements sentinel.CounterStore.
func (s *Store) Delete(ctx context.Context, keys ...string) (bool, error) {
	if len(keys) == 0 {
		return false, nil
	}
	// One DEL per key: on a cluster the keys can hash to different slots.
	pipe := s.client.Pipeline()
	cmds := make([]*redis.IntCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.Del(ctx, s.prefix+k)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}
	var n int64
	for _, c := range cmds {
		n += c.Val()
	}
	return n > 0, nil
}

// Keys implements sentinel.CounterStore.
func (s *Store) Keys(ctx context.Context, prefix string) ([]string, error) {
	pattern := escapeGlob(s.prefix+prefix) + "*"
	var (
		mu   sync.Mutex
		keys []string
	)
	collect := func(ctx context.Context, c redis.Cmdable) error {
		iter := c.Scan(ctx, 0, pattern, 256).Iterator()
		for iter.Next(ctx) {
			mu.Lock()
			keys = append(keys, strings.TrimPrefix(iter.Val(), s.prefix))
			mu.Unlock()
		}
		return iter.Err()
	}
	if cc, ok := s.client.(*redis.ClusterClient); ok {
		// A cluster spreads keys over its masters; scan each one.
		err := cc.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
			return collect(ctx, node)
		})
		return keys, err
	}
	return keys, collect(ctx, s.client)
}

// millis converts d to whole milliseconds, at least 1.
func millis(d time.Duration) int64 {
	if ms := d.Milliseconds(); ms > 0 {
		return ms
	}
	return 1
}

// escapeGlob escapes the characters SCAN's MATCH treats as a pattern, so a
// username like "a*" lists only its own keys.
func escapeGlob(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*', '?', '[', ']', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
