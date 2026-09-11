package intelligence

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxFeedBytes bounds one feed download. The largest common lists (FireHOL
// level 1/2, Spamhaus DROP) are well under 1 MB.
const maxFeedBytes = 10 << 20

// FeedStatus reports the state of one blocklist feed.
type FeedStatus struct {
	URL         string    `json:"url"`
	Entries     int       `json:"entries"`
	LastRefresh time.Time `json:"last_refresh,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// FeedBlocklist holds IP ranges from public blocklist feeds — Spamhaus DROP,
// FireHOL netsets, and similar plain-text or NDJSON lists — and answers
// IsBlocked from memory, so a new deployment starts with external reputation
// data instead of an empty history. Refresh swaps in the whole set at once;
// a feed that fails to download keeps its last good copy.
type FeedBlocklist struct {
	urls   []string
	client *http.Client

	ranges atomic.Pointer[[]addrRange]

	mu       sync.Mutex
	byURL    map[string][]netip.Prefix
	statuses map[string]*FeedStatus
}

type addrRange struct {
	start, end netip.Addr
}

// NewFeedBlocklist creates a blocklist for the given feed URLs. Use an
// SSRF-safe client (safefetch) in production so a misconfigured feed URL
// cannot reach internal addresses.
func NewFeedBlocklist(urls []string, client *http.Client) *FeedBlocklist {
	f := &FeedBlocklist{
		urls:     urls,
		client:   client,
		byURL:    make(map[string][]netip.Prefix),
		statuses: make(map[string]*FeedStatus),
	}
	for _, u := range urls {
		f.statuses[u] = &FeedStatus{URL: u}
	}
	empty := []addrRange{}
	f.ranges.Store(&empty)
	return f
}

// Run refreshes immediately and then every interval until ctx is done.
func (f *FeedBlocklist) Run(ctx context.Context, interval time.Duration) {
	f.Refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.Refresh(ctx)
		}
	}
}

// Refresh downloads every feed and replaces the blocklist. Feeds that fail
// keep their previous entries; the error is reported in Status.
func (f *FeedBlocklist) Refresh(ctx context.Context) {
	for _, u := range f.urls {
		prefixes, err := f.fetch(ctx, u)
		f.mu.Lock()
		st := f.statuses[u]
		if err != nil {
			st.Error = err.Error()
			log.Printf("[sentinel] blocklist feed %s: %v (keeping %d previous entries)", u, err, len(f.byURL[u]))
		} else {
			f.byURL[u] = prefixes
			st.Entries = len(prefixes)
			st.LastRefresh = time.Now()
			st.Error = ""
		}
		f.mu.Unlock()
	}

	f.mu.Lock()
	var all []netip.Prefix
	for _, p := range f.byURL {
		all = append(all, p...)
	}
	f.mu.Unlock()

	merged := mergeRanges(all)
	f.ranges.Store(&merged)
}

func (f *FeedBlocklist) fetch(ctx context.Context, url string) ([]netip.Prefix, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	prefixes, err := ParseFeed(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no IP ranges found")
	}
	return prefixes, nil
}

// IsBlocked reports whether ip falls inside any feed range.
func (f *FeedBlocklist) IsBlocked(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.WithZone("").Unmap()
	ranges := *f.ranges.Load()
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].start.Compare(addr) > 0 })
	if i == 0 {
		return false
	}
	r := ranges[i-1]
	return r.start.Is4() == addr.Is4() && addr.Compare(r.end) <= 0
}

// Status reports each feed's entry count, last successful refresh, and last
// error.
func (f *FeedBlocklist) Status() []FeedStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FeedStatus, 0, len(f.urls))
	for _, u := range f.urls {
		out = append(out, *f.statuses[u])
	}
	return out
}

// Len returns the number of merged address ranges in effect.
func (f *FeedBlocklist) Len() int { return len(*f.ranges.Load()) }

// ParseFeed reads IPs and CIDR ranges from a blocklist feed. It accepts
// one-entry-per-line text (Spamhaus DROP, FireHOL netsets: the first token of
// each line, with "#" and ";" comments) and NDJSON lines carrying a "cidr"
// field (Spamhaus drop_v4.json). Unparseable lines are skipped.
func ParseFeed(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		var token string
		if line[0] == '{' {
			var entry struct {
				CIDR string `json:"cidr"`
			}
			if json.Unmarshal([]byte(line), &entry) != nil || entry.CIDR == "" {
				continue
			}
			token = entry.CIDR
		} else {
			token = strings.FieldsFunc(line, func(r rune) bool {
				return r == ' ' || r == '\t' || r == ';' || r == ','
			})[0]
		}
		if p, err := netip.ParsePrefix(token); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(token); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, sc.Err()
}

// mergeRanges converts prefixes to sorted, non-overlapping address ranges.
func mergeRanges(prefixes []netip.Prefix) []addrRange {
	ranges := make([]addrRange, 0, len(prefixes))
	for _, p := range prefixes {
		start, end := prefixRange(p)
		ranges = append(ranges, addrRange{start, end})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start.Compare(ranges[j].start) < 0 })

	merged := ranges[:0]
	for _, r := range ranges {
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			if last.start.Is4() == r.start.Is4() && r.start.Compare(last.end) <= 0 {
				if r.end.Compare(last.end) > 0 {
					last.end = r.end
				}
				continue
			}
		}
		merged = append(merged, r)
	}
	return merged
}

// prefixRange returns the first and last address of a prefix.
func prefixRange(p netip.Prefix) (netip.Addr, netip.Addr) {
	p = p.Masked()
	start := p.Addr()
	if start.Is4() {
		a := start.As4()
		host := uint64(32 - p.Bits())
		v := uint64(binary.BigEndian.Uint32(a[:])) | (1<<host - 1)
		var e [4]byte
		binary.BigEndian.PutUint32(e[:], uint32(v))
		return start, netip.AddrFrom4(e)
	}
	b := start.As16()
	for bit := p.Bits(); bit < 128; bit++ {
		b[bit/8] |= 1 << (7 - bit%8)
	}
	return start, netip.AddrFrom16(b)
}
