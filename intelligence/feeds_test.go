package intelligence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const dropText = `; Spamhaus DROP List 2026/09/11 - (c) 2026 The Spamhaus Project
; Last-Modified: Thu, 11 Sep 2026 10:00:00 GMT
1.10.16.0/20 ; SBL256894
2.56.192.0/22 ; SBL459831
`

const fireholText = `#
# firehol_level1
#
5.188.10.0/23
203.0.113.9
10.0.0.0/8
2001:db8:bad::/48
not-an-ip
`

const dropJSON = `{"cidr":"45.12.0.0/16","sblid":"SBL1","rir":"ripencc"}
{"type":"metadata","timestamp":1757584800,"size":1,"records":1}
`

func TestParseFeed_Formats(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want int
	}{
		"spamhaus drop text": {dropText, 2},
		"firehol netset":     {fireholText, 4},
		"spamhaus ndjson":    {dropJSON, 1},
	} {
		got, err := ParseFeed(strings.NewReader(tc.in))
		if err != nil || len(got) != tc.want {
			t.Errorf("%s: got %d prefixes (err %v), want %d", name, len(got), err, tc.want)
		}
	}
}

func TestFeedBlocklist_Lookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/drop.txt":
			w.Write([]byte(dropText))
		case "/firehol.netset":
			w.Write([]byte(fireholText))
		}
	}))
	defer srv.Close()

	f := NewFeedBlocklist([]string{srv.URL + "/drop.txt", srv.URL + "/firehol.netset"}, srv.Client())
	f.Refresh(context.Background())

	for ip, want := range map[string]bool{
		"1.10.16.1":         true,  // inside a /20
		"1.10.31.255":       true,  // last address of the /20
		"1.10.32.0":         false, // just past it
		"203.0.113.9":       true,  // single address
		"203.0.113.10":      false,
		"10.200.1.1":        true,
		"::ffff:10.1.1.1":   true, // IPv4-mapped form of a listed address
		"2001:db8:bad:1::5": true,
		"2001:db8:bee::1":   false,
		"8.8.8.8":           false,
		"garbage":           false,
	} {
		if got := f.IsBlocked(ip); got != want {
			t.Errorf("IsBlocked(%s) = %v, want %v", ip, got, want)
		}
	}

	for _, st := range f.Status() {
		if st.Error != "" || st.Entries == 0 || st.LastRefresh.IsZero() {
			t.Errorf("feed %s status: %+v", st.URL, st)
		}
	}
}

// TestFeedBlocklist_KeepsLastGoodCopy: a feed outage must not unblock
// everything it listed.
func TestFeedBlocklist_KeepsLastGoodCopy(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer srv.Close()

	f := NewFeedBlocklist([]string{srv.URL}, srv.Client())
	f.Refresh(context.Background())
	fail.Store(true)
	f.Refresh(context.Background())

	if !f.IsBlocked("198.51.100.7") {
		t.Error("a failed refresh dropped the previous entries")
	}
	if st := f.Status()[0]; st.Error == "" || st.Entries != 1 {
		t.Errorf("status should report the error and keep the count: %+v", st)
	}
}

func TestMergeRanges_OverlapsCollapse(t *testing.T) {
	prefixes, _ := ParseFeed(strings.NewReader("10.0.0.0/8\n10.1.0.0/16\n10.255.255.255\n11.0.0.0/8\n"))
	merged := mergeRanges(prefixes)
	if len(merged) != 2 {
		t.Fatalf("expected 10/8 and 11/8 after merging, got %d ranges", len(merged))
	}
}
