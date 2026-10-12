package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

func TestIPMatcher(t *testing.T) {
	m := NewIPMatcher([]string{"192.0.2.4", "10.0.0.0/8", "2001:db8::/32", " "})
	for ip, want := range map[string]bool{
		"192.0.2.4":   true,
		"192.0.2.5":   false,
		"10.1.2.3":    true,
		"11.1.2.3":    false,
		"2001:db8::1": true,
		"2001:dba::1": false,
		"not-an-ip":   false,
		"":            false,
	} {
		if got := m.Matches(ip); got != want {
			t.Errorf("Matches(%q) = %v, want %v", ip, got, want)
		}
	}

	if !NewIPMatcher(nil).Empty() {
		t.Error("an empty list must produce an empty matcher")
	}
	var nilMatcher *IPMatcher
	if nilMatcher.Matches("192.0.2.4") {
		t.Error("a nil matcher must match nothing")
	}
}

// WAF.ExcludeIPs has been documented as accepting "IP addresses or CIDR
// ranges" since v2.0, but entries were compared as exact strings: a
// "10.0.0.0/8" entry excluded exactly one client, the one whose address was
// the literal string "10.0.0.0/8" — that is, none.
func TestWAFExcludeIPsHonorsCIDR(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(100)
	pipe.Start(1)
	defer pipe.Stop()

	r := gin.New()
	r.Use(WAFMiddleware(sentinel.WAFConfig{
		Enabled:    true,
		Mode:       sentinel.ModeBlock,
		ExcludeIPs: []string{"10.0.0.0/8"},
	}, store, pipe, nil))
	r.GET("/api/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	attack := "/api/items?id=1'+OR+'1'='1"
	for ip, want := range map[string]int{
		"10.4.5.6":   http.StatusOK,        // inside the excluded range
		"192.0.2.10": http.StatusForbidden, // outside it
	} {
		req := httptest.NewRequest("GET", attack, nil)
		req.RemoteAddr = ip + ":5000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("%s: got %d, want %d", ip, w.Code, want)
		}
	}
}
