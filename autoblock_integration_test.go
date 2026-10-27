package sentinel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// The scan this is modelled on: one address asking for a list of env files,
// every request detected, recorded, and answered — 18,405 rows in a threat
// log, all of them "Logged". With AutoBlock on, the address is blocked a
// few requests in and the rest of the scan gets nothing.
func TestMountE_AutoBlockStopsEnvScanner(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	r := gin.New()
	cfg := Config{
		Storage:   StorageConfig{Driver: Memory},
		Dashboard: DashboardConfig{Password: "correct-horse-battery", SecretKey: "autoblock-secret"},
		// Log mode, as a deployment that hasn't turned blocking on yet:
		// the scanner's requests are recorded but not refused.
		WAF: WAFConfig{Enabled: true, Mode: ModeLog},
		AutoBlock: AutoBlockConfig{
			Enabled:     true,
			Threats:     5,
			Window:      time.Minute,
			Duration:    time.Hour,
			MinSeverity: SeverityHigh,
			ExemptIPs:   []string{"198.51.100.0/24"},
		},
	}
	if err := MountE(r, nil, cfg); err != nil {
		t.Fatalf("MountE: %v", err)
	}
	r.GET("/:probe", func(c *gin.Context) { c.Status(http.StatusNotFound) })

	get := func(path, ip string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = ip + ":5000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// The paths from the log, in the order they arrived.
	probes := []string{
		"/.env", "/.env.local", "/.env.production", "/.env.prod", "/gemini.env",
		"/sendgrid.env", "/.env.dev", "/.env.development", "/web/.env", "/server/.env",
	}

	scanner := "203.0.113.66"
	for _, probe := range probes {
		get(probe, scanner)
	}

	// The pipeline is asynchronous, so give the block a moment to land.
	deadline := time.Now().Add(5 * time.Second)
	for get("/.env", scanner) != http.StatusForbidden {
		if time.Now().After(deadline) {
			t.Fatal("the scanner was never blocked after ten detected probes")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Being blocked covers everything, not just the probes.
	if code := get("/", scanner); code != http.StatusForbidden {
		t.Errorf("a blocked scanner must be refused everywhere: got %d", code)
	}

	// Other clients are untouched, and an exempt range never gets blocked
	// however much it trips detection.
	if code := get("/", "203.0.113.90"); code == http.StatusForbidden {
		t.Error("an unrelated client must not be blocked")
	}
	exempt := "198.51.100.4"
	for _, probe := range probes {
		get(probe, exempt)
	}
	time.Sleep(200 * time.Millisecond)
	if code := get("/", exempt); code == http.StatusForbidden {
		t.Error("an address in AutoBlock.ExemptIPs must never be auto-blocked")
	}
}

// Without AutoBlock nothing changes: the scan is recorded and answered, as
// it was before.
func TestMountE_WithoutAutoBlockScannerKeepsGoing(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	r := gin.New()
	if err := MountE(r, nil, Config{
		Storage:   StorageConfig{Driver: Memory},
		Dashboard: DashboardConfig{Password: "correct-horse-battery", SecretKey: "no-autoblock"},
		WAF:       WAFConfig{Enabled: true, Mode: ModeLog},
	}); err != nil {
		t.Fatalf("MountE: %v", err)
	}
	r.GET("/:probe", func(c *gin.Context) { c.Status(http.StatusNotFound) })

	get := func(path string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "203.0.113.67:5000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	for i := 0; i < 20; i++ {
		get("/.env")
	}
	time.Sleep(200 * time.Millisecond)
	if code := get("/.env"); code == http.StatusForbidden {
		t.Errorf("with AutoBlock off nothing should be blocked, got %d", code)
	}
}
