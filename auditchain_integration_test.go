package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MUKE-coder/sentinel/v2/storage/auditchain"
	"github.com/gin-gonic/gin"
)

// TestMountE_AuditEntriesAreChained: entries written through Mount's
// pipeline are linked into a hash chain and verify through the API.
func TestMountE_AuditEntriesAreChained(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	r := gin.New()
	cfg := Config{
		Storage:   StorageConfig{Driver: Memory, AuditKey: "0123456789abcdef0123456789abcdef"},
		Dashboard: DashboardConfig{Password: "correct-horse-battery", SecretKey: "integration-secret"},
	}
	if err := MountE(r, nil, cfg); err != nil {
		t.Fatalf("MountE: %v", err)
	}

	// A dashboard login writes an audit entry through the pipeline.
	req := httptest.NewRequest("POST", "/sentinel/api/auth/login", strings.NewReader(`{"username":"admin","password":"correct-horse-battery"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var login struct {
		Token string `json:"token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &login) != nil {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		req := httptest.NewRequest("GET", "/sentinel/api/audit-logs/verify", nil)
		req.Header.Set("Authorization", "Bearer "+login.Token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Data auditchain.Report `json:"data"`
		}
		json.Unmarshal(w.Body.Bytes(), &body)
		if body.Data.Checked >= 1 {
			if !body.Data.OK || !body.Data.Keyed || body.Data.Unchained != 0 {
				t.Fatalf("audit entries from Mount should be chained, keyed, and verify: %+v", body.Data)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no chained audit entry appeared: %s", w.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
