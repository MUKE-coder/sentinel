package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage/auditchain"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/gin-gonic/gin"
)

func TestVerifyAuditLogsEndpoint(t *testing.T) {
	store := memory.New()
	pipe := pipeline.New(10)
	pipe.Start(1)
	defer pipe.Stop()

	chain := auditchain.New(nil)
	var entries []*sentinel.AuditLog
	for i := 0; i < 3; i++ {
		e := &sentinel.AuditLog{ID: fmt.Sprintf("e%d", i), Timestamp: time.Now().Add(-time.Minute), Action: "DELETE", Resource: "users"}
		chain.Link(e)
		store.SaveAuditLog(t.Context(), e)
		entries = append(entries, e)
	}

	srv := NewServer(store, pipe, nil, nil, sentinel.Config{Dashboard: sentinel.DashboardConfig{SecretKey: "test-secret"}})
	r := gin.New()
	srv.RegisterRoutes(r, "/sentinel")
	token, _ := GenerateToken("test-secret")

	verify := func() auditchain.Report {
		t.Helper()
		req := httptest.NewRequest("GET", "/sentinel/api/audit-logs/verify", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("verify: got %d: %s", w.Code, w.Body.String())
		}
		var body struct {
			Data auditchain.Report `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.Data
	}

	if rep := verify(); !rep.OK || rep.Checked != 3 {
		t.Fatalf("intact chain: %+v", rep)
	}

	entries[1].UserID = "edited-after-the-fact" // the memory store holds this pointer
	if rep := verify(); rep.OK || len(rep.Problems) != 1 || rep.Problems[0].Kind != auditchain.ProblemModified {
		t.Fatalf("expected a modified entry: %+v", rep)
	}
}
