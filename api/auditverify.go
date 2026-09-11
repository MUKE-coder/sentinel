package api

import (
	"net/http"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/storage/auditchain"
	"github.com/gin-gonic/gin"
)

// handleVerifyAuditLogs checks every stored audit entry against the hash
// chain it was written into and reports modified entries, deletions, and
// broken links.
func (s *Server) handleVerifyAuditLogs(c *gin.Context) {
	ctx := c.Request.Context()

	// Snapshot at a fixed end time and de-duplicate by ID: entries written
	// while we page would otherwise shift the offsets and could be read
	// twice, which would look like two entries claiming one position.
	end := time.Now()
	const pageSize = 1000
	seen := make(map[string]bool)
	var entries []*sentinel.AuditLog
	for page := 1; ; page++ {
		logs, total, err := s.store.ListAuditLogs(ctx, sentinel.AuditFilter{EndTime: &end, Page: page, PageSize: pageSize})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
			return
		}
		for _, l := range logs {
			if !seen[l.ID] {
				seen[l.ID] = true
				entries = append(entries, l)
			}
		}
		if len(logs) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": auditchain.Verify(entries, []byte(s.config.Storage.AuditKey))})
}
