package api

import (
	"net/http"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/reports"
	"github.com/MUKE-coder/sentinel/v2/storage"
	"github.com/gin-gonic/gin"
)

// newReportGenerator builds the compliance report generator and tells it
// about the storage behind it, so every report carries provenance: whether
// the data survives a restart, how long it is kept, and what it can't show.
func newReportGenerator(store storage.Store, config sentinel.Config) *reports.Generator {
	gen := reports.NewGenerator(store)
	gen.SetSourceInfo(reports.SourceInfo{
		StorageDriver:        string(config.Storage.Driver),
		RetentionDays:        config.Storage.RetentionDays,
		AuditRetentionDays:   config.Storage.AuditRetentionDays,
		UserActivityRecorded: config.UserExtractor != nil,
	})
	return gen
}

// refuseEphemeralReport answers 409 for a compliance report requested from
// the in-memory store in release mode. That data is gone after every
// restart, so the report would cover only the time since the last deploy
// while reading as a complete record. ?acknowledge_ephemeral=true overrides
// it for an operator who knows.
func (s *Server) refuseEphemeralReport(c *gin.Context) bool {
	if s.config.Storage.Driver != sentinel.Memory || gin.Mode() != gin.ReleaseMode || c.Query("acknowledge_ephemeral") == "true" {
		return false
	}
	c.JSON(http.StatusConflict, gin.H{
		"error": "Compliance reports are refused on in-memory storage in release mode: the data is lost on every restart, so the report would cover only the time since the last deploy. Configure SQLite or Postgres storage, or pass acknowledge_ephemeral=true.",
		"code":  "EPHEMERAL_STORAGE",
	})
	return true
}
