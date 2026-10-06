package api

import (
	"log"
	"net/http"

	"github.com/MUKE-coder/sentinel/v2/liveconfig"
	"github.com/gin-gonic/gin"
)

// SetLiveConfig gives the API server the manager that stores dashboard
// setting changes, so they survive a restart and reach other replicas.
// Without it, a change applies to this process only.
func (s *Server) SetLiveConfig(m *liveconfig.Manager) {
	s.liveConfig = m
}

// persistLiveSettings stores the running settings after a dashboard change.
// It returns text for the response when the change could not be stored —
// the change is already live either way, so a storage failure must not look
// like the change was rejected.
func (s *Server) persistLiveSettings(c *gin.Context) string {
	if s.liveConfig == nil {
		return "Applied to this instance only: the configured storage cannot keep dashboard settings, so this is lost on restart and does not reach other replicas."
	}
	if err := s.liveConfig.Save(c.Request.Context(), s.config.Dashboard.Username); err != nil {
		log.Printf("[sentinel] dashboard settings were not stored: %v", err)
		return "Applied to this instance, but storing it failed, so it is lost on restart and does not reach other replicas. Check the application log."
	}
	return ""
}

// withWarning adds a warning to a response body only when there is one.
func withWarning(body gin.H, warning string) gin.H {
	if warning != "" {
		body["warning"] = warning
	}
	return body
}

// handleGetLiveSettings reports what is stored, what Config asked for, and
// how long a change takes to reach other replicas.
func (s *Server) handleGetLiveSettings(c *gin.Context) {
	data := gin.H{
		"persistable":   s.liveConfig != nil,
		"sync_interval": s.config.Storage.SyncInterval.String(),
	}
	if s.liveConfig == nil {
		data["stored"] = nil
		c.JSON(http.StatusOK, gin.H{"data": data})
		return
	}

	stored, err := s.liveConfig.Stored(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Stored settings could not be read",
			"code":  "INTERNAL_ERROR",
		})
		return
	}
	configured := s.liveConfig.Baseline()
	data["stored"] = stored
	data["configured"] = configured
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// handleResetLiveSettings discards the stored settings and puts the
// configured values back, here now and on the other replicas at their next
// poll.
func (s *Server) handleResetLiveSettings(c *gin.Context) {
	if s.liveConfig == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "The configured storage cannot keep dashboard settings, so there is nothing stored to discard.",
			"code":  "SETTINGS_NOT_PERSISTABLE",
		})
		return
	}

	before, err := s.liveConfig.Stored(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Stored settings could not be read",
			"code":  "INTERNAL_ERROR",
		})
		return
	}
	if err := s.liveConfig.Reset(c.Request.Context()); err != nil {
		s.auditDashboard(c, "DELETE", auditResourceLiveSettings, "live", toJSONMap(before), nil, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Stored settings could not be discarded",
			"code":  "INTERNAL_ERROR",
		})
		return
	}

	configured := s.liveConfig.Baseline()
	s.auditDashboard(c, "DELETE", auditResourceLiveSettings, "live", toJSONMap(before), toJSONMap(configured), nil)
	c.JSON(http.StatusOK, gin.H{
		"message": "Stored dashboard settings discarded; the configured values are in force",
		"data":    gin.H{"configured": configured},
	})
}
