package api

import (
	"net/http"

	"github.com/MUKE-coder/sentinel/v2/intelligence"
	"github.com/gin-gonic/gin"
)

// SetReputationWatcher gives the API server the live reputation checker so
// its quota use can be reported.
func (s *Server) SetReputationWatcher(w *intelligence.ReputationWatcher) {
	s.repWatcher = w
}

// SetFeedBlocklist gives the API server the blocklist feeds so their status
// can be reported.
func (s *Server) SetFeedBlocklist(f *intelligence.FeedBlocklist) {
	s.feeds = f
}

// handleIPIntelStatus reports live reputation checking and blocklist feeds.
func (s *Server) handleIPIntelStatus(c *gin.Context) {
	live := gin.H{"enabled": s.repWatcher != nil}
	if s.repWatcher != nil {
		live["used_today"] = s.repWatcher.UsedToday()
		live["max_per_day"] = s.config.IPReputation.MaxChecksPerDay
	}
	feeds := []intelligence.FeedStatus{}
	if s.feeds != nil {
		feeds = s.feeds.Status()
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"live_checks": live, "feeds": feeds}})
}
