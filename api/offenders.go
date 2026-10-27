package api

import (
	"net/http"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/gin-gonic/gin"
)

// Bulk-block defaults and guards.
const (
	defaultOffenderMinThreats = 5
	defaultOffenderWindow     = 7 * 24 * time.Hour
	maxOffendersPerCall       = 1000
	offenderPageSize          = 500
)

// offenderRequest is the body of POST /api/ip/block-offenders.
type offenderRequest struct {
	// MinThreats is how many recorded threats an address needs before it
	// is blocked. Default 5.
	MinThreats int `json:"min_threats"`

	// Since bounds how recently the address was last seen, as a duration
	// ("168h"). Default 7 days — an address that stopped a month ago is
	// probably a different machine now.
	Since string `json:"since"`

	// Duration is how long each block lasts. Default 24h; ignored when
	// Permanent is set.
	Duration  string `json:"duration"`
	Permanent bool   `json:"permanent"`

	Reason string `json:"reason"`

	// DryRun reports who would be blocked and blocks nobody.
	DryRun bool `json:"dry_run"`
}

// handleBlockOffenders blocks every address that has tripped the WAF often
// enough, in one call. The dashboard's per-address button is no answer to a
// scan from dozens of hosts, and going through them by hand is how a threat
// log with thousands of rows gets ignored instead of acted on.
//
// It is deliberately explicit: the criteria are in the request, `dry_run`
// shows the list first, and one audit entry records what was done.
func (s *Server) handleBlockOffenders(c *gin.Context) {
	var req offenderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "code": "BAD_REQUEST"})
		return
	}
	if s.ipManager == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "IP blocking is not available on this instance.",
			"code":  "IP_MANAGER_UNAVAILABLE",
		})
		return
	}

	minThreats := req.MinThreats
	if minThreats <= 0 {
		minThreats = defaultOffenderMinThreats
	}
	window := defaultOffenderWindow
	if req.Since != "" {
		parsed, err := time.ParseDuration(req.Since)
		if err != nil || parsed <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": `since must be a positive duration such as "168h"`,
				"code":  "BAD_REQUEST",
			})
			return
		}
		window = parsed
	}
	var expiry *time.Time
	if !req.Permanent {
		blockFor := defaultBlockDuration
		if req.Duration != "" {
			parsed, err := time.ParseDuration(req.Duration)
			if err != nil || parsed <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": `duration must be a positive duration such as "24h"`,
					"code":  "BAD_REQUEST",
				})
				return
			}
			blockFor = parsed
		}
		until := time.Now().Add(blockFor)
		expiry = &until
	}
	reason := req.Reason
	if reason == "" {
		reason = "bulk block: repeat offender"
	}

	ctx := c.Request.Context()
	candidates, truncated, err := s.findOffenders(c, minThreats, window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read threat actors", "code": "INTERNAL_ERROR"})
		return
	}

	data := gin.H{
		"matched":     len(candidates),
		"ips":         candidates,
		"min_threats": minThreats,
		"since":       window.String(),
		"dry_run":     req.DryRun,
		"truncated":   truncated,
	}
	if req.DryRun {
		data["blocked"] = 0
		c.JSON(http.StatusOK, gin.H{
			"message": "Nothing was blocked — this was a dry run",
			"data":    data,
		})
		return
	}

	blocked := make([]string, 0, len(candidates))
	var failed int
	for _, ip := range candidates {
		if err := s.ipManager.BlockIP(ctx, ip, reason, expiry); err != nil {
			failed++
			continue
		}
		blocked = append(blocked, ip)
	}
	data["blocked"] = len(blocked)
	data["failed"] = failed

	// One audit entry for the operation, not one per address: a bulk block
	// is a single decision, and the addresses are the evidence for it. A
	// sweep that blocked nobody is not a change, and recording it would
	// only push real entries out of view.
	if len(blocked) == 0 && failed == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "No addresses matched", "data": data})
		return
	}
	after := sentinel.JSONMap{
		"matched":     len(candidates),
		"blocked":     len(blocked),
		"failed":      failed,
		"min_threats": minThreats,
		"since":       window.String(),
		"reason":      reason,
		"permanent":   req.Permanent,
		"ips":         blocked,
	}
	if expiry != nil {
		after["expires_at"] = expiry.Format(time.RFC3339)
	}
	s.auditDashboard(c, "CREATE", auditResourceIPBlock, "bulk", nil, after, nil)

	c.JSON(http.StatusOK, gin.H{
		"message": "Repeat offenders blocked",
		"data":    data,
	})
}

// findOffenders returns the addresses that have tripped detection at least
// minThreats times and were seen within window, skipping those already
// blocked or whitelisted. truncated is true when the cap was reached.
func (s *Server) findOffenders(c *gin.Context, minThreats int, window time.Duration) (ips []string, truncated bool, err error) {
	ctx := c.Request.Context()
	cutoff := time.Now().Add(-window)

	for page := 1; ; page++ {
		actors, _, listErr := s.store.ListActors(ctx, sentinel.ActorFilter{
			Page:      page,
			PageSize:  offenderPageSize,
			SortBy:    "threat_count",
			SortOrder: "desc",
		})
		if listErr != nil {
			return nil, false, listErr
		}
		if len(actors) == 0 {
			return ips, false, nil
		}
		for _, actor := range actors {
			if actor == nil || actor.IP == "" {
				continue
			}
			if actor.ThreatCount < minThreats || actor.LastSeen.Before(cutoff) {
				continue
			}
			if actor.Status == sentinel.ActorWhitelisted || s.ipManager.IsWhitelisted(actor.IP) {
				continue
			}
			if s.ipManager.IsBlocked(actor.IP) {
				continue
			}
			ips = append(ips, actor.IP)
			if len(ips) >= maxOffendersPerCall {
				return ips, true, nil
			}
		}
		if len(actors) < offenderPageSize {
			return ips, false, nil
		}
	}
}
