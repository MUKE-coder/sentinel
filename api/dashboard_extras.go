package api

import (
	"encoding/json"
	"net/http"
	"sort"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/gin-gonic/gin"
)

// handleAuthShieldStatus returns the current per-IP AuthShield snapshot —
// who's locked, who's in the CAPTCHA tier, who's at attempt N of M. Used
// by the dashboard's AuthShield panel.
func (s *Server) handleAuthShieldStatus(c *gin.Context) {
	if s.authShield == nil {
		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"enabled":          false,
				"captcha_provider": "",
				"entries":          []any{},
			},
		})
		return
	}
	snap := s.authShield.Snapshot()
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"enabled":          true,
			"captcha_provider": s.authShield.CAPTCHAProviderName(),
			"entries":          snap,
		},
	})
}

// cspViolationStat is one row of the CSP-violations aggregate.
type cspViolationStat struct {
	BlockedURI         string `json:"blocked_uri"`
	ViolatedDirective  string `json:"violated_directive"`
	EffectiveDirective string `json:"effective_directive"`
	Count              int    `json:"count"`
	LastSeen           string `json:"last_seen"`
}

// handleCSPStats returns a grouped view of CSP violations by
// (violated_directive, blocked_uri). Frontend uses it for the
// at-a-glance "most-blocked third-party scripts" panel.
func (s *Server) handleCSPStats(c *gin.Context) {
	threats, _, err := s.store.ListThreats(c.Request.Context(), sentinel.ThreatFilter{
		Type:     string(sentinel.ThreatCSPViolation),
		Page:     1,
		PageSize: 1000,
		SortBy:   "timestamp",
		SortOrder: "desc",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type key struct{ directive, uri string }
	bucket := map[key]*cspViolationStat{}
	for _, t := range threats {
		v := decodeCSPSnippet(t.BodySnippet)
		k := key{directive: v.ViolatedDirective, uri: v.BlockedURI}
		row, ok := bucket[k]
		if !ok {
			row = &cspViolationStat{
				BlockedURI:         v.BlockedURI,
				ViolatedDirective:  v.ViolatedDirective,
				EffectiveDirective: v.EffectiveDirective,
				LastSeen:           t.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			}
			bucket[k] = row
		}
		row.Count++
	}

	out := make([]*cspViolationStat, 0, len(bucket))
	for _, v := range bucket {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })

	c.JSON(http.StatusOK, gin.H{"data": out, "meta": gin.H{"total": len(out)}})
}

// decodeCSPSnippet pulls a normalized cspViolation back out of the JSON we
// stuffed into BodySnippet at ingest time. Tolerates malformed input —
// blank fields just sort to the bottom.
func decodeCSPSnippet(s string) cspViolation {
	var v cspViolation
	if s == "" {
		return v
	}
	_ = json.Unmarshal([]byte(s), &v)
	return v
}
