package api

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Audit resources for changes made through the dashboard. Every mutating
// dashboard endpoint records who changed what, so an operator can't switch
// the WAF to log-only or unblock an attacker without a trace.
const (
	auditResourceThreat      = "sentinel.threat"
	auditResourceIPBlock     = "sentinel.ip_block"
	auditResourceAuthLockout = "sentinel.auth_lockout"
	auditResourceWAFConfig   = "sentinel.waf_config"
	auditResourceCustomRule  = "sentinel.waf_custom_rule"
	auditResourceAlertConfig = "sentinel.alert_config"
	auditResourceRateLimit   = "sentinel.rate_limit"
)

// dashboardRole marks audit entries made through the Sentinel dashboard.
const dashboardRole = "sentinel_admin"

var errInvalidCredentials = errors.New("invalid credentials")

// auditDashboard records an action taken through the dashboard. The
// dashboard has a single operator account, so the configured username is
// the actor for every authenticated request. A non-nil opErr records a
// failed attempt.
func (s *Server) auditDashboard(c *gin.Context, action, resource, resourceID string, before, after sentinel.JSONMap, opErr error) {
	s.auditAs(c, s.config.Dashboard.Username, action, resource, resourceID, before, after, opErr)
}

// auditLogin records a dashboard login attempt under the auth resource the
// PCI-DSS report counts, with the username that was tried.
func (s *Server) auditLogin(c *gin.Context, username string, ok bool) {
	var err error
	if !ok {
		err = errInvalidCredentials
	}
	s.auditAs(c, clip(username, 128), "LOGIN", sentinel.AuditResourceAuth, "sentinel-dashboard", nil, nil, err)
}

func (s *Server) auditAs(c *gin.Context, userID, action, resource, resourceID string, before, after sentinel.JSONMap, opErr error) {
	if s.pipe == nil {
		return
	}
	entry := &sentinel.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		UserID:     userID,
		UserRole:   dashboardRole,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Before:     before,
		After:      after,
		IP:         middleware.ClientIP(c),
		UserAgent:  c.Request.UserAgent(),
		Success:    opErr == nil,
	}
	if opErr != nil {
		entry.Error = opErr.Error()
	}
	s.pipe.EmitAudit(entry)
}

// toJSONMap converts a config value into the JSONMap an audit entry stores,
// via a JSON round trip so the entry holds exactly what the API would show.
func toJSONMap(v any) sentinel.JSONMap {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m sentinel.JSONMap
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	return m
}

// blockDetails is the after-state recorded for an IP block.
func blockDetails(reason string, permanent bool, expiry *time.Time) sentinel.JSONMap {
	details := sentinel.JSONMap{"reason": reason, "permanent": permanent}
	if expiry != nil {
		details["expires_at"] = expiry.Format(time.RFC3339)
	}
	return details
}

// clip bounds a client-supplied string before it is stored.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
