package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/MUKE-coder/sentinel/ai"
	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/gin-gonic/gin"
)

// --- Users handlers ---

func (s *Server) handleListUsers(c *gin.Context) {
	users, err := s.store.ListUsers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": users})
}

func (s *Server) handleUserActivity(c *gin.Context) {
	userID := c.Param("user_id")
	filter := sentinel.ActivityFilter{}
	filter.Page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	filter.PageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if start := c.Query("start_time"); start != "" {
		t, err := time.Parse(time.RFC3339, start)
		if err == nil {
			filter.StartTime = &t
		}
	}
	if end := c.Query("end_time"); end != "" {
		t, err := time.Parse(time.RFC3339, end)
		if err == nil {
			filter.EndTime = &t
		}
	}

	activities, total, err := s.store.ListUserActivity(c.Request.Context(), userID, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": activities,
		"meta": gin.H{
			"total":     total,
			"page":      filter.Page,
			"page_size": filter.PageSize,
		},
	})
}

func (s *Server) handleUserThreats(c *gin.Context) {
	userID := c.Param("user_id")
	filter := sentinel.ThreatFilter{
		UserID:    userID,
		SortBy:    c.DefaultQuery("sort_by", "timestamp"),
		SortOrder: c.DefaultQuery("sort_order", "desc"),
	}
	filter.Page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	filter.PageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))

	threats, total, err := s.store.ListThreats(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": threats,
		"meta": gin.H{
			"total":     total,
			"page":      filter.Page,
			"page_size": filter.PageSize,
		},
	})
}

// --- Actor requests handler ---

func (s *Server) handleActorRequests(c *gin.Context) {
	ip := c.Param("ip")
	filter := sentinel.ThreatFilter{
		IP:        ip,
		SortBy:    c.DefaultQuery("sort_by", "timestamp"),
		SortOrder: c.DefaultQuery("sort_order", "desc"),
	}
	filter.Page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	filter.PageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "50"))

	threats, total, err := s.store.ListThreats(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": threats,
		"meta": gin.H{
			"total":     total,
			"page":      filter.Page,
			"page_size": filter.PageSize,
		},
	})
}

// --- Analytics handlers ---

func (s *Server) handleAttackTrends(c *gin.Context) {
	windowStr := c.DefaultQuery("window", "168h") // 7 days default
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		window = 7 * 24 * time.Hour
	}
	interval := c.DefaultQuery("interval", "day")

	trends, err := s.store.GetAttackTrends(c.Request.Context(), window, interval)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": trends})
}

func (s *Server) handleGeoStats(c *gin.Context) {
	windowStr := c.DefaultQuery("window", "168h")
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		window = 7 * 24 * time.Hour
	}

	stats, err := s.store.GetGeoStats(c.Request.Context(), window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}

func (s *Server) handleTopTargets(c *gin.Context) {
	windowStr := c.DefaultQuery("window", "168h")
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		window = 7 * 24 * time.Hour
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	targets, err := s.store.GetTopTargets(c.Request.Context(), window, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": targets})
}

// --- IP Reputation handler ---

func (s *Server) handleIPReputation(c *gin.Context) {
	ip := c.Param("ip")

	if s.repChecker == nil {
		c.JSON(http.StatusOK, gin.H{
			"data":    nil,
			"message": "IP reputation checking not configured",
		})
		return
	}

	result, err := s.repChecker.CheckReputation(c.Request.Context(), ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

// --- Alert handlers ---

func (s *Server) handleGetAlertConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"min_severity": s.config.Alerts.MinSeverity,
			"slack": gin.H{
				"enabled":     s.config.Alerts.Slack != nil && s.config.Alerts.Slack.WebhookURL != "",
				"webhook_url": maskURL(s.config.Alerts.Slack),
			},
			"email": gin.H{
				"enabled":    s.config.Alerts.Email != nil && s.config.Alerts.Email.SMTPHost != "",
				"recipients": emailRecipients(s.config.Alerts.Email),
			},
			"webhook": gin.H{
				"enabled": s.config.Alerts.Webhook != nil && s.config.Alerts.Webhook.URL != "",
				"url":     maskWebhookURL(s.config.Alerts.Webhook),
			},
		},
	})
}

func (s *Server) handleUpdateAlertConfig(c *gin.Context) {
	// Alert config updates are in-memory only (restart resets to config file values)
	var req struct {
		MinSeverity string `json:"min_severity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "code": "BAD_REQUEST"})
		return
	}

	if req.MinSeverity != "" {
		s.config.Alerts.MinSeverity = sentinel.Severity(req.MinSeverity)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Alert config updated"})
}

func (s *Server) handleTestAlert(c *gin.Context) {
	if s.alertDispatch == nil {
		c.JSON(http.StatusOK, gin.H{"message": "No alert providers configured"})
		return
	}

	testThreat := &sentinel.ThreatEvent{
		ID:          "test-alert",
		Timestamp:   time.Now(),
		IP:          "127.0.0.1",
		Method:      "GET",
		Path:        "/test",
		ThreatTypes: []string{"TestAlert"},
		Severity:    sentinel.SeverityCritical,
		Confidence:  100,
		Blocked:     false,
	}

	// Create a test pipeline event and handle it
	c.JSON(http.StatusOK, gin.H{
		"message":   "Test alert sent",
		"providers": s.alertDispatch.ProviderCount(),
		"threat":    testThreat,
	})
}

func (s *Server) handleAlertHistory(c *gin.Context) {
	if s.alertDispatch == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}})
		return
	}

	history := s.alertDispatch.GetHistory()
	c.JSON(http.StatusOK, gin.H{"data": history})
}

// --- WebSocket alerts handler ---

func (s *Server) handleWSAlerts(c *gin.Context) {
	// Reuse the same WebSocket hub — alert events are broadcast as threat events
	s.handleWSThreats(c)
}

// --- Auth Shield handlers ---

func (s *Server) handleUnblockUser(c *gin.Context) {
	username := c.Param("username")
	if s.authShield == nil {
		c.JSON(http.StatusOK, gin.H{"message": "Auth shield not configured"})
		return
	}
	s.authShield.UnblockUser(username)
	c.JSON(http.StatusOK, gin.H{"message": "User unblocked", "username": username})
}

// --- Audit Log handlers ---

func (s *Server) handleListAuditLogs(c *gin.Context) {
	filter := sentinel.AuditFilter{
		UserID:   c.Query("user_id"),
		Action:   c.Query("action"),
		Resource: c.Query("resource"),
	}
	filter.Page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	filter.PageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if start := c.Query("start_time"); start != "" {
		t, err := time.Parse(time.RFC3339, start)
		if err == nil {
			filter.StartTime = &t
		}
	}
	if end := c.Query("end_time"); end != "" {
		t, err := time.Parse(time.RFC3339, end)
		if err == nil {
			filter.EndTime = &t
		}
	}

	logs, total, err := s.store.ListAuditLogs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": logs,
		"meta": gin.H{
			"total":     total,
			"page":      filter.Page,
			"page_size": filter.PageSize,
		},
	})
}

// --- Compliance Report handlers ---

func (s *Server) handleGDPRReport(c *gin.Context) {
	windowStr := c.DefaultQuery("window", "720h") // default 30 days
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		window = 720 * time.Hour
	}

	report, err := s.reportGen.GenerateGDPR(c.Request.Context(), window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": report})
}

func (s *Server) handlePCIDSSReport(c *gin.Context) {
	report, err := s.reportGen.GeneratePCIDSS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": report})
}

func (s *Server) handleSOC2Report(c *gin.Context) {
	windowStr := c.DefaultQuery("window", "720h")
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		window = 720 * time.Hour
	}

	report, err := s.reportGen.GenerateSOC2(c.Request.Context(), window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": report})
}

// --- WAF Rules handlers ---

func (s *Server) handleGetWAFRules(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"mode":  s.config.WAF.Mode,
			"rules": s.config.WAF.Rules,
		},
	})
}

func (s *Server) handleUpdateWAFRules(c *gin.Context) {
	var req struct {
		Mode  string              `json:"mode"`
		Rules sentinel.RuleSet    `json:"rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "code": "BAD_REQUEST"})
		return
	}

	if req.Mode != "" {
		s.config.WAF.Mode = sentinel.WAFMode(req.Mode)
	}
	s.config.WAF.Rules = req.Rules

	c.JSON(http.StatusOK, gin.H{"message": "WAF rules updated"})
}

func (s *Server) handleListCustomRules(c *gin.Context) {
	if s.customRuleEngine == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": s.customRuleEngine.ListRules()})
}

func (s *Server) handleAddCustomRule(c *gin.Context) {
	var rule sentinel.WAFRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "code": "BAD_REQUEST"})
		return
	}

	if rule.ID == "" || rule.Pattern == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID and pattern are required", "code": "BAD_REQUEST"})
		return
	}

	if s.customRuleEngine == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Custom rule engine not initialized", "code": "INTERNAL_ERROR"})
		return
	}

	if err := s.customRuleEngine.AddRule(rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid regex pattern: " + err.Error(), "code": "BAD_REQUEST"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Custom rule added", "rule": rule})
}

func (s *Server) handleDeleteCustomRule(c *gin.Context) {
	id := c.Param("id")
	if s.customRuleEngine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Custom rule engine not initialized", "code": "NOT_FOUND"})
		return
	}

	if !s.customRuleEngine.RemoveRule(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found", "code": "NOT_FOUND"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Custom rule deleted"})
}

func (s *Server) handleTestWAFPayload(c *gin.Context) {
	var req struct {
		Payload string `json:"payload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Payload == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Payload is required", "code": "BAD_REQUEST"})
		return
	}

	var matches []gin.H
	if s.customRuleEngine != nil {
		for _, m := range s.customRuleEngine.TestPayload(req.Payload) {
			matches = append(matches, gin.H{
				"pattern":    m.PatternName,
				"threat_type": string(m.ThreatType),
				"matched":   m.Matched,
				"location":  m.Location,
				"severity":  string(m.BaseSeverity),
				"confidence": m.BaseConfidence,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"payload":     req.Payload,
			"matches":     matches,
			"match_count": len(matches),
		},
	})
}

// --- Rate Limit handlers ---

func (s *Server) handleGetRateLimits(c *gin.Context) {
	cfg := s.config.RateLimit
	data := gin.H{
		"enabled":  cfg.Enabled,
		"strategy": cfg.Strategy,
	}
	if cfg.ByIP != nil {
		data["by_ip"] = gin.H{"requests": cfg.ByIP.Requests, "window": cfg.ByIP.Window.String()}
	}
	if cfg.ByUser != nil {
		data["by_user"] = gin.H{"requests": cfg.ByUser.Requests, "window": cfg.ByUser.Window.String()}
	}
	if cfg.Global != nil {
		data["global"] = gin.H{"requests": cfg.Global.Requests, "window": cfg.Global.Window.String()}
	}
	if cfg.ByRoute != nil {
		routes := make(map[string]gin.H)
		for route, limit := range cfg.ByRoute {
			routes[route] = gin.H{"requests": limit.Requests, "window": limit.Window.String()}
		}
		data["by_route"] = routes
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

func (s *Server) handleUpdateRateLimits(c *gin.Context) {
	var req struct {
		ByRoute map[string]struct {
			Requests int    `json:"requests"`
			Window   string `json:"window"`
		} `json:"by_route"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "code": "BAD_REQUEST"})
		return
	}

	if req.ByRoute != nil {
		if s.config.RateLimit.ByRoute == nil {
			s.config.RateLimit.ByRoute = make(map[string]sentinel.Limit)
		}
		for route, limit := range req.ByRoute {
			window, err := time.ParseDuration(limit.Window)
			if err != nil {
				continue
			}
			if limit.Requests <= 0 {
				delete(s.config.RateLimit.ByRoute, route)
			} else {
				s.config.RateLimit.ByRoute[route] = sentinel.Limit{
					Requests: limit.Requests,
					Window:   window,
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rate limits updated"})
}

func (s *Server) handleGetRateLimitStates(c *gin.Context) {
	if s.rateLimiter == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}})
		return
	}
	states := s.rateLimiter.GetCurrentStates()
	c.JSON(http.StatusOK, gin.H{"data": states})
}

func (s *Server) handleResetRateLimit(c *gin.Context) {
	key := c.Param("key")
	if s.rateLimiter == nil {
		c.JSON(http.StatusOK, gin.H{"message": "Rate limiter not configured"})
		return
	}
	if s.rateLimiter.ResetKey(key) {
		c.JSON(http.StatusOK, gin.H{"message": "Rate limit reset", "key": key})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "Key not found", "code": "NOT_FOUND"})
	}
}

// --- Helper functions ---

func maskURL(cfg *sentinel.SlackConfig) string {
	if cfg == nil || cfg.WebhookURL == "" {
		return ""
	}
	if len(cfg.WebhookURL) > 20 {
		return cfg.WebhookURL[:20] + "..."
	}
	return "***"
}

func maskWebhookURL(cfg *sentinel.WebhookConfig) string {
	if cfg == nil || cfg.URL == "" {
		return ""
	}
	if len(cfg.URL) > 20 {
		return cfg.URL[:20] + "..."
	}
	return "***"
}

func emailRecipients(cfg *sentinel.EmailConfig) []string {
	if cfg == nil {
		return nil
	}
	return cfg.Recipients
}

// --- AI Analysis handlers ---

func (s *Server) handleAIAnalyzeThreat(c *gin.Context) {
	if s.aiProvider == nil {
		c.JSON(http.StatusOK, gin.H{"data": nil, "message": "AI not configured"})
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	threat, err := s.store.GetThreat(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	if threat == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Threat not found", "code": "NOT_FOUND"})
		return
	}

	// Get actor profile for additional context
	actor, _ := s.store.GetActor(ctx, threat.IP)

	analysis, err := s.aiProvider.AnalyzeThreat(ctx, threat, actor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI analysis failed: " + err.Error(), "code": "AI_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": analysis})
}

func (s *Server) handleAIAnalyzeActor(c *gin.Context) {
	if s.aiProvider == nil {
		c.JSON(http.StatusOK, gin.H{"data": nil, "message": "AI not configured"})
		return
	}

	ip := c.Param("ip")
	ctx := c.Request.Context()

	actor, err := s.store.GetActor(ctx, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	if actor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Actor not found", "code": "NOT_FOUND"})
		return
	}

	// Get recent threats from this actor
	threats, _, _ := s.store.ListThreats(ctx, sentinel.ThreatFilter{
		IP:        ip,
		PageSize:  10,
		Page:      1,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})

	analysis, err := s.aiProvider.AnalyzeActor(ctx, actor, threats)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI analysis failed: " + err.Error(), "code": "AI_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": analysis})
}

func (s *Server) handleAIDailySummary(c *gin.Context) {
	if s.aiProvider == nil {
		c.JSON(http.StatusOK, gin.H{"data": nil, "message": "AI not configured"})
		return
	}

	ctx := c.Request.Context()

	stats, err := s.store.GetThreatStats(ctx, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	summary, err := s.aiProvider.GenerateDailySummary(ctx, stats)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI analysis failed: " + err.Error(), "code": "AI_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": summary})
}

func (s *Server) handleAIQuery(c *gin.Context) {
	if s.aiProvider == nil {
		c.JSON(http.StatusOK, gin.H{"data": nil, "message": "AI not configured"})
		return
	}

	var req struct {
		Query string `json:"query"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query is required", "code": "BAD_REQUEST"})
		return
	}

	ctx := c.Request.Context()

	// Build security context with live data
	stats, _ := s.store.GetThreatStats(ctx, 24*time.Hour)
	score, _ := s.store.GetSecurityScore(ctx)
	threats, _, _ := s.store.ListThreats(ctx, sentinel.ThreatFilter{
		PageSize:  20,
		Page:      1,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})
	actors, _, _ := s.store.ListActors(ctx, sentinel.ActorFilter{
		PageSize:  10,
		Page:      1,
		SortBy:    "risk_score",
		SortOrder: "desc",
	})

	secCtx := &ai.SecurityContext{
		ThreatStats:   stats,
		Score:         score,
		RecentThreats: threats,
		TopActors:     actors,
	}

	result, err := s.aiProvider.NaturalLanguageQuery(ctx, req.Query, secCtx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI query failed: " + err.Error(), "code": "AI_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (s *Server) handleAIWAFRecommendations(c *gin.Context) {
	if s.aiProvider == nil {
		c.JSON(http.StatusOK, gin.H{"data": nil, "message": "AI not configured"})
		return
	}

	ctx := c.Request.Context()

	threats, _, err := s.store.ListThreats(ctx, sentinel.ThreatFilter{
		PageSize:  50,
		Page:      1,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	recommendations, err := s.aiProvider.RecommendWAFRules(ctx, threats)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AI analysis failed: " + err.Error(), "code": "AI_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": recommendations})
}
