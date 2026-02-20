// Package api provides the REST API and WebSocket server for Sentinel.
package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/ai"
	"github.com/MUKE-coder/sentinel/alerting"
	"github.com/MUKE-coder/sentinel/detection"
	"github.com/MUKE-coder/sentinel/intelligence"
	"github.com/MUKE-coder/sentinel/middleware"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/MUKE-coder/sentinel/reports"
	"github.com/MUKE-coder/sentinel/storage"
	"github.com/gin-gonic/gin"
)

// Server holds references needed by API handlers.
type Server struct {
	store        storage.Store
	pipe         *pipeline.Pipeline
	ipManager    *intelligence.IPManager
	scoreEngine  *intelligence.ScoreEngine
	repChecker   *intelligence.ReputationChecker
	geoLocator   *intelligence.GeoLocator
	alertDispatch *alerting.Dispatcher
	authShield   *middleware.AuthShield
	reportGen       *reports.Generator
	customRuleEngine *detection.CustomRuleEngine
	aiProvider       ai.Provider
	rateLimiter      *middleware.RateLimiter
	config          sentinel.Config
	wsHub        *WSHub
	loginRL      *LoginRateLimiter
}

// NewServer creates a new API server.
func NewServer(store storage.Store, pipe *pipeline.Pipeline, ipMgr *intelligence.IPManager, scoreEngine *intelligence.ScoreEngine, config sentinel.Config) *Server {
	return &Server{
		store:       store,
		pipe:        pipe,
		ipManager:   ipMgr,
		scoreEngine: scoreEngine,
		reportGen:   reports.NewGenerator(store),
		config:      config,
		wsHub:       NewWSHub(),
		loginRL:     NewLoginRateLimiter(),
	}
}

// SetReputationChecker sets the reputation checker for the API server.
func (s *Server) SetReputationChecker(rc *intelligence.ReputationChecker) {
	s.repChecker = rc
}

// SetGeoLocator sets the geo locator for the API server.
func (s *Server) SetGeoLocator(gl *intelligence.GeoLocator) {
	s.geoLocator = gl
}

// SetAlertDispatcher sets the alert dispatcher for the API server.
func (s *Server) SetAlertDispatcher(d *alerting.Dispatcher) {
	s.alertDispatch = d
}

// SetAuthShield sets the auth shield for the API server.
func (s *Server) SetAuthShield(as *middleware.AuthShield) {
	s.authShield = as
}

// SetCustomRuleEngine sets the custom WAF rule engine for the API server.
func (s *Server) SetCustomRuleEngine(e *detection.CustomRuleEngine) {
	s.customRuleEngine = e
}

// SetAIProvider sets the AI provider for the API server.
func (s *Server) SetAIProvider(p ai.Provider) {
	s.aiProvider = p
}

// SetRateLimiter sets the rate limiter for the API server.
func (s *Server) SetRateLimiter(rl *middleware.RateLimiter) {
	s.rateLimiter = rl
}

// RegisterRoutes registers all API routes on the Gin router.
func (s *Server) RegisterRoutes(r *gin.Engine, prefix string) {
	api := r.Group(prefix + "/api")

	// Auth routes (no JWT required)
	auth := api.Group("/auth")
	{
		auth.POST("/login", s.handleLogin)
		auth.POST("/logout", s.handleLogout)
		auth.GET("/verify", AuthMiddleware(s.config.Dashboard.SecretKey), s.handleVerify)
	}

	// Protected routes
	protected := api.Group("")
	protected.Use(AuthMiddleware(s.config.Dashboard.SecretKey))
	{
		// Threats
		protected.GET("/threats", s.handleListThreats)
		protected.GET("/threats/:id", s.handleGetThreat)
		protected.POST("/threats/:id/resolve", s.handleResolveThreat)
		protected.POST("/threats/:id/false-positive", s.handleFalsePositive)

		// Actors
		protected.GET("/actors", s.handleListActors)
		protected.GET("/actors/:ip", s.handleGetActor)
		protected.POST("/actors/:ip/block", s.handleBlockActor)

		// IP Management
		protected.GET("/ip/blocked", s.handleListBlockedIPs)
		protected.POST("/ip/block", s.handleBlockIP)
		protected.DELETE("/ip/block/:ip", s.handleUnblockIP)

		// Performance
		protected.GET("/performance/overview", s.handlePerformanceOverview)
		protected.GET("/performance/routes", s.handleRouteMetrics)

		// Score
		protected.GET("/score", s.handleGetScore)

		// Analytics
		protected.GET("/analytics/summary", s.handleAnalyticsSummary)
		protected.GET("/analytics/attack-trends", s.handleAttackTrends)
		protected.GET("/analytics/geographic", s.handleGeoStats)
		protected.GET("/analytics/top-targets", s.handleTopTargets)

		// Users
		protected.GET("/users", s.handleListUsers)
		protected.GET("/users/:user_id/activity", s.handleUserActivity)
		protected.GET("/users/:user_id/threats", s.handleUserThreats)

		// Actor requests (threat history for an IP)
		protected.GET("/actors/:ip/requests", s.handleActorRequests)

		// IP Reputation
		protected.GET("/ip/:ip/reputation", s.handleIPReputation)

		// Audit Logs
		protected.GET("/audit-logs", s.handleListAuditLogs)

		// Auth Shield
		protected.POST("/auth/unblock-user/:username", s.handleUnblockUser)

		// Compliance Reports
		protected.GET("/reports/gdpr", s.handleGDPRReport)
		protected.GET("/reports/pci-dss", s.handlePCIDSSReport)
		protected.GET("/reports/soc2", s.handleSOC2Report)

		// WAF Rules
		protected.GET("/waf/rules", s.handleGetWAFRules)
		protected.PUT("/waf/rules", s.handleUpdateWAFRules)
		protected.GET("/waf/custom-rules", s.handleListCustomRules)
		protected.POST("/waf/custom-rules", s.handleAddCustomRule)
		protected.DELETE("/waf/custom-rules/:id", s.handleDeleteCustomRule)
		protected.POST("/waf/test", s.handleTestWAFPayload)

		// Alerts
		protected.GET("/alerts/config", s.handleGetAlertConfig)
		protected.PUT("/alerts/config", s.handleUpdateAlertConfig)
		protected.POST("/alerts/test", s.handleTestAlert)
		protected.GET("/alerts/history", s.handleAlertHistory)

		// AI Analysis
		protected.POST("/ai/analyze-threat/:id", s.handleAIAnalyzeThreat)
		protected.GET("/ai/analyze-actor/:ip", s.handleAIAnalyzeActor)
		protected.GET("/ai/daily-summary", s.handleAIDailySummary)
		protected.POST("/ai/query", s.handleAIQuery)
		protected.GET("/ai/waf-recommendations", s.handleAIWAFRecommendations)

		// Rate Limits
		protected.GET("/rate-limits", s.handleGetRateLimits)
		protected.PUT("/rate-limits", s.handleUpdateRateLimits)
		protected.GET("/rate-limits/current", s.handleGetRateLimitStates)
		protected.POST("/rate-limits/reset/:key", s.handleResetRateLimit)
	}

	// WebSocket routes
	r.GET(prefix+"/ws/threats", s.handleWSThreats)
	r.GET(prefix+"/ws/metrics", s.handleWSMetrics)
	r.GET(prefix+"/ws/alerts", s.handleWSAlerts)

	// Start WebSocket hub
	go s.wsHub.Run()

	// Subscribe pipeline to broadcast to WebSocket clients
	s.pipe.AddHandler(pipeline.HandlerFunc(func(ctx context.Context, event pipeline.Event) error {
		s.wsHub.Broadcast(event)
		return nil
	}))
}

// --- Auth handlers ---

func (s *Server) handleLogin(c *gin.Context) {
	clientIP := c.ClientIP()

	if !s.loginRL.Check(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "Too many login attempts",
			"code":  "RATE_LIMITED",
		})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "BAD_REQUEST",
		})
		return
	}

	if req.Username != s.config.Dashboard.Username || req.Password != s.config.Dashboard.Password {
		s.loginRL.RecordFailure(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "UNAUTHORIZED",
		})
		return
	}

	token, err := GenerateToken(s.config.Dashboard.SecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
			"code":  "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_in": 86400,
	})
}

func (s *Server) handleLogout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func (s *Server) handleVerify(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// --- Threat handlers ---

func (s *Server) handleListThreats(c *gin.Context) {
	filter := sentinel.ThreatFilter{
		Severity:  sentinel.Severity(c.Query("severity")),
		Type:      c.Query("type"),
		IP:        c.Query("ip"),
		Search:    c.Query("search"),
		SortBy:    c.DefaultQuery("sort_by", "timestamp"),
		SortOrder: c.DefaultQuery("sort_order", "desc"),
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

func (s *Server) handleGetThreat(c *gin.Context) {
	id := c.Param("id")
	threat, err := s.store.GetThreat(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	if threat == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Threat not found", "code": "NOT_FOUND"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": threat})
}

func (s *Server) handleResolveThreat(c *gin.Context) {
	id := c.Param("id")
	resolved := true
	err := s.store.UpdateThreat(c.Request.Context(), id, sentinel.ThreatUpdate{Resolved: &resolved})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Threat resolved"})
}

func (s *Server) handleFalsePositive(c *gin.Context) {
	id := c.Param("id")
	fp := true
	resolved := true
	err := s.store.UpdateThreat(c.Request.Context(), id, sentinel.ThreatUpdate{
		FalsePositive: &fp,
		Resolved:      &resolved,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Marked as false positive"})
}

// --- Actor handlers ---

func (s *Server) handleListActors(c *gin.Context) {
	filter := sentinel.ActorFilter{
		Status: sentinel.ActorStatus(c.Query("status")),
		Search: c.Query("search"),
	}
	filter.Page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	filter.PageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))
	filter.MinRisk, _ = strconv.Atoi(c.Query("min_risk"))

	actors, total, err := s.store.ListActors(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": actors,
		"meta": gin.H{
			"total":     total,
			"page":      filter.Page,
			"page_size": filter.PageSize,
		},
	})
}

func (s *Server) handleGetActor(c *gin.Context) {
	ip := c.Param("ip")
	actor, err := s.store.GetActor(c.Request.Context(), ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	if actor == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Actor not found", "code": "NOT_FOUND"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": actor})
}

func (s *Server) handleBlockActor(c *gin.Context) {
	ip := c.Param("ip")
	ctx := c.Request.Context()

	if s.ipManager != nil {
		if err := s.ipManager.BlockIP(ctx, ip, "Blocked via dashboard", nil); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Actor blocked"})
}

// --- IP Management handlers ---

func (s *Server) handleListBlockedIPs(c *gin.Context) {
	blocked, err := s.store.ListBlockedIPs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": blocked})
}

func (s *Server) handleBlockIP(c *gin.Context) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
		Expiry string `json:"expiry,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "code": "BAD_REQUEST"})
		return
	}

	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP is required", "code": "BAD_REQUEST"})
		return
	}

	var expiry *time.Time
	if req.Expiry != "" {
		t, err := time.Parse(time.RFC3339, req.Expiry)
		if err == nil {
			expiry = &t
		}
	}

	if s.ipManager != nil {
		if err := s.ipManager.BlockIP(c.Request.Context(), req.IP, req.Reason, expiry); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "IP blocked"})
}

func (s *Server) handleUnblockIP(c *gin.Context) {
	ip := c.Param("ip")

	// Handle CIDR in URL (replace _ with /)
	ip = strings.ReplaceAll(ip, "_", "/")

	if s.ipManager != nil {
		if err := s.ipManager.UnblockIP(c.Request.Context(), ip); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "IP unblocked"})
}

// --- Performance handlers ---

func (s *Server) handlePerformanceOverview(c *gin.Context) {
	overview, err := s.store.GetPerformanceOverview(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": overview})
}

func (s *Server) handleRouteMetrics(c *gin.Context) {
	metrics, err := s.store.GetRouteMetrics(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": metrics})
}

// --- Score handlers ---

func (s *Server) handleGetScore(c *gin.Context) {
	var score *sentinel.SecurityScore
	var err error

	if s.scoreEngine != nil {
		score, err = s.scoreEngine.ComputeScore(c.Request.Context())
	} else {
		score, err = s.store.GetSecurityScore(c.Request.Context())
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	if score == nil {
		score = &sentinel.SecurityScore{
			Overall:    0,
			Grade:      "F",
			ComputedAt: time.Now(),
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": score})
}

// --- Analytics handlers ---

func (s *Server) handleAnalyticsSummary(c *gin.Context) {
	windowStr := c.DefaultQuery("window", "24h")
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		window = 24 * time.Hour
	}

	stats, err := s.store.GetThreatStats(c.Request.Context(), window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}
