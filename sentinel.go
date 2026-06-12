// Package sentinel is a production-grade security intelligence SDK for Go applications.
//
// Sentinel provides WAF protection, rate limiting, threat detection, user activity logging,
// audit trails, security scoring, and an embedded dashboard — all mountable with a single
// function call on any Gin application.
//
// Quick start:
//
//	r := gin.Default()
//	sentinel.Mount(r, nil, sentinel.Config{})
//	r.Run(":8080")
//	// Dashboard at http://localhost:8080/sentinel/ui
package sentinel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"strings"
	"time"

	"github.com/MUKE-coder/sentinel/v2/ai"
	"github.com/MUKE-coder/sentinel/v2/alerting"
	"github.com/MUKE-coder/sentinel/v2/api"
	"github.com/MUKE-coder/sentinel/v2/captcha"
	"github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/detection"
	sentinelgorm "github.com/MUKE-coder/sentinel/v2/gorm"
	"github.com/MUKE-coder/sentinel/v2/intelligence"
	"github.com/MUKE-coder/sentinel/v2/middleware"
	"github.com/MUKE-coder/sentinel/v2/pipeline"
	"github.com/MUKE-coder/sentinel/v2/storage"
	"github.com/MUKE-coder/sentinel/v2/storage/memory"
	"github.com/MUKE-coder/sentinel/v2/storage/postgres"
	"github.com/MUKE-coder/sentinel/v2/storage/sqlite"
	"github.com/MUKE-coder/sentinel/v2/ui"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ErrInsecureDefaults is returned by MountE when the application would start
// in gin.ReleaseMode with the built-in default password or JWT secret and
// DashboardConfig.AllowInsecureDefaults is false.
var ErrInsecureDefaults = errors.New("sentinel: refusing to start in release mode with default dashboard credentials")

// Mount attaches Sentinel to a Gin router, enabling security middleware, the REST API,
// WebSocket streams, and the embedded dashboard UI.
//
// Parameters:
//   - router: The Gin engine to attach middleware and routes to.
//   - db: An optional GORM database instance for the GORM plugin. Pass nil to skip.
//   - config: Configuration for all Sentinel features. Use sentinel.Config{} for all defaults.
//
// Mount will initialize the storage backend, run migrations, start background goroutines
// (event pipeline, score recomputation, cleanup), and register all middleware and routes.
// Any initialization error is fatal — use MountE if you want to handle errors yourself.
func Mount(router *gin.Engine, db *gorm.DB, config Config) {
	if err := MountE(router, db, config); err != nil {
		log.Fatalf("[sentinel] %v", err)
	}
}

// MountE is the error-returning variant of Mount. Library callers that don't
// want a sub-system failure to kill the host process should prefer this and
// handle the returned error themselves (log + skip Sentinel, retry, etc.).
func MountE(router *gin.Engine, db *gorm.DB, config Config) error {
	config.ApplyDefaults()

	// Refuse to start with built-in default credentials in release mode unless
	// the operator has explicitly opted in. This stops zero-config deployments
	// from shipping with forgeable admin tokens and a known password.
	if gin.Mode() == gin.ReleaseMode && !config.Dashboard.AllowInsecureDefaults {
		if config.Dashboard.Password == core.DefaultInsecurePassword {
			return fmt.Errorf("%w: default dashboard password — set Dashboard.Password or AllowInsecureDefaults", ErrInsecureDefaults)
		}
		if config.Dashboard.SecretKey == core.DefaultInsecureSecretKey {
			return fmt.Errorf("%w: default JWT secret — set Dashboard.SecretKey or AllowInsecureDefaults", ErrInsecureDefaults)
		}
	}

	// Configure trusted proxies for safe X-Forwarded-For handling across all
	// middleware. Empty list = ignore proxy headers (the safe default).
	middleware.ConfigureTrustedProxies(config.WAF.TrustedProxies)

	// 1. Initialize storage adapter
	var store storage.Store
	var err error

	switch config.Storage.Driver {
	case SQLite:
		store, err = sqlite.New(config.Storage.DSN)
		if err != nil {
			return fmt.Errorf("initialize SQLite storage: %w", err)
		}
	case Postgres:
		store, err = postgres.New(config.Storage.DSN, postgres.Options{
			MaxOpenConns: config.Storage.MaxOpenConns,
			MaxIdleConns: config.Storage.MaxIdleConns,
		})
		if err != nil {
			return fmt.Errorf("initialize Postgres storage: %w", err)
		}
	case Memory:
		store = memory.New()
	default:
		store = memory.New()
	}

	// 2. Run migrations
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	// 3. Initialize IP manager
	ipManager := intelligence.NewIPManager(store)

	// 4. Initialize event pipeline
	pipe := pipeline.New(pipeline.DefaultBufferSize)

	// Add threat actor profiler to pipeline
	profiler := intelligence.NewProfiler(store)
	pipe.AddHandler(profiler)

	// Add storage handler to pipeline
	pipe.AddHandler(pipeline.HandlerFunc(func(ctx context.Context, event pipeline.Event) error {
		switch event.Type {
		case pipeline.EventThreat:
			if te, ok := event.Payload.(*ThreatEvent); ok {
				return store.SaveThreat(ctx, te)
			}
		case pipeline.EventPerformance:
			if pm, ok := event.Payload.(*PerformanceMetric); ok {
				return store.SavePerformanceMetric(ctx, pm)
			}
		case pipeline.EventUserActivity:
			if ua, ok := event.Payload.(*UserActivity); ok {
				return store.SaveUserActivity(ctx, ua)
			}
		case pipeline.EventAudit:
			if al, ok := event.Payload.(*AuditLog); ok {
				return store.SaveAuditLog(ctx, al)
			}
		}
		return nil
	}))

	pipe.Start(4) // 4 worker goroutines

	// 5. Initialize security score engine
	scoreEngine := intelligence.NewScoreEngine(store, config)

	// 5a. Initialize geolocation
	geoLocator := intelligence.NewGeoLocator(config.Geo)

	// 5b. Initialize IP reputation checker
	repChecker := intelligence.NewReputationChecker(config.IPReputation, ipManager)

	// 5c. Initialize anomaly detector and add to pipeline
	if config.Anomaly.Enabled {
		anomalyDetector := intelligence.NewAnomalyDetector(store, pipe, geoLocator, config.Anomaly)
		pipe.AddHandler(anomalyDetector)
	}

	// 5d. Initialize alerting system
	var alertDispatcher *alerting.Dispatcher
	if config.Alerts.Slack != nil || config.Alerts.Email != nil || config.Alerts.Webhook != nil || config.Alerts.PagerDuty != nil {
		alertDispatcher = alerting.NewDispatcher(config.Alerts)
		if config.Alerts.Slack != nil && config.Alerts.Slack.WebhookURL != "" {
			alertDispatcher.AddProvider(alerting.NewSlackProvider(config.Alerts.Slack.WebhookURL))
		}
		if config.Alerts.Email != nil && config.Alerts.Email.SMTPHost != "" {
			alertDispatcher.AddProvider(alerting.NewEmailProvider(*config.Alerts.Email))
		}
		if config.Alerts.Webhook != nil && config.Alerts.Webhook.URL != "" {
			alertDispatcher.AddProvider(alerting.NewWebhookProvider(*config.Alerts.Webhook))
		}
		if config.Alerts.PagerDuty != nil && config.Alerts.PagerDuty.IntegrationKey != "" {
			alertDispatcher.AddProvider(alerting.NewPagerDutyProvider(*config.Alerts.PagerDuty))
		}
		pipe.AddHandler(alertDispatcher)
	}

	// 5e. Initialize auth shield (with optional CAPTCHA tier)
	var authShield *middleware.AuthShield
	if config.AuthShield.Enabled {
		authShield = middleware.NewAuthShield(config.AuthShield, store, pipe)
		if cp := buildCAPTCHAProvider(config); cp != nil {
			authShield.SetCAPTCHAProvider(cp)
		}
		router.Use(authShield.Middleware())
	}

	// 5f. Initialize custom rule engine
	customRuleEngine := detection.NewCustomRuleEngine(config.WAF.CustomRules)

	// 6. Register middleware
	if config.WAF.Enabled {
		router.Use(middleware.WAFMiddleware(config.WAF, store, pipe, customRuleEngine))
	}

	// 7. Register rate limiter
	var rateLimiter *middleware.RateLimiter
	if config.RateLimit.Enabled {
		rateLimiter = middleware.NewRateLimiter()
		router.Use(middleware.RateLimitMiddleware(config.RateLimit, rateLimiter, pipe))
	}

	// 8. Register security headers
	router.Use(middleware.HeadersMiddleware(config.Headers))

	// 9. Register performance middleware
	router.Use(middleware.PerformanceMiddleware(config.Performance, pipe))

	// 10. Register API routes
	apiServer := api.NewServer(store, pipe, ipManager, scoreEngine, config)
	apiServer.SetReputationChecker(repChecker)
	apiServer.SetGeoLocator(geoLocator)
	if alertDispatcher != nil {
		apiServer.SetAlertDispatcher(alertDispatcher)
	}
	if authShield != nil {
		apiServer.SetAuthShield(authShield)
	}
	apiServer.SetCustomRuleEngine(customRuleEngine)
	if rateLimiter != nil {
		apiServer.SetRateLimiter(rateLimiter)
	}

	// 10b. Initialize AI provider (optional)
	if aiProvider := ai.NewProvider(config.AI); aiProvider != nil {
		apiServer.SetAIProvider(aiProvider)
		log.Println("[sentinel] AI provider initialized:", config.AI.Provider)
	}

	apiServer.RegisterRoutes(router, config.Dashboard.Prefix)

	// 11. Serve embedded React dashboard
	prefix := config.Dashboard.Prefix
	distFS, err := ui.DistFS()
	if err != nil {
		log.Printf("[sentinel] Failed to load embedded UI: %v (serving fallback)", err)
		router.GET(prefix+"/ui/*filepath", func(c *gin.Context) {
			c.Header("Content-Type", "text/html")
			c.String(200, dashboardPlaceholder)
		})
	} else {
		indexHTML, _ := fs.ReadFile(distFS, "index.html")

		router.GET(prefix+"/ui/*filepath", func(c *gin.Context) {
			filePath := strings.TrimPrefix(c.Param("filepath"), "/")
			if filePath == "" || filePath == "/" {
				c.Data(200, "text/html; charset=utf-8", indexHTML)
				return
			}
			// Try to serve the file directly (JS, CSS, assets)
			data, readErr := fs.ReadFile(distFS, filePath)
			if readErr != nil {
				// SPA fallback: serve index.html for all unknown routes
				c.Data(200, "text/html; charset=utf-8", indexHTML)
				return
			}
			contentType := "application/octet-stream"
			switch {
			case strings.HasSuffix(filePath, ".html"):
				contentType = "text/html; charset=utf-8"
			case strings.HasSuffix(filePath, ".js"):
				contentType = "application/javascript"
			case strings.HasSuffix(filePath, ".css"):
				contentType = "text/css"
			case strings.HasSuffix(filePath, ".json"):
				contentType = "application/json"
			case strings.HasSuffix(filePath, ".svg"):
				contentType = "image/svg+xml"
			case strings.HasSuffix(filePath, ".png"):
				contentType = "image/png"
			}
			c.Data(200, contentType, data)
		})
	}

	// 12. Start background goroutines
	go backgroundCleanup(store, config.Storage.RetentionDays)
	go backgroundScoreRecompute(scoreEngine)

	log.Printf("[sentinel] Mounted at %s (WAF: %v, RateLimit: %v, Storage: %s)",
		config.Dashboard.Prefix,
		config.WAF.Enabled,
		config.RateLimit.Enabled,
		config.Storage.Driver,
	)

	// 13. Auto-register the GORM plugin when a *gorm.DB is supplied.
	// Previously the db parameter was unused — callers had to wire the plugin
	// themselves. That defeats the one-line setup promise of Mount.
	if db != nil {
		if err := db.Use(sentinelgorm.New(pipe)); err != nil {
			return fmt.Errorf("register GORM plugin: %w", err)
		}
	}

	return nil
}

// buildCAPTCHAProvider picks the first configured CAPTCHA provider, with a
// precedence order biased toward commercial providers (more battle-tested
// against bots) over the self-hosted fallback.
func buildCAPTCHAProvider(config Config) captcha.Provider {
	switch {
	case config.CAPTCHA.HCaptchaSecret != "":
		return captcha.NewHCaptchaProvider(config.CAPTCHA.HCaptchaSecret)
	case config.CAPTCHA.TurnstileSecret != "":
		return captcha.NewTurnstileProvider(config.CAPTCHA.TurnstileSecret)
	case config.CAPTCHA.RecaptchaSecret != "":
		return captcha.NewRecaptchaProvider(config.CAPTCHA.RecaptchaSecret)
	case config.CAPTCHA.SelfHostedSecret != "":
		return captcha.NewSelfHostedProvider(config.CAPTCHA.SelfHostedSecret)
	}
	return nil
}

func backgroundCleanup(store storage.Store, retentionDays int) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		store.Cleanup(ctx, time.Duration(retentionDays)*24*time.Hour)
	}
}

func backgroundScoreRecompute(engine *intelligence.ScoreEngine) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Compute initial score
	ctx := context.Background()
	engine.ComputeScore(ctx)

	for range ticker.C {
		ctx := context.Background()
		engine.ComputeScore(ctx)
	}
}

const dashboardPlaceholder = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel Security Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0f1e; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.container { text-align: center; }
h1 { color: #00d4ff; font-size: 2rem; margin-bottom: 1rem; }
p { color: #8892a0; margin-bottom: 0.5rem; }
.badge { display: inline-block; background: #0d1526; border: 1px solid #1e2d4a; padding: 0.5rem 1rem; border-radius: 6px; margin-top: 1rem; color: #00d4ff; }
</style>
</head>
<body>
<div class="container">
<h1>SENTINEL</h1>
<p>Security Dashboard</p>
<p>Full React UI will be embedded in Task 1.14</p>
<div class="badge">API available at /sentinel/api/</div>
</div>
</body>
</html>`
