// Package main demonstrates a fully configured Sentinel setup with all features enabled.
// Run: go run main.go
// Dashboard: http://localhost:8080/sentinel/ui (admin/s3cur3-p4ss!)
package main

import (
	"log"
	"time"

	sentinel "github.com/MUKE-coder/sentinel"
	sentinelgorm "github.com/MUKE-coder/sentinel/gorm"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// User is an example GORM model.
type User struct {
	ID    uint   `gorm:"primarykey" json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func main() {
	// 1. Set up your GORM database
	db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&User{})

	// 2. Configure Sentinel with all features
	config := sentinel.Config{
		Dashboard: sentinel.DashboardConfig{
			Username:  "admin",
			Password:  "s3cur3-p4ss!",
			SecretKey: "my-jwt-secret-change-in-production",
		},

		Storage: sentinel.StorageConfig{
			Driver:        sentinel.SQLite,
			DSN:           "sentinel.db",
			RetentionDays: 90,
		},

		WAF: sentinel.WAFConfig{
			Enabled: true,
			Mode:    sentinel.ModeBlock, // Block malicious requests
			Rules: sentinel.RuleSet{
				SQLInjection:     sentinel.RuleStrict,
				XSS:              sentinel.RuleStrict,
				PathTraversal:    sentinel.RuleStrict,
				CommandInjection: sentinel.RuleStrict,
			},
			CustomRules: []sentinel.WAFRule{
				{
					ID:        "block-admin-enum",
					Name:      "Block admin enumeration",
					Pattern:   `(?i)/(wp-admin|phpmyadmin|administrator)`,
					AppliesTo: []string{"path"},
					Severity:  sentinel.SeverityMedium,
					Action:    "block",
					Enabled:   true,
				},
			},
		},

		RateLimit: sentinel.RateLimitConfig{
			Enabled: true,
			ByIP:    &sentinel.Limit{Requests: 100, Window: 1 * time.Minute},
			Global:  &sentinel.Limit{Requests: 1000, Window: 1 * time.Minute},
			ByRoute: map[string]sentinel.Limit{
				"/api/login": {Requests: 5, Window: 15 * time.Minute},
			},
		},

		AuthShield: sentinel.AuthShieldConfig{
			Enabled:           true,
			LoginRoute:        "/api/login",
			MaxFailedAttempts: 5,
			LockoutDuration:   15 * time.Minute,
		},

		Anomaly: sentinel.AnomalyConfig{
			Enabled:    true,
			Sensitivity: sentinel.AnomalySensitivityMedium,
		},

		// Uncomment to enable AI analysis:
		// AI: &sentinel.AIConfig{
		//     Provider: sentinel.Claude,
		//     APIKey:   "your-anthropic-api-key",
		// },

		// Uncomment to enable Slack alerts:
		// Alerts: sentinel.AlertConfig{
		//     MinSeverity: sentinel.SeverityHigh,
		//     Slack: &sentinel.SlackConfig{
		//         WebhookURL: "https://hooks.slack.com/services/...",
		//     },
		// },

		// Extract user context from your auth middleware
		UserExtractor: func(c *gin.Context) *sentinel.UserContext {
			// In a real app, extract from JWT or session
			userID := c.GetHeader("X-User-ID")
			if userID == "" {
				return nil
			}
			return &sentinel.UserContext{
				ID:    userID,
				Email: c.GetHeader("X-User-Email"),
				Role:  c.GetHeader("X-User-Role"),
			}
		},
	}

	// 3. Create Gin router and mount Sentinel
	r := gin.Default()
	sentinel.Mount(r, db, config)

	// 4. Register the GORM plugin for automatic audit logging
	pipe := pipeline.New(100)
	pipe.Start(2)
	db.Use(sentinelgorm.New(pipe))

	// 5. Your application routes
	r.POST("/api/login", func(c *gin.Context) {
		// Your login logic here
		c.JSON(200, gin.H{"token": "example-jwt-token"})
	})

	r.GET("/api/users", func(c *gin.Context) {
		var users []User
		db.Find(&users)
		c.JSON(200, gin.H{"data": users})
	})

	r.POST("/api/users", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		// Pass request context to GORM for audit logging
		ctx := sentinelgorm.WithRequestInfo(c.Request.Context(), &sentinelgorm.RequestInfo{
			IP:        c.ClientIP(),
			UserID:    c.GetHeader("X-User-ID"),
			UserAgent: c.Request.UserAgent(),
		})
		db.WithContext(ctx).Create(&user)
		c.JSON(201, gin.H{"data": user})
	})

	r.GET("/api/users/:id", func(c *gin.Context) {
		var user User
		if err := db.First(&user, c.Param("id")).Error; err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		c.JSON(200, gin.H{"data": user})
	})

	r.DELETE("/api/users/:id", func(c *gin.Context) {
		ctx := sentinelgorm.WithRequestInfo(c.Request.Context(), &sentinelgorm.RequestInfo{
			IP:        c.ClientIP(),
			UserID:    c.GetHeader("X-User-ID"),
			UserAgent: c.Request.UserAgent(),
		})
		db.WithContext(ctx).Delete(&User{}, c.Param("id"))
		c.JSON(200, gin.H{"message": "User deleted"})
	})

	log.Println("Server starting on :8080")
	log.Println("Dashboard: http://localhost:8080/sentinel/ui")
	log.Println("Login: admin / s3cur3-p4ss!")
	r.Run(":8080")
}
