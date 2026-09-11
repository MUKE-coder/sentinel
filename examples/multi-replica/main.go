// Command multi-replica is one instance of an app scaled horizontally behind
// a load balancer, with Sentinel's counters in Redis and its data in
// Postgres. Run two or more with examples/multi-replica/docker-compose.yml:
// rate limits and AuthShield lockouts hold across all of them.
//
//	REPLICA               name shown in responses (default "replica")
//	REDIS_ADDR            Redis address (default redis:6379)
//	DATABASE_URL          Postgres DSN
//	TRUSTED_PROXIES       comma-separated load balancer addresses
//	SENTINEL_PASSWORD     dashboard password (required)
//	SENTINEL_SECRET_KEY   dashboard JWT secret, shared by every replica (required)
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2"
	"github.com/MUKE-coder/sentinel/v2/redisstore"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func main() {
	replica := env("REPLICA", "replica")
	client := redis.NewClient(&redis.Options{
		Addr:        env("REDIS_ADDR", "redis:6379"),
		DialTimeout: time.Second,
		ReadTimeout: 250 * time.Millisecond,
	})

	cfg := sentinel.Config{
		Storage: sentinel.StorageConfig{Driver: sentinel.Postgres, DSN: mustEnv("DATABASE_URL")},
		Dashboard: sentinel.DashboardConfig{
			Password: mustEnv("SENTINEL_PASSWORD"),
			// Every replica must sign and accept the same tokens.
			SecretKey: mustEnv("SENTINEL_SECRET_KEY"),
		},
		// Shared counters: the point of this example.
		Counters: redisstore.New(client),
		WAF: sentinel.WAFConfig{
			Enabled:        true,
			Mode:           sentinel.ModeBlock,
			TrustedProxies: strings.Split(env("TRUSTED_PROXIES", ""), ","),
		},
		RateLimit: sentinel.RateLimitConfig{
			Enabled: true,
			ByIP:    &sentinel.Limit{Requests: 10, Window: time.Minute},
		},
		AuthShield: sentinel.AuthShieldConfig{
			Enabled:           true,
			LoginRoute:        "/api/login",
			MaxFailedAttempts: 5,
			LockoutDuration:   15 * time.Minute,
		},
	}

	r := gin.Default()
	if err := sentinel.MountE(r, nil, cfg); err != nil {
		log.Fatal(err)
	}

	r.GET("/api/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"replica": replica})
	})
	r.POST("/api/login", func(c *gin.Context) {
		var body struct{ Username, Password string }
		_ = c.ShouldBindJSON(&body)
		c.Set("sentinel_username", body.Username) // lets AuthShield track the username too
		if body.Username == "alice" && body.Password == "correct-horse" {
			c.JSON(http.StatusOK, gin.H{"replica": replica, "user": "alice"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"replica": replica, "error": "invalid credentials"})
	})

	log.Printf("%s listening on :8080", replica)
	log.Fatal(r.Run(":8080"))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}
