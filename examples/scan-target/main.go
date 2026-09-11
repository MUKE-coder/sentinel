// Command scan-target is a deliberately vulnerable app mounted behind
// Sentinel, for scanning with OWASP ZAP and sqlmap (see security/scan). Its
// handlers are injectable on purpose: never deploy it, never copy them.
//
//	SENTINEL_WAF=block|log|off   WAF mode (default block)
//	SENTINEL_PASSWORD            dashboard password (default scan-target-password)
package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"

	sentinel "github.com/MUKE-coder/sentinel/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	for _, stmt := range []string{
		"CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)",
		"INSERT INTO items (id, name) VALUES (1, 'widget'), (2, 'gadget')",
		"CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)",
		"INSERT INTO users (username, password) VALUES ('admin', 'hunter2')",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			log.Fatal(err)
		}
	}

	mode := env("SENTINEL_WAF", "block")
	cfg := sentinel.Config{
		Storage: sentinel.StorageConfig{Driver: sentinel.Memory},
		Dashboard: sentinel.DashboardConfig{
			Password:  env("SENTINEL_PASSWORD", "scan-target-password"),
			SecretKey: randomKey(),
		},
	}
	switch mode {
	case "block":
		cfg.WAF = sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeBlock}
	case "log":
		cfg.WAF = sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeLog}
	case "off":
	default:
		log.Fatalf("SENTINEL_WAF=%q: want block, log, or off", mode)
	}

	r := gin.Default()
	if err := sentinel.MountE(r, nil, cfg); err != nil {
		log.Fatal(err)
	}

	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`<!doctype html><title>scan target</title>
<a href="/api/items?id=1">item 1</a> <a href="/api/search?q=widget">search</a>
<form action="/api/search"><input name="q"><button>Search</button></form>`))
	})

	// Injectable on purpose: id is concatenated into the SQL.
	r.GET("/api/items", func(c *gin.Context) {
		var rows []map[string]any
		if err := db.Raw("SELECT id, name FROM items WHERE id = " + c.Query("id")).Scan(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, rows)
	})

	// Reflected XSS on purpose: q is written into the page unescaped.
	r.GET("/api/search", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<p>Results for "+c.Query("q")+"</p>"))
	})

	log.Printf("scan target on :8080, WAF %s", mode)
	log.Fatal(r.Run(":8080"))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}
