// Package main demonstrates the minimal Sentinel setup.
// Run: go run main.go
// Dashboard: http://localhost:8080/sentinel/ui (admin/sentinel)
package main

import (
	"log"

	sentinel "github.com/MUKE-coder/sentinel"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Mount Sentinel with all defaults — zero config required.
	// This enables: WAF (log mode), rate limiting (off), security headers,
	// performance monitoring, SQLite storage, and the embedded dashboard.
	sentinel.Mount(r, nil, sentinel.Config{})

	// Your application routes
	r.GET("/api/hello", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello, World!"})
	})

	r.GET("/api/users/:id", func(c *gin.Context) {
		c.JSON(200, gin.H{"id": c.Param("id"), "name": "Jane Doe"})
	})

	log.Println("Server starting on :8080")
	log.Println("Dashboard: http://localhost:8080/sentinel/ui")
	log.Println("Login: admin / sentinel")
	r.Run(":8080")
}
