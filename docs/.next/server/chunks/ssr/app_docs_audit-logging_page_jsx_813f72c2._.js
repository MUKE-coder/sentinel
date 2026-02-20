module.exports=[24368,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Audit Logging"}),(0,b.jsxs)("p",{children:["Sentinel includes a GORM plugin that automatically tracks every database mutation — creates, updates, and deletes — and records them as immutable audit log entries. Every change captures ",(0,b.jsx)("em",{children:"who"})," made it, ",(0,b.jsx)("em",{children:"what"})," changed (including before/after state for updates), and ",(0,b.jsx)("em",{children:"when"})," it happened. Audit entries flow through the Sentinel pipeline asynchronously, so your application code is never blocked by audit writes."]}),(0,b.jsxs)(d.default,{type:"info",title:"Optional Package",children:["The GORM audit logging plugin lives in a separate package (",(0,b.jsx)("code",{children:"github.com/MUKE-coder/sentinel/gorm"}),"). It is completely optional — your core Sentinel middleware works independently. Import it only if your application uses GORM and you want automatic database-level audit trails."]}),(0,b.jsx)("h2",{id:"installation",children:"Installation"}),(0,b.jsx)("p",{children:"The audit logging plugin requires two Sentinel packages: the GORM plugin itself and the event pipeline that transports audit entries to storage."}),(0,b.jsx)(c.default,{language:"go",filename:"go imports",code:`import (
    sentinelgorm "github.com/MUKE-coder/sentinel/gorm"
    "github.com/MUKE-coder/sentinel/pipeline"
)`}),(0,b.jsx)("p",{children:"Make sure both packages are available in your module:"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`go get github.com/MUKE-coder/sentinel/gorm
go get github.com/MUKE-coder/sentinel/pipeline`}),(0,b.jsx)("h2",{id:"setup",children:"Setup"}),(0,b.jsx)("p",{children:"Setting up audit logging takes three steps: create a pipeline, start its background workers, and register the plugin with your GORM database instance."}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`// 1. Create an event pipeline with a buffer of 10,000 events
pipe := pipeline.New(0) // 0 = DefaultBufferSize (10,000)

// 2. Start background workers to process audit events
pipe.Start(2) // 2 worker goroutines
defer pipe.Stop()

// 3. Register the Sentinel GORM plugin
db.Use(sentinelgorm.New(pipe))`}),(0,b.jsxs)("p",{children:["By default, ",(0,b.jsx)("code",{children:"sentinelgorm.New(pipe)"})," enables both audit logging and query shielding (N+1 detection, unfiltered query warnings). You can selectively disable features using option functions:"]}),(0,b.jsx)(c.default,{language:"go",code:`// Audit logging only — disable query shielding
db.Use(sentinelgorm.New(pipe, func(c *sentinelgorm.Config) {
    c.QueryShieldEnabled = false
}))

// Query shielding only — disable audit logging
db.Use(sentinelgorm.New(pipe, func(c *sentinelgorm.Config) {
    c.AuditEnabled = false
}))`}),(0,b.jsx)("h3",{children:"Plugin Config"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AuditEnabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})}),(0,b.jsx)("td",{children:"Enables audit logging for CREATE, UPDATE, and DELETE operations."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"QueryShieldEnabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})}),(0,b.jsx)("td",{children:"Enables query analysis (N+1 detection, unfiltered query warnings)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SlowQueryThreshold"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"200ms"})}),(0,b.jsx)("td",{children:"Queries slower than this duration are flagged."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"N1QueryThreshold"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"10"})}),(0,b.jsx)("td",{children:"Number of same-table queries in a single request before flagging as N+1."})]})]})]}),(0,b.jsx)("h2",{id:"request-context",children:"Request Context"}),(0,b.jsxs)("p",{children:["For audit entries to include ",(0,b.jsx)("em",{children:"who"})," performed the action, you need to attach request metadata to the GORM context using ",(0,b.jsx)("code",{children:"sentinelgorm.WithRequestInfo()"}),". This connects each database operation back to the originating HTTP request."]}),(0,b.jsx)(c.default,{language:"go",filename:"handler.go",code:`func CreateProductHandler(c *gin.Context) {
    // Build request info from the current HTTP request
    ctx := sentinelgorm.WithRequestInfo(c.Request.Context(), &sentinelgorm.RequestInfo{
        IP:        c.ClientIP(),
        UserID:    c.GetString("user_id"),    // from your auth middleware
        UserEmail: c.GetString("user_email"),
        UserRole:  c.GetString("user_role"),
        UserAgent: c.Request.UserAgent(),
        RequestID: c.GetString("request_id"),
    })

    product := Product{Name: "Widget", Price: 9.99}

    // Use db.WithContext(ctx) so the plugin picks up the request info
    if err := db.WithContext(ctx).Create(&product).Error; err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    c.JSON(201, product)
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Context is Required for Attribution",children:["If you call ",(0,b.jsx)("code",{children:"db.Create(&record)"})," without attaching request info via"," ",(0,b.jsx)("code",{children:"WithContext"}),", the audit entry is still created but the ",(0,b.jsx)("code",{children:"UserID"}),","," ",(0,b.jsx)("code",{children:"IP"}),", and ",(0,b.jsx)("code",{children:"UserAgent"})," fields will be empty. Always use"," ",(0,b.jsx)("code",{children:"db.WithContext(ctx)"})," in your HTTP handlers for full attribution."]}),(0,b.jsx)("h3",{children:"RequestInfo Fields"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"IP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Client IP address of the request originator."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Authenticated user identifier (from your auth middleware)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserEmail"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Email address of the authenticated user."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserRole"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["Role of the authenticated user (e.g., ",(0,b.jsx)("code",{children:'"admin"'}),", ",(0,b.jsx)("code",{children:'"editor"'}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserAgent"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The User-Agent header from the HTTP request."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RequestID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Unique request identifier for correlating multiple audit entries from a single request."})]})]})]}),(0,b.jsx)("h2",{id:"what-gets-logged",children:"What Gets Logged"}),(0,b.jsx)("p",{children:"The plugin hooks into GORM callbacks for all mutation operations. Every CREATE, UPDATE, and DELETE that passes through GORM produces an audit entry. Read operations (SELECT) are not audited — they are handled separately by the query shield feature."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Operation"}),(0,b.jsx)("th",{children:"Action Value"}),(0,b.jsx)("th",{children:"Before State"}),(0,b.jsx)("th",{children:"After State"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Create"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CREATE"})}),(0,b.jsx)("td",{children:"-"}),(0,b.jsx)("td",{children:"Full record"}),(0,b.jsx)("td",{children:"Captures the complete newly created record."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Update"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UPDATE"})}),(0,b.jsx)("td",{children:"Record before change"}),(0,b.jsx)("td",{children:"Record after change"}),(0,b.jsx)("td",{children:"Captures both the previous and new state so you can diff exactly what changed."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Delete"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"DELETE"})}),(0,b.jsx)("td",{children:"Record before deletion"}),(0,b.jsx)("td",{children:"-"}),(0,b.jsx)("td",{children:"Captures the full record state before it was removed."})]})]})]}),(0,b.jsx)("p",{children:"Each audit entry also records:"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Table name"})," — which database table was affected (e.g., ",(0,b.jsx)("code",{children:"users"}),", ",(0,b.jsx)("code",{children:"products"}),")"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Record ID"})," — the primary key of the affected record"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"User attribution"})," — UserID, UserEmail, UserRole from the request context"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Request metadata"})," — IP address, User-Agent, RequestID"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Timestamp"})," — when the operation occurred"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Success flag"})," — whether the database operation succeeded"]})]}),(0,b.jsxs)(d.default,{type:"success",title:"Before/After Diffing",children:["For UPDATE operations, the plugin captures the model state before the update runs (in a"," ",(0,b.jsx)("code",{children:"Before"})," callback) and after it completes. Both states are serialized as JSON, giving you a complete before/after snapshot that you can diff to see exactly which fields changed."]}),(0,b.jsx)("h2",{id:"audit-log-model",children:"The AuditLog Model"}),(0,b.jsxs)("p",{children:["Every audit entry is represented by the ",(0,b.jsx)("code",{children:"AuditLog"})," struct defined in the"," ",(0,b.jsx)("code",{children:"core"})," package. This is the shape of the data that gets stored and returned by the API."]}),(0,b.jsx)(c.default,{language:"go",filename:"core/models.go",code:`// AuditLog represents an immutable audit trail entry.
type AuditLog struct {
    ID         string    \`json:"id"\`
    Timestamp  time.Time \`json:"timestamp"\`
    UserID     string    \`json:"user_id"\`
    UserEmail  string    \`json:"user_email,omitempty"\`
    UserRole   string    \`json:"user_role,omitempty"\`
    Action     string    \`json:"action"\`
    Resource   string    \`json:"resource"\`
    ResourceID string    \`json:"resource_id"\`
    Before     JSONMap   \`json:"before,omitempty"\`
    After      JSONMap   \`json:"after,omitempty"\`
    IP         string    \`json:"ip"\`
    UserAgent  string    \`json:"user_agent"\`
    Success    bool      \`json:"success"\`
    Error      string    \`json:"error,omitempty"\`
    RequestID  string    \`json:"request_id"\`
}`}),(0,b.jsx)("h3",{children:"Field Reference"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"UUID v4 unique identifier for the audit entry."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Timestamp"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Time"})}),(0,b.jsx)("td",{children:"When the database operation occurred."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"ID of the user who performed the operation."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserEmail"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Email of the user (omitted if empty)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserRole"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Role of the user (omitted if empty)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Action"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["The operation type: ",(0,b.jsx)("code",{children:"CREATE"}),", ",(0,b.jsx)("code",{children:"UPDATE"}),", or ",(0,b.jsx)("code",{children:"DELETE"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Resource"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["The database table name (e.g., ",(0,b.jsx)("code",{children:"users"}),", ",(0,b.jsx)("code",{children:"orders"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ResourceID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The primary key value of the affected record."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Before"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"JSONMap"})}),(0,b.jsx)("td",{children:"JSON snapshot of the record before the change. Present for UPDATE and DELETE; omitted for CREATE."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"After"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"JSONMap"})}),(0,b.jsx)("td",{children:"JSON snapshot of the record after the change. Present for CREATE and UPDATE; omitted for DELETE."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"IP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Client IP address from the request context."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserAgent"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"User-Agent header from the request context."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Success"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:"Whether the database operation completed without error."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Error"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Error message if the operation failed (omitted on success)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RequestID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Correlation ID to link multiple audit entries from a single HTTP request."})]})]})]}),(0,b.jsx)("h2",{id:"full-example",children:"Full Example"}),(0,b.jsxs)("p",{children:["The following example shows a complete ",(0,b.jsx)("code",{children:"main.go"})," that sets up Sentinel with the GORM audit logging plugin, creates an HTTP handler that attaches request context, and performs a database mutation that produces an audit trail entry."]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

import (
    "net/http"

    sentinel "github.com/MUKE-coder/sentinel"
    sentinelgorm "github.com/MUKE-coder/sentinel/gorm"
    "github.com/MUKE-coder/sentinel/pipeline"
    "github.com/gin-gonic/gin"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

type Product struct {
    ID    uint    \`gorm:"primaryKey" json:"id"\`
    Name  string  \`json:"name"\`
    Price float64 \`json:"price"\`
}

func main() {
    // --- Database setup ---
    db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
    if err != nil {
        panic("failed to connect database")
    }
    db.AutoMigrate(&Product{})

    // --- Pipeline setup ---
    pipe := pipeline.New(0) // default 10,000 buffer
    pipe.Start(2)
    defer pipe.Stop()

    // --- Register GORM audit plugin ---
    db.Use(sentinelgorm.New(pipe))

    // --- Gin router ---
    r := gin.Default()

    // Mount Sentinel middleware + dashboard
    sentinel.Mount(r, pipe, sentinel.Config{
        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },
    })

    // --- Routes ---
    r.POST("/api/products", func(c *gin.Context) {
        // Attach request info so audit entries include user attribution
        ctx := sentinelgorm.WithRequestInfo(c.Request.Context(), &sentinelgorm.RequestInfo{
            IP:        c.ClientIP(),
            UserID:    c.GetString("user_id"),
            UserEmail: c.GetString("user_email"),
            UserRole:  c.GetString("user_role"),
            UserAgent: c.Request.UserAgent(),
            RequestID: c.GetHeader("X-Request-ID"),
        })

        var product Product
        if err := c.ShouldBindJSON(&product); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        // This Create() call automatically generates an audit log entry
        if err := db.WithContext(ctx).Create(&product).Error; err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusCreated, product)
    })

    r.PUT("/api/products/:id", func(c *gin.Context) {
        ctx := sentinelgorm.WithRequestInfo(c.Request.Context(), &sentinelgorm.RequestInfo{
            IP:        c.ClientIP(),
            UserID:    c.GetString("user_id"),
            UserEmail: c.GetString("user_email"),
            UserAgent: c.Request.UserAgent(),
        })

        var product Product
        if err := db.WithContext(ctx).First(&product, c.Param("id")).Error; err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
            return
        }

        if err := c.ShouldBindJSON(&product); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        // This Save() call generates an UPDATE audit log with before/after state
        if err := db.WithContext(ctx).Save(&product).Error; err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, product)
    })

    r.DELETE("/api/products/:id", func(c *gin.Context) {
        ctx := sentinelgorm.WithRequestInfo(c.Request.Context(), &sentinelgorm.RequestInfo{
            IP:        c.ClientIP(),
            UserID:    c.GetString("user_id"),
            UserAgent: c.Request.UserAgent(),
        })

        var product Product
        if err := db.WithContext(ctx).First(&product, c.Param("id")).Error; err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
            return
        }

        // This Delete() call generates a DELETE audit log with the before state
        if err := db.WithContext(ctx).Delete(&product).Error; err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "deleted"})
    })

    r.Run(":8080")
}`}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsxs)("p",{children:["The Sentinel dashboard includes a dedicated Audit Logs page that provides a searchable, filterable view of your entire audit trail. Access it at"," ",(0,b.jsx)("code",{children:"http://localhost:8080/sentinel/ui"})," and navigate to the Audit Logs section."]}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Search and filter"})," — filter audit entries by user ID, action type (CREATE, UPDATE, DELETE), resource (table name), and date range."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Before/after diff"})," — expand any UPDATE entry to see the full before and after JSON state side by side."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"User attribution"})," — each entry shows who performed the action, from which IP, and with which user agent."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Pagination"})," — large audit trails are paginated for fast browsing."]})]}),(0,b.jsxs)(d.default,{type:"info",title:"Dashboard Access",children:["The audit logs page is part of the Sentinel dashboard UI. It is available automatically when you call ",(0,b.jsx)("code",{children:"sentinel.Mount()"})," — no additional configuration is needed beyond setting up the GORM plugin."]}),(0,b.jsx)("h2",{id:"api",children:"API"}),(0,b.jsxs)("p",{children:["Audit logs are available via the Sentinel REST API. Use the"," ",(0,b.jsx)("code",{children:"GET /sentinel/api/audit-logs"})," endpoint to query the audit trail programmatically."]}),(0,b.jsx)("h3",{children:"Query Parameters"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Parameter"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"user_id"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"-"}),(0,b.jsx)("td",{children:"Filter by the user who performed the action."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"action"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"-"}),(0,b.jsxs)("td",{children:["Filter by action type: ",(0,b.jsx)("code",{children:"CREATE"}),", ",(0,b.jsx)("code",{children:"UPDATE"}),", or ",(0,b.jsx)("code",{children:"DELETE"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"resource"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"-"}),(0,b.jsxs)("td",{children:["Filter by table name (e.g., ",(0,b.jsx)("code",{children:"users"}),", ",(0,b.jsx)("code",{children:"products"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"start_time"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"-"}),(0,b.jsx)("td",{children:"ISO 8601 / RFC 3339 timestamp. Only return entries after this time."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"end_time"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"-"}),(0,b.jsx)("td",{children:"ISO 8601 / RFC 3339 timestamp. Only return entries before this time."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"page"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"1"})}),(0,b.jsx)("td",{children:"Page number for pagination."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"page_size"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"20"})}),(0,b.jsx)("td",{children:"Number of entries per page."})]})]})]}),(0,b.jsx)("h3",{children:"Example Request"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:'curl "http://localhost:8080/sentinel/api/audit-logs?action=UPDATE&resource=products&page=1&page_size=10"'}),(0,b.jsx)("h3",{children:"Example Response"}),(0,b.jsx)(c.default,{language:"json",filename:"Response",showLineNumbers:!1,code:`{
  "data": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "timestamp": "2025-01-15T14:30:00Z",
      "user_id": "user-42",
      "user_email": "admin@example.com",
      "user_role": "admin",
      "action": "UPDATE",
      "resource": "products",
      "resource_id": "7",
      "before": {
        "id": 7,
        "name": "Widget",
        "price": 9.99
      },
      "after": {
        "id": 7,
        "name": "Widget Pro",
        "price": 14.99
      },
      "ip": "10.0.0.1",
      "user_agent": "Mozilla/5.0 ...",
      "success": true,
      "request_id": "req-abc-123"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "page_size": 10
  }
}`}),(0,b.jsx)("h2",{id:"testing",children:"Testing"}),(0,b.jsx)("p",{children:"You can verify that audit entries are being generated by writing a test that collects events from the pipeline. The pattern below uses an in-memory SQLite database and a custom pipeline handler that captures audit events."}),(0,b.jsx)(c.default,{language:"go",filename:"audit_test.go",code:`package main_test

import (
    "context"
    "sync"
    "testing"
    "time"

    sentinel "github.com/MUKE-coder/sentinel/core"
    sentinelgorm "github.com/MUKE-coder/sentinel/gorm"
    "github.com/MUKE-coder/sentinel/pipeline"
    "github.com/glebarez/sqlite"
    "gorm.io/gorm"
)

type Product struct {
    ID    uint    \`gorm:"primaryKey" json:"id"\`
    Name  string  \`json:"name"\`
    Price float64 \`json:"price"\`
}

// auditCollector captures audit events from the pipeline.
type auditCollector struct {
    mu     sync.Mutex
    audits []*sentinel.AuditLog
}

func (ac *auditCollector) Handle(ctx context.Context, event pipeline.Event) error {
    if event.Type == pipeline.EventAudit {
        if al, ok := event.Payload.(*sentinel.AuditLog); ok {
            ac.mu.Lock()
            ac.audits = append(ac.audits, al)
            ac.mu.Unlock()
        }
    }
    return nil
}

func TestAuditLogging(t *testing.T) {
    // Set up pipeline with a collector
    pipe := pipeline.New(100)
    collector := &auditCollector{}
    pipe.AddHandler(collector)
    pipe.Start(1)
    defer pipe.Stop()

    // Open in-memory SQLite
    db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
    if err != nil {
        t.Fatal(err)
    }

    // Register plugin and migrate
    db.Use(sentinelgorm.New(pipe))
    db.AutoMigrate(&Product{})

    // Attach request info
    ctx := sentinelgorm.WithRequestInfo(context.Background(), &sentinelgorm.RequestInfo{
        IP:     "10.0.0.1",
        UserID: "user-42",
    })

    // CREATE — should produce an audit entry
    product := Product{Name: "Widget", Price: 9.99}
    db.WithContext(ctx).Create(&product)

    // Wait for async pipeline processing
    time.Sleep(100 * time.Millisecond)

    // Verify the audit entry
    collector.mu.Lock()
    defer collector.mu.Unlock()

    if len(collector.audits) != 1 {
        t.Fatalf("expected 1 audit entry, got %d", len(collector.audits))
    }

    entry := collector.audits[0]
    if entry.Action != "CREATE" {
        t.Errorf("expected action CREATE, got %s", entry.Action)
    }
    if entry.Resource != "products" {
        t.Errorf("expected resource products, got %s", entry.Resource)
    }
    if entry.UserID != "user-42" {
        t.Errorf("expected user_id user-42, got %s", entry.UserID)
    }
    if entry.IP != "10.0.0.1" {
        t.Errorf("expected IP 10.0.0.1, got %s", entry.IP)
    }
    if entry.After == nil {
        t.Error("expected After state to be present")
    }
    if entry.After["name"] != "Widget" {
        t.Errorf("expected After.name=Widget, got %v", entry.After["name"])
    }
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Pipeline is Asynchronous",children:["Audit events are processed asynchronously by pipeline workers. In tests, add a short"," ",(0,b.jsx)("code",{children:"time.Sleep"})," (50-100ms) after database operations to allow the pipeline to flush before asserting on collected audit entries."]}),(0,b.jsx)("p",{children:"You can also verify audit entries via the API in an integration test by sending an HTTP request and then querying the audit logs endpoint:"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Create a product
curl -X POST http://localhost:8080/api/products \\
  -H "Content-Type: application/json" \\
  -d '{"name": "Widget", "price": 9.99}'

# Check audit trail
curl "http://localhost:8080/sentinel/api/audit-logs?resource=products&action=CREATE"`}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/getting-started",children:"Getting Started"})," — Set up the core Sentinel middleware"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Browse audit logs and other security data in the UI"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/performance",children:"Performance"})," — Monitor route-level performance alongside audit trails"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/alerting",children:"Alerting"})," — Get notified when threat events occur"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF"})," — Protect your application from common web attacks"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Audit Logging - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_audit-logging_page_jsx_813f72c2._.js.map