import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Audit Logging - Sentinel Docs',
  description:
    'Automatically track database changes with Sentinel\'s GORM plugin. Record creates, updates, and deletes with user attribution.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/audit-logging',
  },
  openGraph: {
    title: 'Audit Logging - Sentinel Docs',
    description:
      'Automatically track database changes with Sentinel\'s GORM plugin. Record creates, updates, and deletes with user attribution.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/audit-logging',
    siteName: 'Sentinel',
    type: 'article',
  },
};

export default function AuditLogging() {
  return (
    <>
      <FAQSchema
        faqs={[
          {
            question: 'What is the Sentinel GORM audit logging plugin?',
            answer: 'The Sentinel GORM audit plugin is an optional package that automatically tracks every database mutation through GORM callbacks. It records creates, updates, and deletes as immutable audit log entries with full user attribution, flowing through an async pipeline.',
          },
          {
            question: 'What database operations does the Sentinel audit plugin track?',
            answer: 'The plugin tracks three GORM mutation operations: CREATE (captures the new record), UPDATE (captures before and after state), and DELETE (captures the record before removal). Read operations are not audited and are handled by the query shield feature instead.',
          },
          {
            question: 'How do I add user attribution to Sentinel audit log entries?',
            answer: 'Use sentinelgorm.WithRequestInfo() to attach request metadata to the GORM context. Pass IP, UserID, UserEmail, UserRole, UserAgent, and RequestID from your HTTP handler, then use db.WithContext(ctx) for full attribution on every audit entry.',
          },
          {
            question: 'Does the Sentinel audit plugin store old and new values for updates?',
            answer: 'Yes. For UPDATE operations the plugin captures the model state before the update runs and after it completes. Both states are serialized as JSON in the Before and After fields, giving you a complete snapshot that you can diff to see exactly which fields changed.',
          },
        ]}
      />
      <TechArticleSchema
        title="Audit Logging - Sentinel Docs"
        description="Automatically track database changes with Sentinel's GORM plugin. Record creates, updates, and deletes with user attribution."
        url="https://sentinel-go-sdk.vercel.app/docs/audit-logging"
      />
      <SpeakableSchema url="https://sentinel-go-sdk.vercel.app/docs/audit-logging" />

      <h1>Audit Logging</h1>
      <p>
        Sentinel includes a GORM plugin that automatically tracks every database mutation —
        creates, updates, and deletes — and records them as immutable audit log entries. Every
        change captures <em>who</em> made it, <em>what</em> changed (including before/after state
        for updates), and <em>when</em> it happened. Audit entries flow through the Sentinel
        pipeline asynchronously, so your application code is never blocked by audit writes.
      </p>

      <Callout type="info" title="Optional Package">
        The GORM audit logging plugin lives in a separate package (<code>github.com/MUKE-coder/sentinel/gorm</code>).
        It is completely optional — your core Sentinel middleware works independently. Import it
        only if your application uses GORM and you want automatic database-level audit trails.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  INSTALLATION                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="installation">Installation</h2>
      <p>
        The audit logging plugin requires two Sentinel packages: the GORM plugin itself and the
        event pipeline that transports audit entries to storage.
      </p>

      <CodeBlock
        language="go"
        filename="go imports"
        code={`import (
    sentinelgorm "github.com/MUKE-coder/sentinel/gorm"
    "github.com/MUKE-coder/sentinel/pipeline"
)`}
      />

      <p>
        Make sure both packages are available in your module:
      </p>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`go get github.com/MUKE-coder/sentinel/gorm
go get github.com/MUKE-coder/sentinel/pipeline`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  SETUP                                                             */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="setup">Setup</h2>
      <p>
        Setting up audit logging takes three steps: create a pipeline, start its background
        workers, and register the plugin with your GORM database instance.
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`// 1. Create an event pipeline with a buffer of 10,000 events
pipe := pipeline.New(0) // 0 = DefaultBufferSize (10,000)

// 2. Start background workers to process audit events
pipe.Start(2) // 2 worker goroutines
defer pipe.Stop()

// 3. Register the Sentinel GORM plugin
db.Use(sentinelgorm.New(pipe))`}
      />

      <p>
        By default, <code>sentinelgorm.New(pipe)</code> enables both audit logging and query
        shielding (N+1 detection, unfiltered query warnings). You can selectively disable features
        using option functions:
      </p>

      <CodeBlock
        language="go"
        code={`// Audit logging only — disable query shielding
db.Use(sentinelgorm.New(pipe, func(c *sentinelgorm.Config) {
    c.QueryShieldEnabled = false
}))

// Query shielding only — disable audit logging
db.Use(sentinelgorm.New(pipe, func(c *sentinelgorm.Config) {
    c.AuditEnabled = false
}))`}
      />

      <h3>Plugin Config</h3>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>AuditEnabled</code></td>
            <td><code>bool</code></td>
            <td><code>true</code></td>
            <td>Enables audit logging for CREATE, UPDATE, and DELETE operations.</td>
          </tr>
          <tr>
            <td><code>QueryShieldEnabled</code></td>
            <td><code>bool</code></td>
            <td><code>true</code></td>
            <td>Enables query analysis (N+1 detection, unfiltered query warnings).</td>
          </tr>
          <tr>
            <td><code>SlowQueryThreshold</code></td>
            <td><code>time.Duration</code></td>
            <td><code>200ms</code></td>
            <td>Queries slower than this duration are flagged.</td>
          </tr>
          <tr>
            <td><code>N1QueryThreshold</code></td>
            <td><code>int</code></td>
            <td><code>10</code></td>
            <td>Number of same-table queries in a single request before flagging as N+1.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  REQUEST CONTEXT                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="request-context">Request Context</h2>
      <p>
        For audit entries to include <em>who</em> performed the action, you need to attach request
        metadata to the GORM context using <code>sentinelgorm.WithRequestInfo()</code>. This
        connects each database operation back to the originating HTTP request.
      </p>

      <CodeBlock
        language="go"
        filename="handler.go"
        code={`func CreateProductHandler(c *gin.Context) {
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
}`}
      />

      <Callout type="warning" title="Context is Required for Attribution">
        If you call <code>db.Create(&record)</code> without attaching request info via{' '}
        <code>WithContext</code>, the audit entry is still created but the <code>UserID</code>,{' '}
        <code>IP</code>, and <code>UserAgent</code> fields will be empty. Always use{' '}
        <code>db.WithContext(ctx)</code> in your HTTP handlers for full attribution.
      </Callout>

      <h3>RequestInfo Fields</h3>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>IP</code></td>
            <td><code>string</code></td>
            <td>Client IP address of the request originator.</td>
          </tr>
          <tr>
            <td><code>UserID</code></td>
            <td><code>string</code></td>
            <td>Authenticated user identifier (from your auth middleware).</td>
          </tr>
          <tr>
            <td><code>UserEmail</code></td>
            <td><code>string</code></td>
            <td>Email address of the authenticated user.</td>
          </tr>
          <tr>
            <td><code>UserRole</code></td>
            <td><code>string</code></td>
            <td>Role of the authenticated user (e.g., <code>"admin"</code>, <code>"editor"</code>).</td>
          </tr>
          <tr>
            <td><code>UserAgent</code></td>
            <td><code>string</code></td>
            <td>The User-Agent header from the HTTP request.</td>
          </tr>
          <tr>
            <td><code>RequestID</code></td>
            <td><code>string</code></td>
            <td>Unique request identifier for correlating multiple audit entries from a single request.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  WHAT GETS LOGGED                                                  */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="what-gets-logged">What Gets Logged</h2>
      <p>
        The plugin hooks into GORM callbacks for all mutation operations. Every CREATE, UPDATE,
        and DELETE that passes through GORM produces an audit entry. Read operations (SELECT) are
        not audited — they are handled separately by the query shield feature.
      </p>

      <table>
        <thead>
          <tr>
            <th>Operation</th>
            <th>Action Value</th>
            <th>Before State</th>
            <th>After State</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Create</strong></td>
            <td><code>CREATE</code></td>
            <td>-</td>
            <td>Full record</td>
            <td>Captures the complete newly created record.</td>
          </tr>
          <tr>
            <td><strong>Update</strong></td>
            <td><code>UPDATE</code></td>
            <td>Record before change</td>
            <td>Record after change</td>
            <td>Captures both the previous and new state so you can diff exactly what changed.</td>
          </tr>
          <tr>
            <td><strong>Delete</strong></td>
            <td><code>DELETE</code></td>
            <td>Record before deletion</td>
            <td>-</td>
            <td>Captures the full record state before it was removed.</td>
          </tr>
        </tbody>
      </table>

      <p>Each audit entry also records:</p>
      <ul>
        <li><strong>Table name</strong> — which database table was affected (e.g., <code>users</code>, <code>products</code>)</li>
        <li><strong>Record ID</strong> — the primary key of the affected record</li>
        <li><strong>User attribution</strong> — UserID, UserEmail, UserRole from the request context</li>
        <li><strong>Request metadata</strong> — IP address, User-Agent, RequestID</li>
        <li><strong>Timestamp</strong> — when the operation occurred</li>
        <li><strong>Success flag</strong> — whether the database operation succeeded</li>
      </ul>

      <Callout type="success" title="Before/After Diffing">
        For UPDATE operations, the plugin captures the model state before the update runs (in a{' '}
        <code>Before</code> callback) and after it completes. Both states are serialized as JSON,
        giving you a complete before/after snapshot that you can diff to see exactly which fields
        changed.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  THE AUDITLOG MODEL                                                */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="audit-log-model">The AuditLog Model</h2>
      <p>
        Every audit entry is represented by the <code>AuditLog</code> struct defined in the{' '}
        <code>core</code> package. This is the shape of the data that gets stored and returned by
        the API.
      </p>

      <CodeBlock
        language="go"
        filename="core/models.go"
        code={`// AuditLog represents an immutable audit trail entry.
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
}`}
      />

      <h3>Field Reference</h3>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>ID</code></td>
            <td><code>string</code></td>
            <td>UUID v4 unique identifier for the audit entry.</td>
          </tr>
          <tr>
            <td><code>Timestamp</code></td>
            <td><code>time.Time</code></td>
            <td>When the database operation occurred.</td>
          </tr>
          <tr>
            <td><code>UserID</code></td>
            <td><code>string</code></td>
            <td>ID of the user who performed the operation.</td>
          </tr>
          <tr>
            <td><code>UserEmail</code></td>
            <td><code>string</code></td>
            <td>Email of the user (omitted if empty).</td>
          </tr>
          <tr>
            <td><code>UserRole</code></td>
            <td><code>string</code></td>
            <td>Role of the user (omitted if empty).</td>
          </tr>
          <tr>
            <td><code>Action</code></td>
            <td><code>string</code></td>
            <td>The operation type: <code>CREATE</code>, <code>UPDATE</code>, or <code>DELETE</code>.</td>
          </tr>
          <tr>
            <td><code>Resource</code></td>
            <td><code>string</code></td>
            <td>The database table name (e.g., <code>users</code>, <code>orders</code>).</td>
          </tr>
          <tr>
            <td><code>ResourceID</code></td>
            <td><code>string</code></td>
            <td>The primary key value of the affected record.</td>
          </tr>
          <tr>
            <td><code>Before</code></td>
            <td><code>JSONMap</code></td>
            <td>JSON snapshot of the record before the change. Present for UPDATE and DELETE; omitted for CREATE.</td>
          </tr>
          <tr>
            <td><code>After</code></td>
            <td><code>JSONMap</code></td>
            <td>JSON snapshot of the record after the change. Present for CREATE and UPDATE; omitted for DELETE.</td>
          </tr>
          <tr>
            <td><code>IP</code></td>
            <td><code>string</code></td>
            <td>Client IP address from the request context.</td>
          </tr>
          <tr>
            <td><code>UserAgent</code></td>
            <td><code>string</code></td>
            <td>User-Agent header from the request context.</td>
          </tr>
          <tr>
            <td><code>Success</code></td>
            <td><code>bool</code></td>
            <td>Whether the database operation completed without error.</td>
          </tr>
          <tr>
            <td><code>Error</code></td>
            <td><code>string</code></td>
            <td>Error message if the operation failed (omitted on success).</td>
          </tr>
          <tr>
            <td><code>RequestID</code></td>
            <td><code>string</code></td>
            <td>Correlation ID to link multiple audit entries from a single HTTP request.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  FULL EXAMPLE                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="full-example">Full Example</h2>
      <p>
        The following example shows a complete <code>main.go</code> that sets up Sentinel with the
        GORM audit logging plugin, creates an HTTP handler that attaches request context, and
        performs a database mutation that produces an audit trail entry.
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`package main

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
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        The Sentinel dashboard includes a dedicated Audit Logs page that provides a searchable,
        filterable view of your entire audit trail. Access it at{' '}
        <code>http://localhost:8080/sentinel/ui</code> and navigate to the Audit Logs section.
      </p>

      <ul>
        <li>
          <strong>Search and filter</strong> — filter audit entries by user ID, action type
          (CREATE, UPDATE, DELETE), resource (table name), and date range.
        </li>
        <li>
          <strong>Before/after diff</strong> — expand any UPDATE entry to see the full
          before and after JSON state side by side.
        </li>
        <li>
          <strong>User attribution</strong> — each entry shows who performed the action,
          from which IP, and with which user agent.
        </li>
        <li>
          <strong>Pagination</strong> — large audit trails are paginated for fast browsing.
        </li>
      </ul>

      <Callout type="info" title="Dashboard Access">
        The audit logs page is part of the Sentinel dashboard UI. It is available automatically
        when you call <code>sentinel.Mount()</code> — no additional configuration is needed beyond
        setting up the GORM plugin.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  API                                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="api">API</h2>
      <p>
        Audit logs are available via the Sentinel REST API. Use the{' '}
        <code>GET /sentinel/api/audit-logs</code> endpoint to query the audit trail
        programmatically.
      </p>

      <h3>Query Parameters</h3>
      <table>
        <thead>
          <tr>
            <th>Parameter</th>
            <th>Type</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>user_id</code></td>
            <td><code>string</code></td>
            <td>-</td>
            <td>Filter by the user who performed the action.</td>
          </tr>
          <tr>
            <td><code>action</code></td>
            <td><code>string</code></td>
            <td>-</td>
            <td>Filter by action type: <code>CREATE</code>, <code>UPDATE</code>, or <code>DELETE</code>.</td>
          </tr>
          <tr>
            <td><code>resource</code></td>
            <td><code>string</code></td>
            <td>-</td>
            <td>Filter by table name (e.g., <code>users</code>, <code>products</code>).</td>
          </tr>
          <tr>
            <td><code>start_time</code></td>
            <td><code>string</code></td>
            <td>-</td>
            <td>ISO 8601 / RFC 3339 timestamp. Only return entries after this time.</td>
          </tr>
          <tr>
            <td><code>end_time</code></td>
            <td><code>string</code></td>
            <td>-</td>
            <td>ISO 8601 / RFC 3339 timestamp. Only return entries before this time.</td>
          </tr>
          <tr>
            <td><code>page</code></td>
            <td><code>int</code></td>
            <td><code>1</code></td>
            <td>Page number for pagination.</td>
          </tr>
          <tr>
            <td><code>page_size</code></td>
            <td><code>int</code></td>
            <td><code>20</code></td>
            <td>Number of entries per page.</td>
          </tr>
        </tbody>
      </table>

      <h3>Example Request</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl "http://localhost:8080/sentinel/api/audit-logs?action=UPDATE&resource=products&page=1&page_size=10"`}
      />

      <h3>Example Response</h3>
      <CodeBlock
        language="json"
        filename="Response"
        showLineNumbers={false}
        code={`{
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
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing</h2>
      <p>
        You can verify that audit entries are being generated by writing a test that collects
        events from the pipeline. The pattern below uses an in-memory SQLite database and a
        custom pipeline handler that captures audit events.
      </p>

      <CodeBlock
        language="go"
        filename="audit_test.go"
        code={`package main_test

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
}`}
      />

      <Callout type="info" title="Pipeline is Asynchronous">
        Audit events are processed asynchronously by pipeline workers. In tests, add a short{' '}
        <code>time.Sleep</code> (50-100ms) after database operations to allow the pipeline to
        flush before asserting on collected audit entries.
      </Callout>

      <p>
        You can also verify audit entries via the API in an integration test by sending an HTTP
        request and then querying the audit logs endpoint:
      </p>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Create a product
curl -X POST http://localhost:8080/api/products \\
  -H "Content-Type: application/json" \\
  -d '{"name": "Widget", "price": 9.99}'

# Check audit trail
curl "http://localhost:8080/sentinel/api/audit-logs?resource=products&action=CREATE"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/getting-started">Getting Started</a> — Set up the core Sentinel middleware</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Browse audit logs and other security data in the UI</li>
        <li><a href="/docs/performance">Performance</a> — Monitor route-level performance alongside audit trails</li>
        <li><a href="/docs/alerting">Alerting</a> — Get notified when threat events occur</li>
        <li><a href="/docs/waf">WAF</a> — Protect your application from common web attacks</li>
      </ul>
    </>
  );
}
