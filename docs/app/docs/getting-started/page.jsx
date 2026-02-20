import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = { title: 'Getting Started - Sentinel Docs' };

export default function GettingStarted() {
  return (
    <>
      <h1>Getting Started</h1>
      <p>
        Sentinel is a production-grade security intelligence SDK for Go applications using the
        Gin framework. It provides WAF protection, rate limiting, threat detection, AI analysis,
        and an embedded React dashboard — all mountable with a single function call.
      </p>

      <h2>Installation</h2>
      <p>Sentinel requires <strong>Go 1.24+</strong> and uses pure-Go SQLite (no CGo required).</p>
      <CodeBlock
        language="bash"
        code={`go get github.com/MUKE-coder/sentinel`}
        showLineNumbers={false}
      />

      <h2>Quick Start</h2>
      <p>
        The simplest way to use Sentinel is with zero configuration. This gives you an in-memory
        store, all defaults, and a dashboard at <code>/sentinel/ui</code>.
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`package main

import (
    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    // Mount Sentinel with zero config — everything works out of the box
    sentinel.Mount(r, nil, sentinel.Config{})

    // Your application routes
    r.GET("/api/hello", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, World!"})
    })

    r.Run(":8080")
    // Dashboard: http://localhost:8080/sentinel/ui
    // Default login: admin / sentinel
}`}
      />

      <Callout type="info" title="Zero Config">
        With <code>sentinel.Config{'{}'}</code>, Sentinel uses sensible defaults: in-memory storage, WAF disabled,
        rate limiting disabled. The dashboard is always available.
      </Callout>

      <h2>With WAF and Rate Limiting</h2>
      <p>Enable security features by setting configuration fields:</p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`package main

import (
    "time"

    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        Dashboard: sentinel.DashboardConfig{
            Username:  "admin",
            Password:  "my-secure-password",
            SecretKey: "change-this-in-production",
        },

        Storage: sentinel.StorageConfig{
            Driver:        sentinel.SQLite,
            DSN:           "sentinel.db",
            RetentionDays: 90,
        },

        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },

        RateLimit: sentinel.RateLimitConfig{
            Enabled: true,
            ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
        },
    })

    r.GET("/api/users", func(c *gin.Context) {
        c.JSON(200, gin.H{"users": []string{}})
    })

    r.Run(":8080")
}`}
      />

      <h2>What Happens When You Call Mount</h2>
      <p>
        <code>sentinel.Mount()</code> performs the following in order:
      </p>
      <ol>
        <li>Initializes the storage backend (SQLite or in-memory)</li>
        <li>Runs database migrations</li>
        <li>Creates the IP manager for whitelist/blacklist</li>
        <li>Sets up the async event pipeline with worker goroutines</li>
        <li>Initializes threat profiler, security score engine, geo-locator</li>
        <li>Configures alerting (Slack, email, webhook) if enabled</li>
        <li>Registers middleware: Auth Shield, WAF, Rate Limiter, Security Headers, Performance</li>
        <li>Registers the REST API and WebSocket endpoints</li>
        <li>Optionally initializes the AI provider</li>
        <li>Serves the embedded React dashboard</li>
        <li>Starts background cleanup and score recomputation goroutines</li>
      </ol>

      <Callout type="warning" title="Middleware Order Matters">
        Sentinel registers middleware in a specific order. Mount it <strong>before</strong> your
        application routes so that all routes are protected.
      </Callout>

      <h2>Project Architecture</h2>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`sentinel/
├── core/           # Shared types, constants, models
├── ai/             # AI provider interface (Claude, OpenAI, Gemini)
├── alerting/       # Alert dispatching (Slack, email, webhook)
├── api/            # REST API server, JWT auth, WebSocket hub
├── detection/      # WAF pattern matching, custom rule engine
├── gorm/           # GORM audit logging plugin
├── intelligence/   # Threat profiling, scoring, anomaly detection
├── middleware/      # Gin middleware (WAF, rate limit, headers, perf)
├── pipeline/       # Async event pipeline (ring buffer, workers)
├── reports/        # Compliance report generators
├── storage/        # Storage interface + implementations
│   ├── memory/     # In-memory store (default)
│   └── sqlite/     # Pure-Go SQLite store
├── ui/             # Embedded React dashboard
├── sentinel.go     # Mount() entry point
└── models.go       # Type aliases from core/`}
      />

      <h2>Storage Backends</h2>
      <table>
        <thead>
          <tr><th>Driver</th><th>Config Value</th><th>Notes</th></tr>
        </thead>
        <tbody>
          <tr><td>Memory</td><td><code>sentinel.Memory</code></td><td>Default. No persistence — good for development.</td></tr>
          <tr><td>SQLite</td><td><code>sentinel.SQLite</code></td><td>Pure Go (no CGo). Recommended for production.</td></tr>
        </tbody>
      </table>

      <h2>Testing Your Setup</h2>
      <p>After starting your application, verify Sentinel is working:</p>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Check the dashboard
curl http://localhost:8080/sentinel/ui

# Try a SQL injection attack (should be blocked if WAF is enabled)
curl "http://localhost:8080/api/users?id=1'+OR+'1'='1"

# Check rate limiting headers
curl -v http://localhost:8080/api/users 2>&1 | grep X-RateLimit`}
      />

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration">Full Configuration Reference</a> — All available options</li>
        <li><a href="/docs/waf">WAF Configuration</a> — Custom rules and strictness levels</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> — Per-IP, per-user, per-route limits</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the 13-page security dashboard</li>
      </ul>
    </>
  );
}
