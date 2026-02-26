# Sentinel

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/MUKE-coder/sentinel)](https://goreportcard.com/report/github.com/MUKE-coder/sentinel)
[![Release](https://img.shields.io/github/v/release/MUKE-coder/sentinel?color=00d4ff)](https://github.com/MUKE-coder/sentinel/releases)
[![Tests](https://img.shields.io/badge/Tests-12%20suites-brightgreen)](https://github.com/MUKE-coder/sentinel)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-15-orange)](https://github.com/MUKE-coder/sentinel)
[![Dashboard Pages](https://img.shields.io/badge/Dashboard-13%20pages-purple)](https://github.com/MUKE-coder/sentinel)
[![API Endpoints](https://img.shields.io/badge/API-40%2B%20endpoints-yellow)](https://github.com/MUKE-coder/sentinel)

Production-grade security intelligence SDK for Go applications. Drop-in middleware for [Gin](https://github.com/gin-gonic/gin) that provides WAF protection, rate limiting, threat detection, audit logging, anomaly detection, AI-powered analysis, and an embedded React dashboard — all mountable with a single function call.

**[Documentation](https://sentinel-go-sdk.vercel.app)** | **[Getting Started](https://sentinel-go-sdk.vercel.app/docs/getting-started)** | **[API Reference](https://sentinel-go-sdk.vercel.app/docs/api-reference)**

```go
r := gin.Default()
sentinel.Mount(r, nil, sentinel.Config{})
r.Run(":8080")
// Dashboard → http://localhost:8080/sentinel/ui
```

## Features

- **Web Application Firewall (WAF)** — SQL injection, XSS, path traversal, command injection, SSRF, XXE detection with configurable strictness levels and custom rules
- **Rate Limiting** — Per-IP, per-user, per-route, and global rate limits with sliding windows and route exclusions
- **Threat Intelligence** — Automatic threat actor profiling, risk scoring, and IP reputation checking
- **Anomaly Detection** — Statistical anomaly detection with configurable sensitivity
- **Auth Shield** — Brute-force protection with automatic lockouts
- **Audit Logging** — GORM plugin for automatic tracking of database changes
- **Security Headers** — Configurable HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- **AI Analysis** — Optional Claude, OpenAI, or Gemini integration for threat analysis and natural language queries
- **Compliance Reports** — GDPR, PCI-DSS, and SOC 2 report generation
- **Real-time Dashboard** — Embedded React dashboard with live WebSocket updates, charts, and management tools
- **Alerting** — Slack, email, and webhook notifications for security events
- **Geolocation** — IP-based geographic attribution for threat events
- **Performance Monitoring** — Per-route latency tracking (p50/p95/p99), error rates, response sizes
- **Security Score** — Weighted scoring across 5 dimensions with actionable recommendations
- **Zero Config** — Works out of the box with `sentinel.Config{}`
- **No CGo** — Pure-Go SQLite via modernc.org/sqlite

## Installation

```bash
go get github.com/MUKE-coder/sentinel
```

**Requirements:** Go 1.24+, no CGo required.

## Quick Start

### Minimal Setup

```go
package main

import (
    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    sentinel.Mount(r, nil, sentinel.Config{})

    r.GET("/api/hello", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, World!"})
    })

    r.Run(":8080")
}
```

### Full Configuration

```go
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
        Mode:    sentinel.ModeBlock,
        Rules: sentinel.RuleSet{
            SQLInjection:     sentinel.RuleStrict,
            XSS:              sentinel.RuleStrict,
            PathTraversal:    sentinel.RuleStrict,
            CommandInjection: sentinel.RuleStrict,
        },
        ExcludeRoutes: []string{"/health"},
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
        ExcludeRoutes: []string{"/health", "/metrics"},
    },

    AuthShield: sentinel.AuthShieldConfig{
        Enabled:           true,
        LoginRoute:        "/api/login",
        MaxFailedAttempts: 5,
        LockoutDuration:   15 * time.Minute,
    },

    Anomaly: sentinel.AnomalyConfig{
        Enabled:     true,
        Sensitivity: sentinel.AnomalySensitivityMedium,
    },

    // Optional: AI-powered analysis
    AI: &sentinel.AIConfig{
        Provider: sentinel.Claude,
        APIKey:   "your-anthropic-api-key",
    },

    // Optional: Slack alerts
    Alerts: sentinel.AlertConfig{
        MinSeverity: sentinel.SeverityHigh,
        Slack: &sentinel.SlackConfig{
            WebhookURL: "https://hooks.slack.com/services/...",
        },
    },

    // Extract user context from your auth middleware
    UserExtractor: func(c *gin.Context) *sentinel.UserContext {
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

r := gin.Default()
sentinel.Mount(r, db, config)
```

See [examples/](examples/) for complete runnable examples.

## GORM Audit Plugin

Track database changes automatically:

```go
import (
    sentinelgorm "github.com/MUKE-coder/sentinel/gorm"
    "github.com/MUKE-coder/sentinel/pipeline"
)

// Create a pipeline and register the GORM plugin
pipe := pipeline.New(100)
pipe.Start(2)
db.Use(sentinelgorm.New(pipe))

// Pass request context for audit attribution
ctx := sentinelgorm.WithRequestInfo(c.Request.Context(), &sentinelgorm.RequestInfo{
    IP:        c.ClientIP(),
    UserID:    c.GetHeader("X-User-ID"),
    UserAgent: c.Request.UserAgent(),
})
db.WithContext(ctx).Create(&user)
```

## Dashboard

The embedded React dashboard is served at `/sentinel/ui` (default credentials: admin/sentinel).

| Page | Description |
|------|-------------|
| **Dashboard** | Security score, threat timeline, live event stream via WebSocket |
| **Threats** | Searchable threat log with severity filtering, resolve/false-positive actions |
| **Actors** | Threat actor profiles with risk scores and block actions |
| **IP Management** | Whitelist/blacklist management for IPs and CIDR ranges |
| **WAF** | Rule management, custom rules, rule testing |
| **Rate Limits** | Configuration editor and live state monitoring |
| **Analytics** | Attack trends, geographic distribution, security score breakdown |
| **AI Insights** | AI-powered threat analysis and natural language queries |
| **Reports** | GDPR, PCI-DSS, SOC 2 compliance report generation with JSON export |
| **Alerts** | Alert configuration and history |
| **Audit Log** | Full audit trail of all data changes |
| **Performance** | API latency (p50/p95/p99) and throughput metrics |
| **Users** | User activity tracking |

## API Endpoints

All endpoints are under `/sentinel/api/` (configurable via `Dashboard.Prefix`). Protected endpoints require a JWT token from the login endpoint.

See the full [API Reference](https://sentinel-go-sdk.vercel.app/docs/api-reference) for details.

### Authentication
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Get JWT token |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/verify` | Verify token |

### Dashboard
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard/summary` | Overview stats |
| GET | `/api/security-score` | Current security score |

### Threats & Actors
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threats` | List threats (paginated, filterable) |
| GET | `/api/threats/:id` | Threat details |
| POST | `/api/threats/:id/resolve` | Mark resolved |
| POST | `/api/threats/:id/false-positive` | Mark false positive |
| GET | `/api/actors` | List threat actors |
| GET | `/api/actors/:ip` | Actor profile |
| GET | `/api/actors/:ip/threats` | Actor's threats |
| POST | `/api/actors/:ip/block` | Block actor |

### IP Management
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ip-lists` | Get whitelist/blacklist |
| POST | `/api/ip-lists` | Add IP to list |
| DELETE | `/api/ip-lists/:id` | Remove entry |

### WAF
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/waf/rules` | List WAF rules |
| POST | `/api/waf/rules` | Add custom rule |
| PUT | `/api/waf/rules/:id` | Update rule |
| DELETE | `/api/waf/rules/:id` | Delete rule |
| POST | `/api/waf/test` | Test input against rules |

### Rate Limits
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/rate-limits` | Get config |
| PUT | `/api/rate-limits` | Update config |
| GET | `/api/rate-limits/current` | Live counter states |
| POST | `/api/rate-limits/reset/:key` | Reset a counter |

### AI Analysis
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/ai/analyze-threat/:id` | Analyze a threat |
| GET | `/api/ai/analyze-actor/:ip` | Assess an actor |
| GET | `/api/ai/daily-summary` | Daily summary |
| POST | `/api/ai/query` | Natural language query |
| GET | `/api/ai/waf-recommendations` | WAF recommendations |

### Reports
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/reports/gdpr` | GDPR compliance report |
| GET | `/api/reports/pci-dss` | PCI-DSS compliance report |
| GET | `/api/reports/soc2` | SOC 2 compliance report |

### Analytics
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/analytics/trends` | Attack trends |
| GET | `/api/analytics/geographic` | Geographic distribution |
| GET | `/api/analytics/top-routes` | Most attacked routes |
| GET | `/api/analytics/time-pattern` | Hour-of-day patterns |

### WebSocket
| Protocol | Path | Description |
|----------|------|-------------|
| WS | `/ws/threats` | Live threat events |
| WS | `/ws/metrics` | Live performance metrics |

### Other
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/users` | User activity list |
| GET | `/api/audit-logs` | Audit log entries |
| GET | `/api/alerts` | Alert history |
| PUT | `/api/alerts/config` | Update alert config |
| GET | `/api/performance/overview` | System metrics |
| GET | `/api/performance/routes` | Per-route latency |

## Architecture

```
sentinel/
├── core/           # Shared types, constants, models (breaks import cycles)
├── ai/             # AI provider interface (Claude, OpenAI, Gemini)
├── alerting/       # Alert dispatching (Slack, email, webhook)
├── api/            # REST API server, JWT auth, WebSocket hub
├── detection/      # Custom rule engine, pattern matching
├── gorm/           # GORM audit logging plugin
├── intelligence/   # Threat profiling, scoring, anomaly detection, geolocation, IP reputation
├── middleware/      # Gin middleware (WAF, rate limit, headers, perf, auth shield)
├── pipeline/       # Async event pipeline (ring buffer, worker goroutines)
├── reports/        # Compliance report generators (GDPR, PCI-DSS, SOC 2)
├── storage/        # Storage interface + implementations
│   ├── memory/     # In-memory store (default, for development)
│   └── sqlite/     # Pure-Go SQLite store (recommended for production)
├── ui/             # Embedded React dashboard (go:embed)
│   └── dashboard/  # React 18 + Vite + TailwindCSS + Recharts
├── docs/           # Documentation site (Next.js 16 + Tailwind v4)
├── examples/       # Example applications
│   ├── basic/      # Minimal setup
│   └── full/       # All features configured
├── sentinel.go     # Mount() entry point
└── models.go       # Type aliases from core/
```

## Storage Backends

| Driver | Config Value | Notes |
|--------|-------------|-------|
| Memory | `sentinel.Memory` | Default. No persistence, good for development. |
| SQLite | `sentinel.SQLite` | Pure Go (no CGo), recommended for production. |

## AI Providers

| Provider | Config Value | Default Model |
|----------|-------------|---------------|
| Claude | `sentinel.Claude` | claude-sonnet-4-20250514 |
| OpenAI | `sentinel.OpenAI` | gpt-4o |
| Gemini | `sentinel.Gemini` | gemini-2.0-flash |

AI is entirely optional. When not configured, AI endpoints return a graceful "AI not configured" response and the dashboard shows setup instructions.

## Documentation

Full documentation is available at **[sentinel-go-sdk.vercel.app](https://sentinel-go-sdk.vercel.app)** with guides for every feature, code examples, and testing instructions.

## License

MIT

## Author

Built with love by [JB](https://jb.desishub.com/) | [YouTube](https://www.youtube.com/@JBWEBDEVELOPER) | [LinkedIn](https://www.linkedin.com/in/muke-johnbaptist-95bb82198/)
