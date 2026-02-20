module.exports=[61890,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Configuration Reference"}),(0,b.jsxs)("p",{children:["Sentinel is configured by passing a ",(0,b.jsx)("code",{children:"sentinel.Config"})," struct to"," ",(0,b.jsx)("code",{children:"sentinel.Mount()"}),". Every field has a sensible default, so you can start with an empty struct and enable features incrementally. This page documents every configuration section, its fields, default values, and usage patterns."]}),(0,b.jsxs)(d.default,{type:"info",title:"Zero-Value Friendly",children:["All config fields are zero-value safe. An empty ",(0,b.jsxs)("code",{children:["sentinel.Config","{}"]})," gives you a working setup with SQLite storage, the dashboard enabled, security headers active, and performance monitoring on. Features like WAF, rate limiting, and anomaly detection are opt-in via their ",(0,b.jsx)("code",{children:"Enabled"})," field."]}),(0,b.jsx)("h2",{children:"Complete Example"}),(0,b.jsx)("p",{children:"Below is a fully configured Sentinel instance with every major feature enabled. In practice, you only need to set the fields relevant to your application."}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

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
            Password:  "s3cur3-p4ss!",
            SecretKey: "my-jwt-secret-change-in-production",
        },

        Storage: sentinel.StorageConfig{
            Driver:        sentinel.SQLite,
            DSN:           "sentinel.db",
            RetentionDays: 90,
            MaxOpenConns:  10,
            MaxIdleConns:  5,
        },

        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
            Rules: sentinel.RuleSet{
                SQLInjection:     sentinel.RuleStrict,
                XSS:              sentinel.RuleStrict,
                PathTraversal:    sentinel.RuleStrict,
                CommandInjection: sentinel.RuleStrict,
                SSRF:             sentinel.RuleMedium,
                XXE:              sentinel.RuleStrict,
                LFI:              sentinel.RuleStrict,
                OpenRedirect:     sentinel.RuleMedium,
            },
            CustomRules: []sentinel.WAFRule{
                {
                    ID:        "block-admin-enum",
                    Name:      "Block admin enumeration",
                    Pattern:   \`(?i)/(wp-admin|phpmyadmin|administrator)\`,
                    AppliesTo: []string{"path"},
                    Severity:  sentinel.SeverityMedium,
                    Action:    "block",
                    Enabled:   true,
                },
            },
            ExcludeRoutes: []string{"/health", "/metrics"},
            ExcludeIPs:    []string{"10.0.0.0/8"},
        },

        RateLimit: sentinel.RateLimitConfig{
            Enabled:  true,
            Strategy: sentinel.SlidingWindow,
            ByIP:     &sentinel.Limit{Requests: 100, Window: time.Minute},
            ByUser:   &sentinel.Limit{Requests: 500, Window: time.Minute},
            Global:   &sentinel.Limit{Requests: 5000, Window: time.Minute},
            ByRoute: map[string]sentinel.Limit{
                "/api/login":    {Requests: 5, Window: 15 * time.Minute},
                "/api/register": {Requests: 3, Window: time.Hour},
            },
        },

        AuthShield: sentinel.AuthShieldConfig{
            Enabled:                    true,
            LoginRoute:                 "/api/login",
            MaxFailedAttempts:          5,
            LockoutDuration:            15 * time.Minute,
            CredentialStuffingDetection: true,
            BruteForceDetection:        true,
        },

        Headers: sentinel.HeaderConfig{
            ContentSecurityPolicy:   "default-src 'self'",
            StrictTransportSecurity: true,
            XFrameOptions:           "DENY",
            XContentTypeOptions:     true,
            ReferrerPolicy:          "strict-origin-when-cross-origin",
            PermissionsPolicy:       "camera=(), microphone=(), geolocation=()",
        },

        Anomaly: sentinel.AnomalyConfig{
            Enabled:        true,
            Sensitivity:    sentinel.AnomalySensitivityMedium,
            LearningPeriod: 7 * 24 * time.Hour,
            Checks: []sentinel.AnomalyCheckType{
                sentinel.CheckImpossibleTravel,
                sentinel.CheckUnusualAccess,
                sentinel.CheckDataExfiltration,
                sentinel.CheckOffHoursAccess,
                sentinel.CheckVelocityAnomaly,
            },
        },

        IPReputation: sentinel.IPReputationConfig{
            Enabled:       true,
            AbuseIPDBKey:  "your-abuseipdb-api-key",
            AutoBlock:     true,
            MinAbuseScore: 80,
        },

        Geo: sentinel.GeoConfig{
            Enabled:  true,
            Provider: sentinel.GeoIPFree,
        },

        Alerts: sentinel.AlertConfig{
            MinSeverity: sentinel.SeverityHigh,
            Slack: &sentinel.SlackConfig{
                WebhookURL: "https://hooks.slack.com/services/...",
            },
            Email: &sentinel.EmailConfig{
                SMTPHost:   "smtp.example.com",
                SMTPPort:   587,
                Username:   "alerts@example.com",
                Password:   "smtp-password",
                Recipients: []string{"security@example.com"},
            },
            Webhook: &sentinel.WebhookConfig{
                URL: "https://your-siem.example.com/webhook",
                Headers: map[string]string{
                    "Authorization": "Bearer your-token",
                },
            },
        },

        AI: &sentinel.AIConfig{
            Provider:     sentinel.Claude,
            APIKey:       "your-anthropic-api-key",
            Model:        "claude-sonnet-4-20250514",
            DailySummary: true,
        },

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

        Performance: sentinel.PerformanceConfig{
            SlowRequestThreshold: 2 * time.Second,
            SlowQueryThreshold:   500 * time.Millisecond,
            TrackMemory:          true,
            TrackGoroutines:      true,
        },
    })

    r.GET("/api/hello", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, World!"})
    })

    r.Run(":8080")
}`}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"DashboardConfig"})," controls the embedded React security dashboard. The dashboard is enabled by default and served under the configured prefix. It is protected by JWT-based authentication using the username and password you provide."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})}),(0,b.jsxs)("td",{children:["Whether the dashboard is served. Set to ",(0,b.jsx)("code",{children:"false"})," to disable entirely."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Prefix"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"/sentinel"})}),(0,b.jsxs)("td",{children:["URL prefix for the dashboard and API routes. The UI is available at ",(0,b.jsxs)("code",{children:["{prefix}","/ui"]}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Username"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"admin"})}),(0,b.jsx)("td",{children:"Username for dashboard login."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Password"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel"})}),(0,b.jsx)("td",{children:"Password for dashboard login."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SecretKey"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel-default-secret-change-me"})}),(0,b.jsx)("td",{children:"Secret key used to sign JWT tokens for dashboard sessions."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`Dashboard: sentinel.DashboardConfig{
    Prefix:    "/admin/security",
    Username:  "secops",
    Password:  "change-me-in-production",
    SecretKey: "a-strong-random-secret",
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Change Default Credentials",children:["The default username/password (",(0,b.jsx)("code",{children:"admin"}),"/",(0,b.jsx)("code",{children:"sentinel"}),") and secret key are intended for development only. Always set strong values in production. The"," ",(0,b.jsx)("code",{children:"SecretKey"})," is used to sign JWT tokens — if it is compromised, attackers can forge dashboard sessions."]}),(0,b.jsxs)(d.default,{type:"info",title:"Disabling the Dashboard",children:["To run Sentinel as a headless middleware without any dashboard routes, set"," ",(0,b.jsx)("code",{children:"Enabled"})," to ",(0,b.jsx)("code",{children:"false"}),". Because the field is a ",(0,b.jsx)("code",{children:"*bool"}),", you need to use a pointer:",(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`disabled := false
Dashboard: sentinel.DashboardConfig{
    Enabled: &disabled,
}`})]}),(0,b.jsx)("h2",{id:"storage",children:"Storage"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"StorageConfig"})," controls how Sentinel persists security events, threat actors, rate limit counters, and other data. Sentinel ships with two built-in storage drivers and supports additional drivers."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Driver"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"StorageDriver"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SQLite"})}),(0,b.jsxs)("td",{children:["Storage backend. Options: ",(0,b.jsx)("code",{children:"sentinel.SQLite"}),", ",(0,b.jsx)("code",{children:"sentinel.Memory"}),", ",(0,b.jsx)("code",{children:"sentinel.Postgres"}),", ",(0,b.jsx)("code",{children:"sentinel.MySQL"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"DSN"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.db"})}),(0,b.jsx)("td",{children:"Data source name. For SQLite, this is a file path. For Postgres/MySQL, a full connection string."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RetentionDays"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"90"})}),(0,b.jsx)("td",{children:"Number of days to retain security events before automatic cleanup."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MaxOpenConns"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"10"})}),(0,b.jsx)("td",{children:"Maximum number of open database connections."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MaxIdleConns"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"5"})}),(0,b.jsx)("td",{children:"Maximum number of idle database connections."})]})]})]}),(0,b.jsx)("h3",{children:"Storage Drivers"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Driver"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Notes"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"SQLite"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SQLite"})}),(0,b.jsx)("td",{children:"Pure Go (no CGo). Recommended for most deployments. Data persists to a file."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Memory"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.Memory"})}),(0,b.jsx)("td",{children:"In-memory store. No persistence — data is lost on restart. Useful for testing."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Postgres"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.Postgres"})}),(0,b.jsx)("td",{children:"PostgreSQL backend for high-availability production deployments."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"MySQL"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.MySQL"})}),(0,b.jsx)("td",{children:"MySQL/MariaDB backend."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`// SQLite (default, recommended)
Storage: sentinel.StorageConfig{
    Driver:        sentinel.SQLite,
    DSN:           "sentinel.db",
    RetentionDays: 30,
}

// In-memory (for development/testing)
Storage: sentinel.StorageConfig{
    Driver: sentinel.Memory,
}

// PostgreSQL
Storage: sentinel.StorageConfig{
    Driver:       sentinel.Postgres,
    DSN:          "postgres://user:pass@localhost:5432/sentinel?sslmode=disable",
    MaxOpenConns: 25,
    MaxIdleConns: 10,
}`}),(0,b.jsxs)(d.default,{type:"info",title:"No CGo Required",children:["The SQLite driver uses a pure-Go implementation (",(0,b.jsx)("code",{children:"github.com/glebarez/sqlite"}),"), so you do not need CGo or any C compiler installed. This makes cross-compilation and Docker builds straightforward."]}),(0,b.jsx)("h2",{id:"waf",children:"WAF (Web Application Firewall)"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"WAFConfig"})," controls the built-in Web Application Firewall. When enabled, it inspects incoming requests for SQL injection, XSS, path traversal, command injection, SSRF, XXE, LFI, and open redirect attacks. It can operate in log-only mode (observe without blocking) or block mode (reject malicious requests with a 403 status)."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsxs)("td",{children:["Enables the WAF middleware. Must be set to ",(0,b.jsx)("code",{children:"true"})," to activate."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Mode"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"WAFMode"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.ModeLog"})}),(0,b.jsxs)("td",{children:["How detected threats are handled. Options: ",(0,b.jsx)("code",{children:"sentinel.ModeLog"}),", ",(0,b.jsx)("code",{children:"sentinel.ModeBlock"}),", ",(0,b.jsx)("code",{children:"sentinel.ModeChallenge"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Rules"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleSet"})}),(0,b.jsxs)("td",{children:["All ",(0,b.jsx)("code",{children:"RuleStrict"})]}),(0,b.jsx)("td",{children:"Per-category sensitivity levels for built-in detection rules."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CustomRules"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]WAFRule"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Custom regex-based rules for application-specific patterns."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ExcludeRoutes"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Routes to exclude from WAF inspection (e.g., health check endpoints)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ExcludeIPs"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"IP addresses or CIDR ranges to exclude from WAF inspection."})]})]})]}),(0,b.jsx)("h3",{children:"WAF Modes"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Mode"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Behavior"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Log"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.ModeLog"})}),(0,b.jsx)("td",{children:"Detects and logs threats but allows the request to proceed. Good for initial rollout."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Block"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.ModeBlock"})}),(0,b.jsx)("td",{children:"Detects threats and rejects the request with HTTP 403. Recommended for production."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Challenge"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.ModeChallenge"})}),(0,b.jsx)("td",{children:"Presents a challenge to the client before allowing the request through."})]})]})]}),(0,b.jsx)("h3",{children:"RuleSet — Per-Category Sensitivity"}),(0,b.jsxs)("p",{children:["Each built-in detection category can have its sensitivity tuned independently. The available levels are ",(0,b.jsx)("code",{children:"sentinel.RuleOff"}),", ",(0,b.jsx)("code",{children:"sentinel.RuleLow"}),","," ",(0,b.jsx)("code",{children:"sentinel.RuleMedium"}),", and ",(0,b.jsx)("code",{children:"sentinel.RuleStrict"}),"."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SQLInjection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsx)("td",{children:"SQL injection detection sensitivity."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XSS"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsx)("td",{children:"Cross-site scripting detection sensitivity."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"PathTraversal"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsxs)("td",{children:["Path traversal (",(0,b.jsx)("code",{children:"../../etc/passwd"}),") detection sensitivity."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CommandInjection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsx)("td",{children:"OS command injection detection sensitivity."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SSRF"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleMedium"})}),(0,b.jsx)("td",{children:"Server-side request forgery detection sensitivity."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XXE"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsx)("td",{children:"XML external entity injection detection sensitivity."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LFI"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsx)("td",{children:"Local file inclusion detection sensitivity."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"OpenRedirect"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleMedium"})}),(0,b.jsx)("td",{children:"Open redirect detection sensitivity."})]})]})]}),(0,b.jsx)("h3",{children:"Custom WAF Rules"}),(0,b.jsxs)("p",{children:["Custom rules let you add application-specific detection patterns using regular expressions. Each rule is defined as a ",(0,b.jsx)("code",{children:"WAFRule"})," struct."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Unique identifier for the rule."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Name"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Human-readable name displayed in the dashboard."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Pattern"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Go-compatible regular expression to match against request data."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AppliesTo"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsxs)("td",{children:["Which parts of the request to inspect: ",(0,b.jsx)("code",{children:'"path"'}),", ",(0,b.jsx)("code",{children:'"query"'}),", ",(0,b.jsx)("code",{children:'"body"'}),", ",(0,b.jsx)("code",{children:'"headers"'}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsxs)("td",{children:["Severity level: ",(0,b.jsx)("code",{children:"sentinel.SeverityLow"}),", ",(0,b.jsx)("code",{children:"SeverityMedium"}),", ",(0,b.jsx)("code",{children:"SeverityHigh"}),", ",(0,b.jsx)("code",{children:"SeverityCritical"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Action"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["Action to take: ",(0,b.jsx)("code",{children:'"block"'})," or ",(0,b.jsx)("code",{children:'"log"'}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:"Whether the rule is active."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
    Rules: sentinel.RuleSet{
        SQLInjection:     sentinel.RuleStrict,
        XSS:              sentinel.RuleStrict,
        PathTraversal:    sentinel.RuleStrict,
        CommandInjection: sentinel.RuleStrict,
        SSRF:             sentinel.RuleMedium,
        XXE:              sentinel.RuleStrict,
        LFI:              sentinel.RuleStrict,
        OpenRedirect:     sentinel.RuleMedium,
    },
    CustomRules: []sentinel.WAFRule{
        {
            ID:        "block-admin-enum",
            Name:      "Block admin enumeration",
            Pattern:   \`(?i)/(wp-admin|phpmyadmin|administrator)\`,
            AppliesTo: []string{"path"},
            Severity:  sentinel.SeverityMedium,
            Action:    "block",
            Enabled:   true,
        },
        {
            ID:        "block-sensitive-files",
            Name:      "Block sensitive file access",
            Pattern:   \`(?i)\\.(env|git|bak|sql|log)$\`,
            AppliesTo: []string{"path"},
            Severity:  sentinel.SeverityHigh,
            Action:    "block",
            Enabled:   true,
        },
    },
    ExcludeRoutes: []string{"/health", "/readiness"},
    ExcludeIPs:    []string{"127.0.0.1", "10.0.0.0/8"},
}`}),(0,b.jsxs)(d.default,{type:"success",title:"Recommended Rollout Strategy",children:["Start with ",(0,b.jsx)("code",{children:"sentinel.ModeLog"})," in production to observe what the WAF detects without blocking real traffic. Review the dashboard for false positives, tune rule sensitivities, then switch to ",(0,b.jsx)("code",{children:"sentinel.ModeBlock"})," when confident."]}),(0,b.jsx)("h2",{id:"rate-limiting",children:"Rate Limiting"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"RateLimitConfig"})," enables multi-dimensional rate limiting. You can set limits per IP, per authenticated user, per route, and globally. All dimensions are enforced independently — a request must pass all applicable limits."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables the rate limiting middleware."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Strategy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RateLimitStrategy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SlidingWindow"})}),(0,b.jsxs)("td",{children:["Algorithm used for counting. Options: ",(0,b.jsx)("code",{children:"sentinel.SlidingWindow"}),", ",(0,b.jsx)("code",{children:"sentinel.FixedWindow"}),", ",(0,b.jsx)("code",{children:"sentinel.TokenBucket"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ByIP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Per-IP rate limit. Each unique client IP gets its own counter."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ByUser"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsxs)("td",{children:["Per-user rate limit. Requires a ",(0,b.jsx)("code",{children:"UserIDExtractor"})," or ",(0,b.jsx)("code",{children:"UserExtractor"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ByRoute"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"map[string]Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsxs)("td",{children:["Per-route rate limits. Keys are route patterns (e.g., ",(0,b.jsx)("code",{children:"/api/login"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Global"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Global rate limit applied across all requests regardless of source."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserIDExtractor"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"func(*gin.Context) string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Function to extract a user ID from the request for per-user limiting."})]})]})]}),(0,b.jsx)("h3",{children:"The Limit Struct"}),(0,b.jsx)("p",{children:"Each limit is defined by a number of allowed requests within a time window."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Requests"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:"Maximum number of requests allowed within the window."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Window"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsxs)("td",{children:["Time window for the limit (e.g., ",(0,b.jsx)("code",{children:"time.Minute"}),", ",(0,b.jsx)("code",{children:"15 * time.Minute"}),")."]})]})]})]}),(0,b.jsx)("h3",{children:"Rate Limit Strategies"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Strategy"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Sliding Window"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SlidingWindow"})}),(0,b.jsx)("td",{children:"Default. Provides smooth rate limiting without burst spikes at window boundaries."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Fixed Window"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.FixedWindow"})}),(0,b.jsx)("td",{children:"Simple fixed time windows. Slightly less accurate but lower memory overhead."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Token Bucket"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.TokenBucket"})}),(0,b.jsx)("td",{children:"Allows short bursts while maintaining an average rate over time."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`RateLimit: sentinel.RateLimitConfig{
    Enabled:  true,
    Strategy: sentinel.SlidingWindow,

    // 100 requests per minute per IP
    ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute},

    // 500 requests per minute per authenticated user
    ByUser: &sentinel.Limit{Requests: 500, Window: time.Minute},

    // 5000 requests per minute globally
    Global: &sentinel.Limit{Requests: 5000, Window: time.Minute},

    // Strict limits on sensitive routes
    ByRoute: map[string]sentinel.Limit{
        "/api/login":    {Requests: 5, Window: 15 * time.Minute},
        "/api/register": {Requests: 3, Window: time.Hour},
        "/api/password-reset": {Requests: 3, Window: time.Hour},
    },

    // Extract user ID from your auth system
    UserIDExtractor: func(c *gin.Context) string {
        return c.GetHeader("X-User-ID")
    },
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Rate Limit Headers",children:["When rate limiting is active, Sentinel automatically sets standard rate limit headers on every response: ",(0,b.jsx)("code",{children:"X-RateLimit-Limit"}),", ",(0,b.jsx)("code",{children:"X-RateLimit-Remaining"}),", and"," ",(0,b.jsx)("code",{children:"X-RateLimit-Reset"}),". When a limit is exceeded, the client receives a"," ",(0,b.jsx)("code",{children:"429 Too Many Requests"})," response."]}),(0,b.jsx)("h2",{id:"auth-shield",children:"Auth Shield"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"AuthShieldConfig"})," protects authentication endpoints from brute-force attacks and credential stuffing. When enabled, it monitors the configured login route for failed authentication attempts and automatically locks out offending IPs."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables the Auth Shield middleware."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LoginRoute"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'""'})}),(0,b.jsxs)("td",{children:["The route path for your login endpoint (e.g., ",(0,b.jsx)("code",{children:"/api/login"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MaxFailedAttempts"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"5"})}),(0,b.jsx)("td",{children:"Number of failed login attempts before lockout is triggered."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LockoutDuration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"15 * time.Minute"})}),(0,b.jsxs)("td",{children:["How long an IP is locked out after exceeding ",(0,b.jsx)("code",{children:"MaxFailedAttempts"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CredentialStuffingDetection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Detects credential stuffing patterns (many different usernames from the same IP)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"BruteForceDetection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Detects brute force patterns (many password attempts for the same username)."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`AuthShield: sentinel.AuthShieldConfig{
    Enabled:                    true,
    LoginRoute:                 "/api/login",
    MaxFailedAttempts:          5,
    LockoutDuration:            15 * time.Minute,
    CredentialStuffingDetection: true,
    BruteForceDetection:        true,
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"LoginRoute Must Match Exactly",children:["The ",(0,b.jsx)("code",{children:"LoginRoute"})," must match the exact path of your login handler. Sentinel monitors this route for non-2xx responses to count failed login attempts. If the route does not match, Auth Shield will not detect failures."]}),(0,b.jsx)("h2",{id:"headers",children:"Security Headers"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"HeaderConfig"})," controls automatic injection of security headers into every response. Security headers are enabled by default. These headers protect against clickjacking, MIME sniffing, XSS, and other client-side attacks."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})}),(0,b.jsxs)("td",{children:["Whether security headers are injected. Use a ",(0,b.jsx)("code",{children:"*bool"})," to explicitly disable."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ContentSecurityPolicy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:'""'})," (not set)"]}),(0,b.jsxs)("td",{children:["Value for the ",(0,b.jsx)("code",{children:"Content-Security-Policy"})," header. Left empty by default because CSP is application-specific."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"StrictTransportSecurity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsxs)("td",{children:["When ",(0,b.jsx)("code",{children:"true"}),", sets ",(0,b.jsx)("code",{children:"Strict-Transport-Security: max-age=31536000; includeSubDomains"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XFrameOptions"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"DENY"})}),(0,b.jsxs)("td",{children:["Value for the ",(0,b.jsx)("code",{children:"X-Frame-Options"})," header. Common values: ",(0,b.jsx)("code",{children:"DENY"}),", ",(0,b.jsx)("code",{children:"SAMEORIGIN"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XContentTypeOptions"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})}),(0,b.jsxs)("td",{children:["When ",(0,b.jsx)("code",{children:"true"}),", sets ",(0,b.jsx)("code",{children:"X-Content-Type-Options: nosniff"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ReferrerPolicy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"strict-origin-when-cross-origin"})}),(0,b.jsxs)("td",{children:["Value for the ",(0,b.jsx)("code",{children:"Referrer-Policy"})," header."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"PermissionsPolicy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:'""'})," (not set)"]}),(0,b.jsxs)("td",{children:["Value for the ",(0,b.jsx)("code",{children:"Permissions-Policy"})," header. Controls browser feature access."]})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`Headers: sentinel.HeaderConfig{
    ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline'",
    StrictTransportSecurity: true,
    XFrameOptions:           "DENY",
    XContentTypeOptions:     true,
    ReferrerPolicy:          "strict-origin-when-cross-origin",
    PermissionsPolicy:       "camera=(), microphone=(), geolocation=()",
}`}),(0,b.jsxs)(d.default,{type:"info",title:"HSTS Warning",children:["Only enable ",(0,b.jsx)("code",{children:"StrictTransportSecurity"})," if your application is served exclusively over HTTPS. Once a browser receives an HSTS header, it will refuse to connect over plain HTTP for the specified duration."]}),(0,b.jsx)("h2",{id:"anomaly",children:"Anomaly Detection"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"AnomalyConfig"})," enables behavioral anomaly detection. Sentinel learns normal traffic patterns during a configurable learning period and then flags deviations such as impossible travel, unusual access patterns, and data exfiltration attempts."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables the anomaly detection engine."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Sensitivity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AnomalySensitivity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.AnomalySensitivityMedium"})}),(0,b.jsxs)("td",{children:["Detection sensitivity. Options: ",(0,b.jsx)("code",{children:"sentinel.AnomalySensitivityLow"}),", ",(0,b.jsx)("code",{children:"AnomalySensitivityMedium"}),", ",(0,b.jsx)("code",{children:"AnomalySensitivityHigh"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LearningPeriod"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"7 * 24 * time.Hour"})," (7 days)"]}),(0,b.jsx)("td",{children:"Duration of the initial learning phase during which Sentinel builds baseline traffic patterns."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Checks"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]AnomalyCheckType"})}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"nil"})," (all checks)"]}),(0,b.jsxs)("td",{children:["Which anomaly checks to run. When ",(0,b.jsx)("code",{children:"nil"}),", all checks are enabled."]})]})]})]}),(0,b.jsx)("h3",{children:"Anomaly Check Types"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Check"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Impossible Travel"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.CheckImpossibleTravel"})}),(0,b.jsx)("td",{children:"Detects logins from geographically distant locations within impossibly short timeframes."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Unusual Access"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.CheckUnusualAccess"})}),(0,b.jsx)("td",{children:"Flags access to endpoints not typically visited by a given user or IP."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Data Exfiltration"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.CheckDataExfiltration"})}),(0,b.jsx)("td",{children:"Detects abnormally large data transfers or rapid sequential data access."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Off-Hours Access"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.CheckOffHoursAccess"})}),(0,b.jsx)("td",{children:"Flags access outside of normal business hours for a given user profile."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Velocity Anomaly"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.CheckVelocityAnomaly"})}),(0,b.jsx)("td",{children:"Detects sudden spikes in request velocity from a single source."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Credential Stuffing"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.CheckCredentialStuffing"})}),(0,b.jsx)("td",{children:"Identifies patterns consistent with credential stuffing attacks on auth endpoints."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`Anomaly: sentinel.AnomalyConfig{
    Enabled:        true,
    Sensitivity:    sentinel.AnomalySensitivityMedium,
    LearningPeriod: 7 * 24 * time.Hour,
    Checks: []sentinel.AnomalyCheckType{
        sentinel.CheckImpossibleTravel,
        sentinel.CheckUnusualAccess,
        sentinel.CheckDataExfiltration,
        sentinel.CheckVelocityAnomaly,
    },
}`}),(0,b.jsx)(d.default,{type:"info",title:"Learning Period",children:"During the learning period, Sentinel collects baseline data but does not flag anomalies. After the learning period expires, detections begin automatically. A shorter learning period may produce more false positives; a longer period provides more accurate baselines."}),(0,b.jsx)("h2",{id:"ip-reputation",children:"IP Reputation"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"IPReputationConfig"})," integrates with the AbuseIPDB API to check the reputation score of incoming IP addresses. Known malicious IPs can be automatically blocked."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables IP reputation checking."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AbuseIPDBKey"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'""'})}),(0,b.jsxs)("td",{children:["Your AbuseIPDB API key. Required when ",(0,b.jsx)("code",{children:"Enabled"})," is ",(0,b.jsx)("code",{children:"true"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AutoBlock"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsxs)("td",{children:["Automatically add IPs exceeding ",(0,b.jsx)("code",{children:"MinAbuseScore"})," to the blocklist."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MinAbuseScore"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"80"})}),(0,b.jsx)("td",{children:"Minimum AbuseIPDB confidence score (0-100) to consider an IP malicious."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`IPReputation: sentinel.IPReputationConfig{
    Enabled:       true,
    AbuseIPDBKey:  os.Getenv("ABUSEIPDB_API_KEY"),
    AutoBlock:     true,
    MinAbuseScore: 80,
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"API Rate Limits",children:["AbuseIPDB has rate limits on their free plan. Sentinel caches reputation lookups to minimize API calls, but high-traffic applications should consider a paid AbuseIPDB plan or adjust the"," ",(0,b.jsx)("code",{children:"MinAbuseScore"})," threshold."]}),(0,b.jsx)("h2",{id:"geo",children:"Geolocation"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"GeoConfig"})," enables IP geolocation for enriching security events with country, city, and coordinate data. This powers the dashboard map view and the impossible travel anomaly check."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables IP geolocation lookups."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Provider"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GeoProvider"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.GeoIPFree"})}),(0,b.jsxs)("td",{children:["Geolocation provider. Options: ",(0,b.jsx)("code",{children:"sentinel.GeoIPFree"})," (GeoLite2), ",(0,b.jsx)("code",{children:"sentinel.GeoIPPaid"})," (GeoIP2)."]})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`Geo: sentinel.GeoConfig{
    Enabled:  true,
    Provider: sentinel.GeoIPFree,
}`}),(0,b.jsx)("h2",{id:"alerts",children:"Alerts"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"AlertConfig"})," configures real-time alerting when security events exceed a severity threshold. Sentinel supports three alert channels: Slack, email, and generic webhooks. You can enable one or more channels simultaneously."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MinSeverity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SeverityHigh"})}),(0,b.jsxs)("td",{children:["Minimum severity level to trigger alerts. Options: ",(0,b.jsx)("code",{children:"SeverityLow"}),", ",(0,b.jsx)("code",{children:"SeverityMedium"}),", ",(0,b.jsx)("code",{children:"SeverityHigh"}),", ",(0,b.jsx)("code",{children:"SeverityCritical"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Slack"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*SlackConfig"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Slack webhook configuration. Set to enable Slack alerts."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Email"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*EmailConfig"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Email SMTP configuration. Set to enable email alerts."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Webhook"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*WebhookConfig"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Generic webhook configuration. Set to enable webhook alerts."})]})]})]}),(0,b.jsx)("h3",{children:"Slack Alerts"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsx)("tbody",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"WebhookURL"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The Slack incoming webhook URL."})]})})]}),(0,b.jsx)("h3",{children:"Email Alerts"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SMTPHost"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"SMTP server hostname."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SMTPPort"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:"SMTP server port (typically 587 for TLS, 465 for SSL)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Username"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"SMTP authentication username."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Password"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"SMTP authentication password."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Recipients"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsx)("td",{children:"List of email addresses to receive alerts."})]})]})]}),(0,b.jsx)("h3",{children:"Webhook Alerts"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"URL"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The webhook endpoint URL. Sentinel sends a JSON POST request."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Headers"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"map[string]string"})}),(0,b.jsx)("td",{children:"Custom HTTP headers to include in webhook requests (e.g., for authentication)."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`Alerts: sentinel.AlertConfig{
    MinSeverity: sentinel.SeverityHigh,

    // Slack alerts
    Slack: &sentinel.SlackConfig{
        WebhookURL: "https://hooks.slack.com/services/T00/B00/xxx",
    },

    // Email alerts
    Email: &sentinel.EmailConfig{
        SMTPHost:   "smtp.example.com",
        SMTPPort:   587,
        Username:   "alerts@example.com",
        Password:   "smtp-password",
        Recipients: []string{
            "security-team@example.com",
            "oncall@example.com",
        },
    },

    // Webhook alerts (e.g., to a SIEM)
    Webhook: &sentinel.WebhookConfig{
        URL: "https://siem.example.com/api/ingest",
        Headers: map[string]string{
            "Authorization": "Bearer your-api-token",
            "X-Source":      "sentinel",
        },
    },
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Multiple Alert Channels",children:["You can enable any combination of Slack, email, and webhook alerts. When an event exceeds the"," ",(0,b.jsx)("code",{children:"MinSeverity"})," threshold, it is dispatched to all configured channels concurrently."]}),(0,b.jsx)("h2",{id:"ai",children:"AI Analysis"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"AIConfig"})," enables AI-powered security analysis. When configured, Sentinel uses large language models to analyze threat patterns, generate daily security summaries, and provide natural-language insights in the dashboard. This is an optional feature — it requires an API key from one of the supported providers."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Provider"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AIProvider"})}),(0,b.jsx)("td",{children:"(none)"}),(0,b.jsxs)("td",{children:["AI provider. Options: ",(0,b.jsx)("code",{children:"sentinel.Claude"}),", ",(0,b.jsx)("code",{children:"sentinel.OpenAI"}),", ",(0,b.jsx)("code",{children:"sentinel.Gemini"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"APIKey"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'""'})}),(0,b.jsx)("td",{children:"API key for the selected provider."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Model"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"(provider default)"}),(0,b.jsx)("td",{children:"Optional model override. If empty, Sentinel uses the provider's recommended model."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"DailySummary"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsxs)("td",{children:["When ",(0,b.jsx)("code",{children:"true"}),", generates a daily AI-powered security summary."]})]})]})]}),(0,b.jsx)("h3",{children:"Supported Providers"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Provider"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Default Model"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Anthropic Claude"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.Claude"})}),(0,b.jsx)("td",{children:"Claude Sonnet"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"OpenAI"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.OpenAI"})}),(0,b.jsx)("td",{children:"GPT-4o"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Google Gemini"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.Gemini"})}),(0,b.jsx)("td",{children:"Gemini Pro"})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`// Using Anthropic Claude
AI: &sentinel.AIConfig{
    Provider:     sentinel.Claude,
    APIKey:       os.Getenv("ANTHROPIC_API_KEY"),
    DailySummary: true,
}

// Using OpenAI
AI: &sentinel.AIConfig{
    Provider: sentinel.OpenAI,
    APIKey:   os.Getenv("OPENAI_API_KEY"),
    Model:    "gpt-4o",
}

// Using Google Gemini
AI: &sentinel.AIConfig{
    Provider: sentinel.Gemini,
    APIKey:   os.Getenv("GEMINI_API_KEY"),
}`}),(0,b.jsxs)(d.default,{type:"info",title:"AI is Optional",children:["The ",(0,b.jsx)("code",{children:"AI"})," field is a pointer (",(0,b.jsx)("code",{children:"*AIConfig"}),"). When left as ",(0,b.jsx)("code",{children:"nil"}),", no AI provider is initialized and no API calls are made. The dashboard AI analysis tab will show a message indicating that AI is not configured."]}),(0,b.jsx)("h2",{id:"user-extractor",children:"User Extractor"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"UserExtractor"})," is a function that extracts authenticated user context from each incoming request. Sentinel uses this information for per-user rate limiting, user-level threat profiling, and audit logging. Return ",(0,b.jsx)("code",{children:"nil"})," for unauthenticated requests."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsx)("tbody",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserExtractor"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"func(*gin.Context) *UserContext"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsxs)("td",{children:["Function to extract user information from a request. Return ",(0,b.jsx)("code",{children:"nil"})," if no user is authenticated."]})]})})]}),(0,b.jsx)("h3",{children:"UserContext Struct"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Unique user identifier."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Email"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"User email address (used in alerts and dashboard display)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Role"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["User role (e.g., ",(0,b.jsx)("code",{children:'"admin"'}),", ",(0,b.jsx)("code",{children:'"user"'}),"). Used for access pattern analysis."]})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`// Extract user from JWT claims set by your auth middleware
UserExtractor: func(c *gin.Context) *sentinel.UserContext {
    // Option 1: From headers (proxy/gateway sets these)
    userID := c.GetHeader("X-User-ID")
    if userID == "" {
        return nil // Unauthenticated request
    }
    return &sentinel.UserContext{
        ID:    userID,
        Email: c.GetHeader("X-User-Email"),
        Role:  c.GetHeader("X-User-Role"),
    }
}

// Option 2: From Gin context (your auth middleware sets these)
UserExtractor: func(c *gin.Context) *sentinel.UserContext {
    userID, exists := c.Get("userID")
    if !exists {
        return nil
    }
    return &sentinel.UserContext{
        ID:    userID.(string),
        Email: c.GetString("userEmail"),
        Role:  c.GetString("userRole"),
    }
}`}),(0,b.jsxs)(d.default,{type:"info",title:"UserExtractor vs UserIDExtractor",children:[(0,b.jsx)("code",{children:"Config.UserExtractor"})," provides full user context (ID, email, role) for threat profiling and dashboard display. ",(0,b.jsx)("code",{children:"RateLimitConfig.UserIDExtractor"})," is a simpler function that returns only a user ID string for rate limiting. If you set"," ",(0,b.jsx)("code",{children:"UserExtractor"}),", Sentinel can derive the user ID from it automatically. You only need ",(0,b.jsx)("code",{children:"UserIDExtractor"})," if you want rate limiting to use a different identifier."]}),(0,b.jsx)("h2",{id:"performance",children:"Performance Monitoring"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"PerformanceConfig"})," controls request performance tracking and system resource monitoring. Performance monitoring is enabled by default. Sentinel records request durations, flags slow requests, and optionally tracks memory usage and goroutine counts."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})}),(0,b.jsxs)("td",{children:["Whether performance monitoring is active. Use a ",(0,b.jsx)("code",{children:"*bool"})," to explicitly disable."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SlowRequestThreshold"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"2 * time.Second"})}),(0,b.jsx)("td",{children:"Requests exceeding this duration are flagged as slow in the dashboard."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SlowQueryThreshold"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"500 * time.Millisecond"})}),(0,b.jsx)("td",{children:"Database queries exceeding this duration are flagged as slow (used with the GORM plugin)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"TrackMemory"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Track Go runtime memory statistics and expose them in the dashboard."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"TrackGoroutines"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Track the number of active goroutines and expose in the dashboard."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`Performance: sentinel.PerformanceConfig{
    SlowRequestThreshold: 1 * time.Second,
    SlowQueryThreshold:   200 * time.Millisecond,
    TrackMemory:          true,
    TrackGoroutines:      true,
}`}),(0,b.jsx)("h2",{id:"defaults",children:"Defaults (Zero Config)"}),(0,b.jsxs)("p",{children:["When you pass an empty ",(0,b.jsxs)("code",{children:["sentinel.Config","{}"]}),", Sentinel applies the following defaults via the ",(0,b.jsx)("code",{children:"ApplyDefaults()"})," method. This table summarizes the effective configuration with zero user-provided values."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Section"}),(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Default Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Dashboard"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Dashboard"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Prefix"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"/sentinel"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Dashboard"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Username"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"admin"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Dashboard"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Password"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Dashboard"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SecretKey"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel-default-secret-change-me"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Storage"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Driver"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SQLite"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Storage"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"DSN"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.db"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Storage"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RetentionDays"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"90"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Storage"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MaxOpenConns"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"10"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Storage"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MaxIdleConns"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"5"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Mode"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.ModeLog"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SQLInjection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleStrict"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XSS"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleStrict"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"PathTraversal"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleStrict"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CommandInjection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleStrict"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SSRF"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleMedium"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XXE"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleStrict"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LFI"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleStrict"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF Rules"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"OpenRedirect"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleMedium"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Rate Limit"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Rate Limit"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Strategy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SlidingWindow"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Auth Shield"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Auth Shield"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MaxFailedAttempts"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"5"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Auth Shield"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LockoutDuration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"15 * time.Minute"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Headers"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Headers"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XFrameOptions"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"DENY"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Headers"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XContentTypeOptions"})}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"true"})," (nosniff)"]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Headers"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ReferrerPolicy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"strict-origin-when-cross-origin"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Anomaly"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Anomaly"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Sensitivity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.AnomalySensitivityMedium"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Anomaly"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LearningPeriod"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"7 * 24 * time.Hour"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"IP Reputation"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"IP Reputation"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MinAbuseScore"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"80"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Geo"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Geo"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Provider"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.GeoIPFree"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Alerts"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MinSeverity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SeverityHigh"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"AI"}),(0,b.jsx)("td",{children:"(entire section)"}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"nil"})," (disabled)"]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Performance"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"true"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Performance"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SlowRequestThreshold"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"2 * time.Second"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Performance"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SlowQueryThreshold"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"500 * time.Millisecond"})})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`// Zero config — all defaults applied automatically
r := gin.Default()
sentinel.Mount(r, nil, sentinel.Config{})

// This is equivalent to:
sentinel.Mount(r, nil, sentinel.Config{
    Dashboard: sentinel.DashboardConfig{
        // Enabled:   true (default)
        // Prefix:    "/sentinel"
        // Username:  "admin"
        // Password:  "sentinel"
    },
    Storage: sentinel.StorageConfig{
        // Driver:        sentinel.SQLite
        // DSN:           "sentinel.db"
        // RetentionDays: 90
    },
    // WAF:       disabled
    // RateLimit: disabled
    // AuthShield: disabled
    // Headers:   enabled with safe defaults
    // Anomaly:   disabled
    // Performance: enabled
})`}),(0,b.jsxs)(d.default,{type:"success",title:"Production Checklist",children:["Before deploying to production, make sure to:",(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:["Change the dashboard ",(0,b.jsx)("code",{children:"Username"}),", ",(0,b.jsx)("code",{children:"Password"}),", and ",(0,b.jsx)("code",{children:"SecretKey"})]}),(0,b.jsxs)("li",{children:["Enable the WAF with ",(0,b.jsx)("code",{children:"ModeBlock"})]}),(0,b.jsx)("li",{children:"Set up rate limiting with appropriate thresholds for your traffic"}),(0,b.jsx)("li",{children:"Configure at least one alert channel (Slack, email, or webhook)"}),(0,b.jsxs)("li",{children:["Use ",(0,b.jsx)("code",{children:"sentinel.SQLite"})," or ",(0,b.jsx)("code",{children:"sentinel.Postgres"})," for persistent storage"]}),(0,b.jsxs)("li",{children:["Set ",(0,b.jsx)("code",{children:"StrictTransportSecurity: true"})," if serving over HTTPS"]})]})]}),(0,b.jsx)("h2",{children:"Environment Variables Pattern"}),(0,b.jsx)("p",{children:"While Sentinel does not read environment variables directly, a common pattern is to read them yourself and pass them into the config struct. This keeps secrets out of your source code."}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`import "os"

config := sentinel.Config{
    Dashboard: sentinel.DashboardConfig{
        Username:  os.Getenv("SENTINEL_USERNAME"),
        Password:  os.Getenv("SENTINEL_PASSWORD"),
        SecretKey: os.Getenv("SENTINEL_SECRET_KEY"),
    },
    Storage: sentinel.StorageConfig{
        Driver: sentinel.SQLite,
        DSN:    os.Getenv("SENTINEL_DB_PATH"),
    },
    AI: &sentinel.AIConfig{
        Provider: sentinel.Claude,
        APIKey:   os.Getenv("ANTHROPIC_API_KEY"),
    },
    Alerts: sentinel.AlertConfig{
        Slack: &sentinel.SlackConfig{
            WebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
        },
    },
    IPReputation: sentinel.IPReputationConfig{
        Enabled:      os.Getenv("ABUSEIPDB_API_KEY") != "",
        AbuseIPDBKey: os.Getenv("ABUSEIPDB_API_KEY"),
    },
}`}),(0,b.jsx)(d.default,{type:"warning",title:"Never Hardcode Secrets",children:"Always use environment variables or a secrets manager for API keys, passwords, SMTP credentials, and webhook URLs. The code examples on this page use literal strings for clarity, but production deployments should never commit secrets to source control."}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF Deep Dive"})," — Advanced WAF configuration, custom rules, and tuning"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/rate-limiting",children:"Rate Limiting"})," — Strategies, per-route limits, and response headers"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," — Brute-force and credential stuffing protection"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/anomaly-detection",children:"Anomaly Detection"})," — Behavioral analysis and learning periods"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/alerting",children:"Alerting"})," — Slack, email, and webhook integration"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/ai-analysis",children:"AI Analysis"})," — Claude, OpenAI, and Gemini integration"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Explore the 13-page security dashboard"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Configuration - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_configuration_page_jsx_c73a0825._.js.map