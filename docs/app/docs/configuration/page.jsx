import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Configuration - Sentinel Docs',
  description:
    'Complete configuration reference for Sentinel. All options for WAF, rate limiting, storage, auth shield, AI, alerting, and more.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/configuration',
  },
  openGraph: {
    title: 'Configuration - Sentinel Docs',
    description:
      'Complete configuration reference for Sentinel. All options for WAF, rate limiting, storage, auth shield, AI, alerting, and more.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/configuration',
    type: 'article',
  },
};

export default function Configuration() {
  return (
    <>
      <FAQSchema
        questions={[
          {
            q: 'What is the default Sentinel configuration?',
            a: 'With an empty sentinel.Config{}, Sentinel applies sensible defaults: SQLite storage at sentinel.db, the dashboard enabled at /sentinel/ui with admin/sentinel credentials, security headers active, and performance monitoring on. WAF, rate limiting, and anomaly detection are opt-in.',
          },
          {
            q: 'What storage backends does Sentinel support?',
            a: 'Sentinel supports four storage backends: SQLite (pure Go, no CGo, recommended for most deployments), in-memory (for development and testing), PostgreSQL (for high-availability production), and MySQL/MariaDB. SQLite is the default driver.',
          },
          {
            q: 'How do I enable the WAF in Sentinel?',
            a: 'Enable the WAF by setting WAF.Enabled to true and choosing a mode. Use sentinel.ModeLog to detect and log threats without blocking, or sentinel.ModeBlock to reject malicious requests with HTTP 403. Each rule category can be tuned independently.',
          },
          {
            q: 'How do I set up AI analysis in Sentinel?',
            a: 'Configure AI by setting the AI field with a provider (sentinel.Claude, sentinel.OpenAI, or sentinel.Gemini), your API key, and optionally a model override. Enable DailySummary for automated security reports. The AI field is a pointer; leave it nil to disable.',
          },
          {
            q: 'How do I configure Sentinel alerts?',
            a: 'Set the Alerts section with a MinSeverity threshold and one or more channels: Slack (webhook URL), email (SMTP settings and recipients), or webhook (URL and custom headers). All configured channels receive alerts concurrently when the severity threshold is met.',
          },
        ]}
      />
      <TechArticleSchema
        title="Sentinel Configuration Reference"
        description="Complete configuration reference for Sentinel. All options for WAF, rate limiting, storage, auth shield, AI, alerting, and more."
        url="https://sentinel-go-sdk.vercel.app/docs/configuration"
      />
      <SpeakableSchema
        url="https://sentinel-go-sdk.vercel.app/docs/configuration"
        cssSelector={['.prose h1', '.prose h2', '.prose p']}
      />
      <h1>Configuration Reference</h1>
      <p>
        Sentinel is configured by passing a <code>sentinel.Config</code> struct to{' '}
        <code>sentinel.Mount()</code>. Every field has a sensible default, so you can start with an
        empty struct and enable features incrementally. This page documents every configuration
        section, its fields, default values, and usage patterns.
      </p>

      <Callout type="info" title="Zero-Value Friendly">
        All config fields are zero-value safe. An empty <code>sentinel.Config{'{}'}</code> gives you
        a working setup with SQLite storage, the dashboard enabled, security headers active, and
        performance monitoring on. Features like WAF, rate limiting, and anomaly detection are
        opt-in via their <code>Enabled</code> field.
      </Callout>

      <h2>Complete Example</h2>
      <p>
        Below is a fully configured Sentinel instance with every major feature enabled. In practice,
        you only need to set the fields relevant to your application.
      </p>
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
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD CONFIG                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        The <code>DashboardConfig</code> controls the embedded React security dashboard. The
        dashboard is enabled by default and served under the configured prefix. It is protected by
        JWT-based authentication using the username and password you provide.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>*bool</code></td>
            <td><code>true</code></td>
            <td>Whether the dashboard is served. Set to <code>false</code> to disable entirely.</td>
          </tr>
          <tr>
            <td><code>Prefix</code></td>
            <td><code>string</code></td>
            <td><code>/sentinel</code></td>
            <td>URL prefix for the dashboard and API routes. The UI is available at <code>{'{prefix}'}/ui</code>.</td>
          </tr>
          <tr>
            <td><code>Username</code></td>
            <td><code>string</code></td>
            <td><code>admin</code></td>
            <td>Username for dashboard login.</td>
          </tr>
          <tr>
            <td><code>Password</code></td>
            <td><code>string</code></td>
            <td><code>sentinel</code></td>
            <td>Password for dashboard login.</td>
          </tr>
          <tr>
            <td><code>SecretKey</code></td>
            <td><code>string</code></td>
            <td><code>sentinel-default-secret-change-me</code></td>
            <td>Secret key used to sign JWT tokens for dashboard sessions.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`Dashboard: sentinel.DashboardConfig{
    Prefix:    "/admin/security",
    Username:  "secops",
    Password:  "change-me-in-production",
    SecretKey: "a-strong-random-secret",
}`}
      />

      <Callout type="warning" title="Change Default Credentials">
        The default username/password (<code>admin</code>/<code>sentinel</code>) and secret key are
        intended for development only. Always set strong values in production. The{' '}
        <code>SecretKey</code> is used to sign JWT tokens — if it is compromised, attackers can forge
        dashboard sessions.
      </Callout>

      <Callout type="info" title="Disabling the Dashboard">
        To run Sentinel as a headless middleware without any dashboard routes, set{' '}
        <code>Enabled</code> to <code>false</code>. Because the field is a <code>*bool</code>, you
        need to use a pointer:
        <CodeBlock
          language="go"
          showLineNumbers={false}
          code={`disabled := false
Dashboard: sentinel.DashboardConfig{
    Enabled: &disabled,
}`}
        />
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  STORAGE CONFIG                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="storage">Storage</h2>
      <p>
        The <code>StorageConfig</code> controls how Sentinel persists security events, threat actors,
        rate limit counters, and other data. Sentinel ships with two built-in storage drivers and
        supports additional drivers.
      </p>

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
            <td><code>Driver</code></td>
            <td><code>StorageDriver</code></td>
            <td><code>sentinel.SQLite</code></td>
            <td>Storage backend. Options: <code>sentinel.SQLite</code>, <code>sentinel.Memory</code>, <code>sentinel.Postgres</code>, <code>sentinel.MySQL</code>.</td>
          </tr>
          <tr>
            <td><code>DSN</code></td>
            <td><code>string</code></td>
            <td><code>sentinel.db</code></td>
            <td>Data source name. For SQLite, this is a file path. For Postgres/MySQL, a full connection string.</td>
          </tr>
          <tr>
            <td><code>RetentionDays</code></td>
            <td><code>int</code></td>
            <td><code>90</code></td>
            <td>Number of days to retain security events before automatic cleanup.</td>
          </tr>
          <tr>
            <td><code>MaxOpenConns</code></td>
            <td><code>int</code></td>
            <td><code>10</code></td>
            <td>Maximum number of open database connections.</td>
          </tr>
          <tr>
            <td><code>MaxIdleConns</code></td>
            <td><code>int</code></td>
            <td><code>5</code></td>
            <td>Maximum number of idle database connections.</td>
          </tr>
        </tbody>
      </table>

      <h3>Storage Drivers</h3>
      <table>
        <thead>
          <tr>
            <th>Driver</th>
            <th>Constant</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>SQLite</td>
            <td><code>sentinel.SQLite</code></td>
            <td>Pure Go (no CGo). Recommended for most deployments. Data persists to a file.</td>
          </tr>
          <tr>
            <td>Memory</td>
            <td><code>sentinel.Memory</code></td>
            <td>In-memory store. No persistence — data is lost on restart. Useful for testing.</td>
          </tr>
          <tr>
            <td>Postgres</td>
            <td><code>sentinel.Postgres</code></td>
            <td>PostgreSQL backend for high-availability production deployments.</td>
          </tr>
          <tr>
            <td>MySQL</td>
            <td><code>sentinel.MySQL</code></td>
            <td>MySQL/MariaDB backend.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`// SQLite (default, recommended)
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
}`}
      />

      <Callout type="info" title="No CGo Required">
        The SQLite driver uses a pure-Go implementation (<code>github.com/glebarez/sqlite</code>), so
        you do not need CGo or any C compiler installed. This makes cross-compilation and Docker
        builds straightforward.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  WAF CONFIG                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="waf">WAF (Web Application Firewall)</h2>
      <p>
        The <code>WAFConfig</code> controls the built-in Web Application Firewall. When enabled, it
        inspects incoming requests for SQL injection, XSS, path traversal, command injection, SSRF,
        XXE, LFI, and open redirect attacks. It can operate in log-only mode (observe without
        blocking) or block mode (reject malicious requests with a 403 status).
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Enables the WAF middleware. Must be set to <code>true</code> to activate.</td>
          </tr>
          <tr>
            <td><code>Mode</code></td>
            <td><code>WAFMode</code></td>
            <td><code>sentinel.ModeLog</code></td>
            <td>How detected threats are handled. Options: <code>sentinel.ModeLog</code>, <code>sentinel.ModeBlock</code>, <code>sentinel.ModeChallenge</code>.</td>
          </tr>
          <tr>
            <td><code>Rules</code></td>
            <td><code>RuleSet</code></td>
            <td>All <code>RuleStrict</code></td>
            <td>Per-category sensitivity levels for built-in detection rules.</td>
          </tr>
          <tr>
            <td><code>CustomRules</code></td>
            <td><code>[]WAFRule</code></td>
            <td><code>nil</code></td>
            <td>Custom regex-based rules for application-specific patterns.</td>
          </tr>
          <tr>
            <td><code>ExcludeRoutes</code></td>
            <td><code>[]string</code></td>
            <td><code>nil</code></td>
            <td>Routes to exclude from WAF inspection (e.g., health check endpoints).</td>
          </tr>
          <tr>
            <td><code>ExcludeIPs</code></td>
            <td><code>[]string</code></td>
            <td><code>nil</code></td>
            <td>IP addresses or CIDR ranges to exclude from WAF inspection.</td>
          </tr>
        </tbody>
      </table>

      <h3>WAF Modes</h3>
      <table>
        <thead>
          <tr>
            <th>Mode</th>
            <th>Constant</th>
            <th>Behavior</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Log</td>
            <td><code>sentinel.ModeLog</code></td>
            <td>Detects and logs threats but allows the request to proceed. Good for initial rollout.</td>
          </tr>
          <tr>
            <td>Block</td>
            <td><code>sentinel.ModeBlock</code></td>
            <td>Detects threats and rejects the request with HTTP 403. Recommended for production.</td>
          </tr>
          <tr>
            <td>Challenge</td>
            <td><code>sentinel.ModeChallenge</code></td>
            <td>Presents a challenge to the client before allowing the request through.</td>
          </tr>
        </tbody>
      </table>

      <h3>RuleSet — Per-Category Sensitivity</h3>
      <p>
        Each built-in detection category can have its sensitivity tuned independently. The available
        levels are <code>sentinel.RuleOff</code>, <code>sentinel.RuleLow</code>,{' '}
        <code>sentinel.RuleMedium</code>, and <code>sentinel.RuleStrict</code>.
      </p>

      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>SQLInjection</code></td>
            <td><code>RuleStrict</code></td>
            <td>SQL injection detection sensitivity.</td>
          </tr>
          <tr>
            <td><code>XSS</code></td>
            <td><code>RuleStrict</code></td>
            <td>Cross-site scripting detection sensitivity.</td>
          </tr>
          <tr>
            <td><code>PathTraversal</code></td>
            <td><code>RuleStrict</code></td>
            <td>Path traversal (<code>../../etc/passwd</code>) detection sensitivity.</td>
          </tr>
          <tr>
            <td><code>CommandInjection</code></td>
            <td><code>RuleStrict</code></td>
            <td>OS command injection detection sensitivity.</td>
          </tr>
          <tr>
            <td><code>SSRF</code></td>
            <td><code>RuleMedium</code></td>
            <td>Server-side request forgery detection sensitivity.</td>
          </tr>
          <tr>
            <td><code>XXE</code></td>
            <td><code>RuleStrict</code></td>
            <td>XML external entity injection detection sensitivity.</td>
          </tr>
          <tr>
            <td><code>LFI</code></td>
            <td><code>RuleStrict</code></td>
            <td>Local file inclusion detection sensitivity.</td>
          </tr>
          <tr>
            <td><code>OpenRedirect</code></td>
            <td><code>RuleMedium</code></td>
            <td>Open redirect detection sensitivity.</td>
          </tr>
        </tbody>
      </table>

      <h3>Custom WAF Rules</h3>
      <p>
        Custom rules let you add application-specific detection patterns using regular expressions.
        Each rule is defined as a <code>WAFRule</code> struct.
      </p>

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
            <td>Unique identifier for the rule.</td>
          </tr>
          <tr>
            <td><code>Name</code></td>
            <td><code>string</code></td>
            <td>Human-readable name displayed in the dashboard.</td>
          </tr>
          <tr>
            <td><code>Pattern</code></td>
            <td><code>string</code></td>
            <td>Go-compatible regular expression to match against request data.</td>
          </tr>
          <tr>
            <td><code>AppliesTo</code></td>
            <td><code>[]string</code></td>
            <td>Which parts of the request to inspect: <code>"path"</code>, <code>"query"</code>, <code>"body"</code>, <code>"headers"</code>.</td>
          </tr>
          <tr>
            <td><code>Severity</code></td>
            <td><code>Severity</code></td>
            <td>Severity level: <code>sentinel.SeverityLow</code>, <code>SeverityMedium</code>, <code>SeverityHigh</code>, <code>SeverityCritical</code>.</td>
          </tr>
          <tr>
            <td><code>Action</code></td>
            <td><code>string</code></td>
            <td>Action to take: <code>"block"</code> or <code>"log"</code>.</td>
          </tr>
          <tr>
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td>Whether the rule is active.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`WAF: sentinel.WAFConfig{
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
}`}
      />

      <Callout type="success" title="Recommended Rollout Strategy">
        Start with <code>sentinel.ModeLog</code> in production to observe what the WAF detects
        without blocking real traffic. Review the dashboard for false positives, tune rule
        sensitivities, then switch to <code>sentinel.ModeBlock</code> when confident.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  RATE LIMIT CONFIG                                                  */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="rate-limiting">Rate Limiting</h2>
      <p>
        The <code>RateLimitConfig</code> enables multi-dimensional rate limiting. You can set limits
        per IP, per authenticated user, per route, and globally. All dimensions are enforced
        independently — a request must pass all applicable limits.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Enables the rate limiting middleware.</td>
          </tr>
          <tr>
            <td><code>Strategy</code></td>
            <td><code>RateLimitStrategy</code></td>
            <td><code>sentinel.SlidingWindow</code></td>
            <td>Algorithm used for counting. Options: <code>sentinel.SlidingWindow</code>, <code>sentinel.FixedWindow</code>, <code>sentinel.TokenBucket</code>.</td>
          </tr>
          <tr>
            <td><code>ByIP</code></td>
            <td><code>*Limit</code></td>
            <td><code>nil</code></td>
            <td>Per-IP rate limit. Each unique client IP gets its own counter.</td>
          </tr>
          <tr>
            <td><code>ByUser</code></td>
            <td><code>*Limit</code></td>
            <td><code>nil</code></td>
            <td>Per-user rate limit. Requires a <code>UserIDExtractor</code> or <code>UserExtractor</code>.</td>
          </tr>
          <tr>
            <td><code>ByRoute</code></td>
            <td><code>map[string]Limit</code></td>
            <td><code>nil</code></td>
            <td>Per-route rate limits. Keys are route patterns (e.g., <code>/api/login</code>).</td>
          </tr>
          <tr>
            <td><code>Global</code></td>
            <td><code>*Limit</code></td>
            <td><code>nil</code></td>
            <td>Global rate limit applied across all requests regardless of source.</td>
          </tr>
          <tr>
            <td><code>UserIDExtractor</code></td>
            <td><code>func(*gin.Context) string</code></td>
            <td><code>nil</code></td>
            <td>Function to extract a user ID from the request for per-user limiting.</td>
          </tr>
        </tbody>
      </table>

      <h3>The Limit Struct</h3>
      <p>
        Each limit is defined by a number of allowed requests within a time window.
      </p>

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
            <td><code>Requests</code></td>
            <td><code>int</code></td>
            <td>Maximum number of requests allowed within the window.</td>
          </tr>
          <tr>
            <td><code>Window</code></td>
            <td><code>time.Duration</code></td>
            <td>Time window for the limit (e.g., <code>time.Minute</code>, <code>15 * time.Minute</code>).</td>
          </tr>
        </tbody>
      </table>

      <h3>Rate Limit Strategies</h3>
      <table>
        <thead>
          <tr>
            <th>Strategy</th>
            <th>Constant</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Sliding Window</td>
            <td><code>sentinel.SlidingWindow</code></td>
            <td>Default. Provides smooth rate limiting without burst spikes at window boundaries.</td>
          </tr>
          <tr>
            <td>Fixed Window</td>
            <td><code>sentinel.FixedWindow</code></td>
            <td>Simple fixed time windows. Slightly less accurate but lower memory overhead.</td>
          </tr>
          <tr>
            <td>Token Bucket</td>
            <td><code>sentinel.TokenBucket</code></td>
            <td>Allows short bursts while maintaining an average rate over time.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`RateLimit: sentinel.RateLimitConfig{
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
}`}
      />

      <Callout type="info" title="Rate Limit Headers">
        When rate limiting is active, Sentinel automatically sets standard rate limit headers on
        every response: <code>X-RateLimit-Limit</code>, <code>X-RateLimit-Remaining</code>, and{' '}
        <code>X-RateLimit-Reset</code>. When a limit is exceeded, the client receives a{' '}
        <code>429 Too Many Requests</code> response.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  AUTH SHIELD CONFIG                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="auth-shield">Auth Shield</h2>
      <p>
        The <code>AuthShieldConfig</code> protects authentication endpoints from brute-force attacks
        and credential stuffing. When enabled, it monitors the configured login route for failed
        authentication attempts and automatically locks out offending IPs.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Enables the Auth Shield middleware.</td>
          </tr>
          <tr>
            <td><code>LoginRoute</code></td>
            <td><code>string</code></td>
            <td><code>""</code></td>
            <td>The route path for your login endpoint (e.g., <code>/api/login</code>).</td>
          </tr>
          <tr>
            <td><code>MaxFailedAttempts</code></td>
            <td><code>int</code></td>
            <td><code>5</code></td>
            <td>Number of failed login attempts before lockout is triggered.</td>
          </tr>
          <tr>
            <td><code>LockoutDuration</code></td>
            <td><code>time.Duration</code></td>
            <td><code>15 * time.Minute</code></td>
            <td>How long an IP is locked out after exceeding <code>MaxFailedAttempts</code>.</td>
          </tr>
          <tr>
            <td><code>CredentialStuffingDetection</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Detects credential stuffing patterns (many different usernames from the same IP).</td>
          </tr>
          <tr>
            <td><code>BruteForceDetection</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Detects brute force patterns (many password attempts for the same username).</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`AuthShield: sentinel.AuthShieldConfig{
    Enabled:                    true,
    LoginRoute:                 "/api/login",
    MaxFailedAttempts:          5,
    LockoutDuration:            15 * time.Minute,
    CredentialStuffingDetection: true,
    BruteForceDetection:        true,
}`}
      />

      <Callout type="warning" title="LoginRoute Must Match Exactly">
        The <code>LoginRoute</code> must match the exact path of your login handler. Sentinel
        monitors this route for non-2xx responses to count failed login attempts. If the route does
        not match, Auth Shield will not detect failures.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  HEADERS CONFIG                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="headers">Security Headers</h2>
      <p>
        The <code>HeaderConfig</code> controls automatic injection of security headers into every
        response. Security headers are enabled by default. These headers protect against clickjacking,
        MIME sniffing, XSS, and other client-side attacks.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>*bool</code></td>
            <td><code>true</code></td>
            <td>Whether security headers are injected. Use a <code>*bool</code> to explicitly disable.</td>
          </tr>
          <tr>
            <td><code>ContentSecurityPolicy</code></td>
            <td><code>string</code></td>
            <td><code>""</code> (not set)</td>
            <td>Value for the <code>Content-Security-Policy</code> header. Left empty by default because CSP is application-specific.</td>
          </tr>
          <tr>
            <td><code>StrictTransportSecurity</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>When <code>true</code>, sets <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code>.</td>
          </tr>
          <tr>
            <td><code>XFrameOptions</code></td>
            <td><code>string</code></td>
            <td><code>DENY</code></td>
            <td>Value for the <code>X-Frame-Options</code> header. Common values: <code>DENY</code>, <code>SAMEORIGIN</code>.</td>
          </tr>
          <tr>
            <td><code>XContentTypeOptions</code></td>
            <td><code>bool</code></td>
            <td><code>true</code></td>
            <td>When <code>true</code>, sets <code>X-Content-Type-Options: nosniff</code>.</td>
          </tr>
          <tr>
            <td><code>ReferrerPolicy</code></td>
            <td><code>string</code></td>
            <td><code>strict-origin-when-cross-origin</code></td>
            <td>Value for the <code>Referrer-Policy</code> header.</td>
          </tr>
          <tr>
            <td><code>PermissionsPolicy</code></td>
            <td><code>string</code></td>
            <td><code>""</code> (not set)</td>
            <td>Value for the <code>Permissions-Policy</code> header. Controls browser feature access.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`Headers: sentinel.HeaderConfig{
    ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline'",
    StrictTransportSecurity: true,
    XFrameOptions:           "DENY",
    XContentTypeOptions:     true,
    ReferrerPolicy:          "strict-origin-when-cross-origin",
    PermissionsPolicy:       "camera=(), microphone=(), geolocation=()",
}`}
      />

      <Callout type="info" title="HSTS Warning">
        Only enable <code>StrictTransportSecurity</code> if your application is served exclusively
        over HTTPS. Once a browser receives an HSTS header, it will refuse to connect over plain
        HTTP for the specified duration.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  ANOMALY CONFIG                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="anomaly">Anomaly Detection</h2>
      <p>
        The <code>AnomalyConfig</code> enables behavioral anomaly detection. Sentinel learns normal
        traffic patterns during a configurable learning period and then flags deviations such as
        impossible travel, unusual access patterns, and data exfiltration attempts.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Enables the anomaly detection engine.</td>
          </tr>
          <tr>
            <td><code>Sensitivity</code></td>
            <td><code>AnomalySensitivity</code></td>
            <td><code>sentinel.AnomalySensitivityMedium</code></td>
            <td>Detection sensitivity. Options: <code>sentinel.AnomalySensitivityLow</code>, <code>AnomalySensitivityMedium</code>, <code>AnomalySensitivityHigh</code>.</td>
          </tr>
          <tr>
            <td><code>LearningPeriod</code></td>
            <td><code>time.Duration</code></td>
            <td><code>7 * 24 * time.Hour</code> (7 days)</td>
            <td>Duration of the initial learning phase during which Sentinel builds baseline traffic patterns.</td>
          </tr>
          <tr>
            <td><code>Checks</code></td>
            <td><code>[]AnomalyCheckType</code></td>
            <td><code>nil</code> (all checks)</td>
            <td>Which anomaly checks to run. When <code>nil</code>, all checks are enabled.</td>
          </tr>
        </tbody>
      </table>

      <h3>Anomaly Check Types</h3>
      <table>
        <thead>
          <tr>
            <th>Check</th>
            <th>Constant</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Impossible Travel</td>
            <td><code>sentinel.CheckImpossibleTravel</code></td>
            <td>Detects logins from geographically distant locations within impossibly short timeframes.</td>
          </tr>
          <tr>
            <td>Unusual Access</td>
            <td><code>sentinel.CheckUnusualAccess</code></td>
            <td>Flags access to endpoints not typically visited by a given user or IP.</td>
          </tr>
          <tr>
            <td>Data Exfiltration</td>
            <td><code>sentinel.CheckDataExfiltration</code></td>
            <td>Detects abnormally large data transfers or rapid sequential data access.</td>
          </tr>
          <tr>
            <td>Off-Hours Access</td>
            <td><code>sentinel.CheckOffHoursAccess</code></td>
            <td>Flags access outside of normal business hours for a given user profile.</td>
          </tr>
          <tr>
            <td>Velocity Anomaly</td>
            <td><code>sentinel.CheckVelocityAnomaly</code></td>
            <td>Detects sudden spikes in request velocity from a single source.</td>
          </tr>
          <tr>
            <td>Credential Stuffing</td>
            <td><code>sentinel.CheckCredentialStuffing</code></td>
            <td>Identifies patterns consistent with credential stuffing attacks on auth endpoints.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`Anomaly: sentinel.AnomalyConfig{
    Enabled:        true,
    Sensitivity:    sentinel.AnomalySensitivityMedium,
    LearningPeriod: 7 * 24 * time.Hour,
    Checks: []sentinel.AnomalyCheckType{
        sentinel.CheckImpossibleTravel,
        sentinel.CheckUnusualAccess,
        sentinel.CheckDataExfiltration,
        sentinel.CheckVelocityAnomaly,
    },
}`}
      />

      <Callout type="info" title="Learning Period">
        During the learning period, Sentinel collects baseline data but does not flag anomalies.
        After the learning period expires, detections begin automatically. A shorter learning
        period may produce more false positives; a longer period provides more accurate baselines.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  IP REPUTATION CONFIG                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="ip-reputation">IP Reputation</h2>
      <p>
        The <code>IPReputationConfig</code> integrates with the AbuseIPDB API to check the
        reputation score of incoming IP addresses. Known malicious IPs can be automatically blocked.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Enables IP reputation checking.</td>
          </tr>
          <tr>
            <td><code>AbuseIPDBKey</code></td>
            <td><code>string</code></td>
            <td><code>""</code></td>
            <td>Your AbuseIPDB API key. Required when <code>Enabled</code> is <code>true</code>.</td>
          </tr>
          <tr>
            <td><code>AutoBlock</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Automatically add IPs exceeding <code>MinAbuseScore</code> to the blocklist.</td>
          </tr>
          <tr>
            <td><code>MinAbuseScore</code></td>
            <td><code>int</code></td>
            <td><code>80</code></td>
            <td>Minimum AbuseIPDB confidence score (0-100) to consider an IP malicious.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`IPReputation: sentinel.IPReputationConfig{
    Enabled:       true,
    AbuseIPDBKey:  os.Getenv("ABUSEIPDB_API_KEY"),
    AutoBlock:     true,
    MinAbuseScore: 80,
}`}
      />

      <Callout type="warning" title="API Rate Limits">
        AbuseIPDB has rate limits on their free plan. Sentinel caches reputation lookups to minimize
        API calls, but high-traffic applications should consider a paid AbuseIPDB plan or adjust the{' '}
        <code>MinAbuseScore</code> threshold.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  GEO CONFIG                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="geo">Geolocation</h2>
      <p>
        The <code>GeoConfig</code> enables IP geolocation for enriching security events with
        country, city, and coordinate data. This powers the dashboard map view and the impossible
        travel anomaly check.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Enables IP geolocation lookups.</td>
          </tr>
          <tr>
            <td><code>Provider</code></td>
            <td><code>GeoProvider</code></td>
            <td><code>sentinel.GeoIPFree</code></td>
            <td>Geolocation provider. Options: <code>sentinel.GeoIPFree</code> (GeoLite2), <code>sentinel.GeoIPPaid</code> (GeoIP2).</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`Geo: sentinel.GeoConfig{
    Enabled:  true,
    Provider: sentinel.GeoIPFree,
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  ALERTS CONFIG                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="alerts">Alerts</h2>
      <p>
        The <code>AlertConfig</code> configures real-time alerting when security events exceed a
        severity threshold. Sentinel supports three alert channels: Slack, email, and generic
        webhooks. You can enable one or more channels simultaneously.
      </p>

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
            <td><code>MinSeverity</code></td>
            <td><code>Severity</code></td>
            <td><code>sentinel.SeverityHigh</code></td>
            <td>Minimum severity level to trigger alerts. Options: <code>SeverityLow</code>, <code>SeverityMedium</code>, <code>SeverityHigh</code>, <code>SeverityCritical</code>.</td>
          </tr>
          <tr>
            <td><code>Slack</code></td>
            <td><code>*SlackConfig</code></td>
            <td><code>nil</code></td>
            <td>Slack webhook configuration. Set to enable Slack alerts.</td>
          </tr>
          <tr>
            <td><code>Email</code></td>
            <td><code>*EmailConfig</code></td>
            <td><code>nil</code></td>
            <td>Email SMTP configuration. Set to enable email alerts.</td>
          </tr>
          <tr>
            <td><code>Webhook</code></td>
            <td><code>*WebhookConfig</code></td>
            <td><code>nil</code></td>
            <td>Generic webhook configuration. Set to enable webhook alerts.</td>
          </tr>
        </tbody>
      </table>

      <h3>Slack Alerts</h3>
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
            <td><code>WebhookURL</code></td>
            <td><code>string</code></td>
            <td>The Slack incoming webhook URL.</td>
          </tr>
        </tbody>
      </table>

      <h3>Email Alerts</h3>
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
            <td><code>SMTPHost</code></td>
            <td><code>string</code></td>
            <td>SMTP server hostname.</td>
          </tr>
          <tr>
            <td><code>SMTPPort</code></td>
            <td><code>int</code></td>
            <td>SMTP server port (typically 587 for TLS, 465 for SSL).</td>
          </tr>
          <tr>
            <td><code>Username</code></td>
            <td><code>string</code></td>
            <td>SMTP authentication username.</td>
          </tr>
          <tr>
            <td><code>Password</code></td>
            <td><code>string</code></td>
            <td>SMTP authentication password.</td>
          </tr>
          <tr>
            <td><code>Recipients</code></td>
            <td><code>[]string</code></td>
            <td>List of email addresses to receive alerts.</td>
          </tr>
        </tbody>
      </table>

      <h3>Webhook Alerts</h3>
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
            <td><code>URL</code></td>
            <td><code>string</code></td>
            <td>The webhook endpoint URL. Sentinel sends a JSON POST request.</td>
          </tr>
          <tr>
            <td><code>Headers</code></td>
            <td><code>map[string]string</code></td>
            <td>Custom HTTP headers to include in webhook requests (e.g., for authentication).</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`Alerts: sentinel.AlertConfig{
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
}`}
      />

      <Callout type="info" title="Multiple Alert Channels">
        You can enable any combination of Slack, email, and webhook alerts. When an event exceeds the{' '}
        <code>MinSeverity</code> threshold, it is dispatched to all configured channels concurrently.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  AI CONFIG                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="ai">AI Analysis</h2>
      <p>
        The <code>AIConfig</code> enables AI-powered security analysis. When configured, Sentinel
        uses large language models to analyze threat patterns, generate daily security summaries,
        and provide natural-language insights in the dashboard. This is an optional feature — it
        requires an API key from one of the supported providers.
      </p>

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
            <td><code>Provider</code></td>
            <td><code>AIProvider</code></td>
            <td>(none)</td>
            <td>AI provider. Options: <code>sentinel.Claude</code>, <code>sentinel.OpenAI</code>, <code>sentinel.Gemini</code>.</td>
          </tr>
          <tr>
            <td><code>APIKey</code></td>
            <td><code>string</code></td>
            <td><code>""</code></td>
            <td>API key for the selected provider.</td>
          </tr>
          <tr>
            <td><code>Model</code></td>
            <td><code>string</code></td>
            <td>(provider default)</td>
            <td>Optional model override. If empty, Sentinel uses the provider's recommended model.</td>
          </tr>
          <tr>
            <td><code>DailySummary</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>When <code>true</code>, generates a daily AI-powered security summary.</td>
          </tr>
        </tbody>
      </table>

      <h3>Supported Providers</h3>
      <table>
        <thead>
          <tr>
            <th>Provider</th>
            <th>Constant</th>
            <th>Default Model</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Anthropic Claude</td>
            <td><code>sentinel.Claude</code></td>
            <td>Claude Sonnet</td>
          </tr>
          <tr>
            <td>OpenAI</td>
            <td><code>sentinel.OpenAI</code></td>
            <td>GPT-4o</td>
          </tr>
          <tr>
            <td>Google Gemini</td>
            <td><code>sentinel.Gemini</code></td>
            <td>Gemini Pro</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`// Using Anthropic Claude
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
}`}
      />

      <Callout type="info" title="AI is Optional">
        The <code>AI</code> field is a pointer (<code>*AIConfig</code>). When left as <code>nil</code>,
        no AI provider is initialized and no API calls are made. The dashboard AI analysis tab will
        show a message indicating that AI is not configured.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  USER EXTRACTOR                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="user-extractor">User Extractor</h2>
      <p>
        The <code>UserExtractor</code> is a function that extracts authenticated user context from
        each incoming request. Sentinel uses this information for per-user rate limiting, user-level
        threat profiling, and audit logging. Return <code>nil</code> for unauthenticated requests.
      </p>

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
            <td><code>UserExtractor</code></td>
            <td><code>func(*gin.Context) *UserContext</code></td>
            <td><code>nil</code></td>
            <td>Function to extract user information from a request. Return <code>nil</code> if no user is authenticated.</td>
          </tr>
        </tbody>
      </table>

      <h3>UserContext Struct</h3>
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
            <td>Unique user identifier.</td>
          </tr>
          <tr>
            <td><code>Email</code></td>
            <td><code>string</code></td>
            <td>User email address (used in alerts and dashboard display).</td>
          </tr>
          <tr>
            <td><code>Role</code></td>
            <td><code>string</code></td>
            <td>User role (e.g., <code>"admin"</code>, <code>"user"</code>). Used for access pattern analysis.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`// Extract user from JWT claims set by your auth middleware
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
}`}
      />

      <Callout type="info" title="UserExtractor vs UserIDExtractor">
        <code>Config.UserExtractor</code> provides full user context (ID, email, role) for threat
        profiling and dashboard display. <code>RateLimitConfig.UserIDExtractor</code> is a simpler
        function that returns only a user ID string for rate limiting. If you set{' '}
        <code>UserExtractor</code>, Sentinel can derive the user ID from it automatically. You only
        need <code>UserIDExtractor</code> if you want rate limiting to use a different identifier.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  PERFORMANCE CONFIG                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="performance">Performance Monitoring</h2>
      <p>
        The <code>PerformanceConfig</code> controls request performance tracking and system resource
        monitoring. Performance monitoring is enabled by default. Sentinel records request durations,
        flags slow requests, and optionally tracks memory usage and goroutine counts.
      </p>

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
            <td><code>Enabled</code></td>
            <td><code>*bool</code></td>
            <td><code>true</code></td>
            <td>Whether performance monitoring is active. Use a <code>*bool</code> to explicitly disable.</td>
          </tr>
          <tr>
            <td><code>SlowRequestThreshold</code></td>
            <td><code>time.Duration</code></td>
            <td><code>2 * time.Second</code></td>
            <td>Requests exceeding this duration are flagged as slow in the dashboard.</td>
          </tr>
          <tr>
            <td><code>SlowQueryThreshold</code></td>
            <td><code>time.Duration</code></td>
            <td><code>500 * time.Millisecond</code></td>
            <td>Database queries exceeding this duration are flagged as slow (used with the GORM plugin).</td>
          </tr>
          <tr>
            <td><code>TrackMemory</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Track Go runtime memory statistics and expose them in the dashboard.</td>
          </tr>
          <tr>
            <td><code>TrackGoroutines</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Track the number of active goroutines and expose in the dashboard.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`Performance: sentinel.PerformanceConfig{
    SlowRequestThreshold: 1 * time.Second,
    SlowQueryThreshold:   200 * time.Millisecond,
    TrackMemory:          true,
    TrackGoroutines:      true,
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DEFAULTS                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="defaults">Defaults (Zero Config)</h2>
      <p>
        When you pass an empty <code>sentinel.Config{'{}'}</code>, Sentinel applies the following
        defaults via the <code>ApplyDefaults()</code> method. This table summarizes the effective
        configuration with zero user-provided values.
      </p>

      <table>
        <thead>
          <tr>
            <th>Section</th>
            <th>Field</th>
            <th>Default Value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Dashboard</td>
            <td><code>Enabled</code></td>
            <td><code>true</code></td>
          </tr>
          <tr>
            <td>Dashboard</td>
            <td><code>Prefix</code></td>
            <td><code>/sentinel</code></td>
          </tr>
          <tr>
            <td>Dashboard</td>
            <td><code>Username</code></td>
            <td><code>admin</code></td>
          </tr>
          <tr>
            <td>Dashboard</td>
            <td><code>Password</code></td>
            <td><code>sentinel</code></td>
          </tr>
          <tr>
            <td>Dashboard</td>
            <td><code>SecretKey</code></td>
            <td><code>sentinel-default-secret-change-me</code></td>
          </tr>
          <tr>
            <td>Storage</td>
            <td><code>Driver</code></td>
            <td><code>sentinel.SQLite</code></td>
          </tr>
          <tr>
            <td>Storage</td>
            <td><code>DSN</code></td>
            <td><code>sentinel.db</code></td>
          </tr>
          <tr>
            <td>Storage</td>
            <td><code>RetentionDays</code></td>
            <td><code>90</code></td>
          </tr>
          <tr>
            <td>Storage</td>
            <td><code>MaxOpenConns</code></td>
            <td><code>10</code></td>
          </tr>
          <tr>
            <td>Storage</td>
            <td><code>MaxIdleConns</code></td>
            <td><code>5</code></td>
          </tr>
          <tr>
            <td>WAF</td>
            <td><code>Enabled</code></td>
            <td><code>false</code></td>
          </tr>
          <tr>
            <td>WAF</td>
            <td><code>Mode</code></td>
            <td><code>sentinel.ModeLog</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>SQLInjection</code></td>
            <td><code>sentinel.RuleStrict</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>XSS</code></td>
            <td><code>sentinel.RuleStrict</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>PathTraversal</code></td>
            <td><code>sentinel.RuleStrict</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>CommandInjection</code></td>
            <td><code>sentinel.RuleStrict</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>SSRF</code></td>
            <td><code>sentinel.RuleMedium</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>XXE</code></td>
            <td><code>sentinel.RuleStrict</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>LFI</code></td>
            <td><code>sentinel.RuleStrict</code></td>
          </tr>
          <tr>
            <td>WAF Rules</td>
            <td><code>OpenRedirect</code></td>
            <td><code>sentinel.RuleMedium</code></td>
          </tr>
          <tr>
            <td>Rate Limit</td>
            <td><code>Enabled</code></td>
            <td><code>false</code></td>
          </tr>
          <tr>
            <td>Rate Limit</td>
            <td><code>Strategy</code></td>
            <td><code>sentinel.SlidingWindow</code></td>
          </tr>
          <tr>
            <td>Auth Shield</td>
            <td><code>Enabled</code></td>
            <td><code>false</code></td>
          </tr>
          <tr>
            <td>Auth Shield</td>
            <td><code>MaxFailedAttempts</code></td>
            <td><code>5</code></td>
          </tr>
          <tr>
            <td>Auth Shield</td>
            <td><code>LockoutDuration</code></td>
            <td><code>15 * time.Minute</code></td>
          </tr>
          <tr>
            <td>Headers</td>
            <td><code>Enabled</code></td>
            <td><code>true</code></td>
          </tr>
          <tr>
            <td>Headers</td>
            <td><code>XFrameOptions</code></td>
            <td><code>DENY</code></td>
          </tr>
          <tr>
            <td>Headers</td>
            <td><code>XContentTypeOptions</code></td>
            <td><code>true</code> (nosniff)</td>
          </tr>
          <tr>
            <td>Headers</td>
            <td><code>ReferrerPolicy</code></td>
            <td><code>strict-origin-when-cross-origin</code></td>
          </tr>
          <tr>
            <td>Anomaly</td>
            <td><code>Enabled</code></td>
            <td><code>false</code></td>
          </tr>
          <tr>
            <td>Anomaly</td>
            <td><code>Sensitivity</code></td>
            <td><code>sentinel.AnomalySensitivityMedium</code></td>
          </tr>
          <tr>
            <td>Anomaly</td>
            <td><code>LearningPeriod</code></td>
            <td><code>7 * 24 * time.Hour</code></td>
          </tr>
          <tr>
            <td>IP Reputation</td>
            <td><code>Enabled</code></td>
            <td><code>false</code></td>
          </tr>
          <tr>
            <td>IP Reputation</td>
            <td><code>MinAbuseScore</code></td>
            <td><code>80</code></td>
          </tr>
          <tr>
            <td>Geo</td>
            <td><code>Enabled</code></td>
            <td><code>false</code></td>
          </tr>
          <tr>
            <td>Geo</td>
            <td><code>Provider</code></td>
            <td><code>sentinel.GeoIPFree</code></td>
          </tr>
          <tr>
            <td>Alerts</td>
            <td><code>MinSeverity</code></td>
            <td><code>sentinel.SeverityHigh</code></td>
          </tr>
          <tr>
            <td>AI</td>
            <td>(entire section)</td>
            <td><code>nil</code> (disabled)</td>
          </tr>
          <tr>
            <td>Performance</td>
            <td><code>Enabled</code></td>
            <td><code>true</code></td>
          </tr>
          <tr>
            <td>Performance</td>
            <td><code>SlowRequestThreshold</code></td>
            <td><code>2 * time.Second</code></td>
          </tr>
          <tr>
            <td>Performance</td>
            <td><code>SlowQueryThreshold</code></td>
            <td><code>500 * time.Millisecond</code></td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`// Zero config — all defaults applied automatically
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
})`}
      />

      <Callout type="success" title="Production Checklist">
        Before deploying to production, make sure to:
        <ul>
          <li>Change the dashboard <code>Username</code>, <code>Password</code>, and <code>SecretKey</code></li>
          <li>Enable the WAF with <code>ModeBlock</code></li>
          <li>Set up rate limiting with appropriate thresholds for your traffic</li>
          <li>Configure at least one alert channel (Slack, email, or webhook)</li>
          <li>Use <code>sentinel.SQLite</code> or <code>sentinel.Postgres</code> for persistent storage</li>
          <li>Set <code>StrictTransportSecurity: true</code> if serving over HTTPS</li>
        </ul>
      </Callout>

      <h2>Environment Variables Pattern</h2>
      <p>
        While Sentinel does not read environment variables directly, a common pattern is to read
        them yourself and pass them into the config struct. This keeps secrets out of your source
        code.
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`import "os"

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
}`}
      />

      <Callout type="warning" title="Never Hardcode Secrets">
        Always use environment variables or a secrets manager for API keys, passwords, SMTP
        credentials, and webhook URLs. The code examples on this page use literal strings for
        clarity, but production deployments should never commit secrets to source control.
      </Callout>

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/waf">WAF Deep Dive</a> — Advanced WAF configuration, custom rules, and tuning</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> — Strategies, per-route limits, and response headers</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> — Brute-force and credential stuffing protection</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Behavioral analysis and learning periods</li>
        <li><a href="/docs/alerting">Alerting</a> — Slack, email, and webhook integration</li>
        <li><a href="/docs/ai-analysis">AI Analysis</a> — Claude, OpenAI, and Gemini integration</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the 13-page security dashboard</li>
      </ul>
    </>
  );
}
