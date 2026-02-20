import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = { title: 'Alerting - Sentinel Docs' };

export default function Alerting() {
  return (
    <>
      <h1>Alerting</h1>
      <p>
        Sentinel includes a built-in alerting system that sends real-time notifications when
        security events occur. Alerts are dispatched to one or more providers — Slack, email, or a
        custom webhook — whenever a threat event meets or exceeds your configured severity threshold.
        This lets your security team respond immediately to attacks without watching the dashboard
        around the clock.
      </p>

      <Callout type="info" title="Pipeline Integration">
        The alerting system is implemented as a pipeline handler. It processes threat events
        asynchronously alongside other handlers like the threat profiler and geolocation enricher.
        No events are dropped or delayed by alert dispatch.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  ALERT PROVIDERS                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="alert-providers">Alert Providers</h2>
      <p>
        Sentinel supports three alert providers out of the box. You can enable any combination of
        them — all three can run simultaneously.
      </p>

      <table>
        <thead>
          <tr>
            <th>Provider</th>
            <th>Channel</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Slack</strong></td>
            <td><code>slack</code></td>
            <td>Sends rich formatted messages to a Slack channel via an incoming webhook URL.</td>
          </tr>
          <tr>
            <td><strong>Email</strong></td>
            <td><code>email</code></td>
            <td>Sends HTML-formatted alert emails via SMTP to one or more recipients.</td>
          </tr>
          <tr>
            <td><strong>Webhook</strong></td>
            <td><code>webhook</code></td>
            <td>Sends a JSON payload via HTTP POST to any custom URL, with optional custom headers.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="configuration">Configuration</h2>
      <p>
        Alerting is configured through the <code>Alerts</code> field on the main{' '}
        <code>sentinel.Config</code> struct. Each provider is enabled by providing its corresponding
        config pointer — <code>nil</code> means the provider is disabled.
      </p>

      <h3>AlertConfig</h3>
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
            <td><code>High</code></td>
            <td>Minimum severity level required to trigger an alert. Events below this threshold are silently ignored.</td>
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
            <td>Custom webhook configuration. Set to enable webhook alerts.</td>
          </tr>
        </tbody>
      </table>

      <h3>SlackConfig</h3>
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
            <td>The Slack incoming webhook URL. Create one at <code>api.slack.com/messaging/webhooks</code>.</td>
          </tr>
        </tbody>
      </table>

      <h3>EmailConfig</h3>
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
            <td>SMTP server hostname (e.g., <code>smtp.gmail.com</code>).</td>
          </tr>
          <tr>
            <td><code>SMTPPort</code></td>
            <td><code>int</code></td>
            <td>SMTP server port (e.g., <code>587</code> for TLS).</td>
          </tr>
          <tr>
            <td><code>Username</code></td>
            <td><code>string</code></td>
            <td>SMTP authentication username, also used as the <code>From</code> address.</td>
          </tr>
          <tr>
            <td><code>Password</code></td>
            <td><code>string</code></td>
            <td>SMTP authentication password or app-specific password.</td>
          </tr>
          <tr>
            <td><code>Recipients</code></td>
            <td><code>[]string</code></td>
            <td>List of email addresses to receive alerts.</td>
          </tr>
        </tbody>
      </table>

      <h3>WebhookConfig</h3>
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
            <td>The endpoint URL that receives the JSON POST request.</td>
          </tr>
          <tr>
            <td><code>Headers</code></td>
            <td><code>map[string]string</code></td>
            <td>Optional custom HTTP headers to include with every request (e.g., authorization tokens).</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="core/config.go"
        code={`// AlertConfig configures the alerting system.
type AlertConfig struct {
    MinSeverity Severity       \`json:"min_severity"\`
    Slack       *SlackConfig   \`json:"slack,omitempty"\`
    Email       *EmailConfig   \`json:"email,omitempty"\`
    Webhook     *WebhookConfig \`json:"webhook,omitempty"\`
}

// SlackConfig configures Slack webhook alerts.
type SlackConfig struct {
    WebhookURL string \`json:"webhook_url"\`
}

// EmailConfig configures email alerts.
type EmailConfig struct {
    SMTPHost   string   \`json:"smtp_host"\`
    SMTPPort   int      \`json:"smtp_port"\`
    Username   string   \`json:"username"\`
    Password   string   \`json:"password"\`
    Recipients []string \`json:"recipients"\`
}

// WebhookConfig configures generic webhook alerts.
type WebhookConfig struct {
    URL     string            \`json:"url"\`
    Headers map[string]string \`json:"headers,omitempty"\`
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  SEVERITY FILTERING                                                */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="severity-filtering">Severity Filtering</h2>
      <p>
        The <code>MinSeverity</code> field controls which threat events trigger alerts. Only events
        with a severity equal to or greater than the configured threshold are dispatched. Events
        below the threshold are silently discarded by the alert dispatcher.
      </p>

      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Level</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>Low</code></td>
            <td>1</td>
            <td>Minor events such as informational detections. Alerts on everything.</td>
          </tr>
          <tr>
            <td><code>Medium</code></td>
            <td>2</td>
            <td>Moderate events such as suspicious patterns. Skips Low events.</td>
          </tr>
          <tr>
            <td><code>High</code></td>
            <td>3</td>
            <td>Serious events such as confirmed attack attempts. <strong>Default threshold.</strong></td>
          </tr>
          <tr>
            <td><code>Critical</code></td>
            <td>4</td>
            <td>Only the most severe events trigger alerts. Use for low-noise channels.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="warning" title="Default Severity">
        When <code>MinSeverity</code> is not set, it defaults to <code>High</code>. This means only{' '}
        <code>High</code> and <code>Critical</code> events trigger alerts by default. Set it to{' '}
        <code>sentinel.SeverityLow</code> if you want to be alerted on all events, but be aware this
        can be noisy in high-traffic environments.
      </Callout>

      <CodeBlock
        language="go"
        code={`// Alert on everything (noisy)
Alerts: sentinel.AlertConfig{
    MinSeverity: sentinel.SeverityLow,
    // ...providers
}

// Alert only on critical events (quiet)
Alerts: sentinel.AlertConfig{
    MinSeverity: sentinel.SeverityCritical,
    // ...providers
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  HOW IT WORKS                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It Works</h2>
      <p>
        The alert <code>Dispatcher</code> is registered as a handler in the Sentinel event pipeline.
        When any detection feature (WAF, Auth Shield, Anomaly Detection, Rate Limiting) produces a
        threat event, the pipeline delivers it to the dispatcher. The dispatcher then:
      </p>

      <ol>
        <li>
          <strong>Checks the severity threshold</strong> — if the event severity is below{' '}
          <code>MinSeverity</code>, it is ignored.
        </li>
        <li>
          <strong>Deduplicates</strong> — repeated alerts for the same IP and threat type combination
          are suppressed within a 5-minute window to prevent alert fatigue.
        </li>
        <li>
          <strong>Dispatches concurrently</strong> — the event is sent to all configured providers in
          parallel. A failure in one provider does not affect the others.
        </li>
        <li>
          <strong>Retries on failure</strong> — each provider has up to 3 attempts with exponential
          backoff (1s, 2s, 4s) before the alert is marked as failed.
        </li>
        <li>
          <strong>Records history</strong> — every dispatch attempt (success or failure) is recorded
          in the alert history, which is accessible via the dashboard and API.
        </li>
      </ol>

      <Callout type="success" title="Deduplication">
        The dispatcher automatically suppresses duplicate alerts for the same IP and threat type
        within a 5-minute window. If an attacker triggers 100 SQL injection events in a row, you
        receive one alert, not 100. After 5 minutes, a new alert is sent if the attack is still
        ongoing.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  SLACK INTEGRATION                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="slack-integration">Slack Integration</h2>
      <p>
        The Slack provider sends rich formatted messages using Slack Block Kit. Each alert includes
        the severity level, threat type, source IP (with country if geolocation is enabled), the
        targeted route, whether the request was blocked, and the timestamp.
      </p>

      <h3>Configuration</h3>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    WAF: sentinel.WAFConfig{
        Enabled: true,
        Mode:    sentinel.ModeBlock,
    },
    Alerts: sentinel.AlertConfig{
        MinSeverity: sentinel.SeverityHigh,
        Slack: &sentinel.SlackConfig{
            WebhookURL: "https://hooks.slack.com/services/T00/B00/xxxx",
        },
    },
})`}
      />

      <h3>Message Format</h3>
      <p>
        Slack alerts are formatted with Block Kit sections. The message includes a header with a
        severity indicator, a divider, and a details section:
      </p>
      <CodeBlock
        language="text"
        showLineNumbers={false}
        code={`--- Slack message ---

  High Threat Detected

  ────────────────────

  Type:    SQLInjection
  IP:      203.0.113.50 (United States)
  Route:   GET /api/users?id=1' OR '1'='1
  Blocked: Yes
  Time:    2025-01-15T14:30:00Z`}
      />

      <Callout type="info" title="Slack Webhook Setup">
        To create a Slack webhook URL, go to <strong>api.slack.com/apps</strong>, create a new app
        (or select an existing one), enable <strong>Incoming Webhooks</strong>, and add a new
        webhook to the channel where you want to receive alerts. Copy the generated URL into your
        Sentinel config.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  EMAIL INTEGRATION                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="email-integration">Email Integration</h2>
      <p>
        The email provider sends HTML-formatted alert emails via SMTP. Each email includes the
        severity level, threat type, source IP, targeted route, block status, and timestamp in a
        styled table layout.
      </p>

      <h3>Configuration</h3>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    WAF: sentinel.WAFConfig{
        Enabled: true,
        Mode:    sentinel.ModeBlock,
    },
    Alerts: sentinel.AlertConfig{
        MinSeverity: sentinel.SeverityHigh,
        Email: &sentinel.EmailConfig{
            SMTPHost:   "smtp.gmail.com",
            SMTPPort:   587,
            Username:   "alerts@yourcompany.com",
            Password:   "your-app-specific-password",
            Recipients: []string{
                "security-team@yourcompany.com",
                "oncall@yourcompany.com",
            },
        },
    },
})`}
      />

      <p>
        The email subject line follows the format:{' '}
        <code>[Sentinel] High Threat: SQLInjection from 203.0.113.50</code>. The body is an
        HTML table with the same details as the Slack message, styled for readability in email
        clients.
      </p>

      <Callout type="warning" title="Gmail App Passwords">
        If you use Gmail as your SMTP provider, you need to generate an app-specific password rather
        than using your regular account password. Go to your Google Account security settings and
        create an app password under <strong>2-Step Verification</strong>. Use that password in the{' '}
        <code>Password</code> field.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  WEBHOOK INTEGRATION                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="webhook-integration">Webhook Integration</h2>
      <p>
        The webhook provider sends a JSON payload via HTTP POST to any URL you specify. This is
        ideal for integrating with custom SIEM systems, PagerDuty, Opsgenie, Datadog, or any
        service that accepts JSON webhooks. You can include custom headers for authentication.
      </p>

      <h3>Configuration</h3>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    WAF: sentinel.WAFConfig{
        Enabled: true,
        Mode:    sentinel.ModeBlock,
    },
    Alerts: sentinel.AlertConfig{
        MinSeverity: sentinel.SeverityMedium,
        Webhook: &sentinel.WebhookConfig{
            URL: "https://your-siem.example.com/api/v1/events",
            Headers: map[string]string{
                "Authorization": "Bearer your-api-token",
                "X-Source":      "sentinel",
            },
        },
    },
})`}
      />

      <h3>JSON Payload Structure</h3>
      <p>
        Every webhook request sends a JSON payload with the following fields:
      </p>
      <CodeBlock
        language="json"
        filename="Webhook Payload"
        showLineNumbers={false}
        code={`{
  "event": "threat_detected",
  "threat_id": "te-abc123",
  "timestamp": "2025-01-15T14:30:00Z",
  "ip": "203.0.113.50",
  "method": "GET",
  "path": "/api/users",
  "threat_types": ["SQLInjection"],
  "severity": "High",
  "confidence": 95,
  "blocked": true,
  "country": "United States",
  "evidence": "1' OR '1'='1"
}`}
      />

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
            <td><code>event</code></td>
            <td><code>string</code></td>
            <td>Always <code>"threat_detected"</code>.</td>
          </tr>
          <tr>
            <td><code>threat_id</code></td>
            <td><code>string</code></td>
            <td>Unique identifier for the threat event.</td>
          </tr>
          <tr>
            <td><code>timestamp</code></td>
            <td><code>string</code></td>
            <td>ISO 8601 / RFC 3339 timestamp in UTC.</td>
          </tr>
          <tr>
            <td><code>ip</code></td>
            <td><code>string</code></td>
            <td>Source IP address of the attacker.</td>
          </tr>
          <tr>
            <td><code>method</code></td>
            <td><code>string</code></td>
            <td>HTTP method of the request (GET, POST, etc.).</td>
          </tr>
          <tr>
            <td><code>path</code></td>
            <td><code>string</code></td>
            <td>Request path that triggered the detection.</td>
          </tr>
          <tr>
            <td><code>threat_types</code></td>
            <td><code>[]string</code></td>
            <td>List of detected threat types (e.g., <code>SQLInjection</code>, <code>XSS</code>).</td>
          </tr>
          <tr>
            <td><code>severity</code></td>
            <td><code>string</code></td>
            <td>Severity level: <code>Low</code>, <code>Medium</code>, <code>High</code>, or <code>Critical</code>.</td>
          </tr>
          <tr>
            <td><code>confidence</code></td>
            <td><code>int</code></td>
            <td>Detection confidence score (0-100).</td>
          </tr>
          <tr>
            <td><code>blocked</code></td>
            <td><code>bool</code></td>
            <td>Whether the request was blocked by the WAF.</td>
          </tr>
          <tr>
            <td><code>country</code></td>
            <td><code>string</code></td>
            <td>Country of origin (empty if geolocation is not enabled).</td>
          </tr>
          <tr>
            <td><code>evidence</code></td>
            <td><code>string</code></td>
            <td>The matched pattern or payload snippet that triggered the detection.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Response Handling">
        The webhook provider expects a 2xx status code from the receiving endpoint. Any non-2xx
        response triggers the retry mechanism (up to 3 attempts with exponential backoff). The
        request has a 10-second timeout per attempt.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  MULTIPLE PROVIDERS                                                */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="multiple-providers">Multiple Providers</h2>
      <p>
        You can configure all three providers simultaneously. When a qualifying threat event occurs,
        the dispatcher sends alerts to every configured provider concurrently. A failure in one
        provider does not prevent the others from receiving the alert.
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    WAF: sentinel.WAFConfig{
        Enabled: true,
        Mode:    sentinel.ModeBlock,
    },
    Alerts: sentinel.AlertConfig{
        MinSeverity: sentinel.SeverityHigh,

        // Slack for real-time team notifications
        Slack: &sentinel.SlackConfig{
            WebhookURL: "https://hooks.slack.com/services/T00/B00/xxxx",
        },

        // Email for the security team
        Email: &sentinel.EmailConfig{
            SMTPHost:   "smtp.gmail.com",
            SMTPPort:   587,
            Username:   "alerts@yourcompany.com",
            Password:   "your-app-specific-password",
            Recipients: []string{"security-team@yourcompany.com"},
        },

        // Webhook for SIEM integration
        Webhook: &sentinel.WebhookConfig{
            URL: "https://your-siem.example.com/api/v1/events",
            Headers: map[string]string{
                "Authorization": "Bearer your-siem-token",
            },
        },
    },
})`}
      />

      <Callout type="success" title="Independent Delivery">
        Each provider runs in its own goroutine with independent retry logic. If your SMTP server is
        temporarily unreachable, Slack and webhook alerts still go through. Failed attempts are
        recorded in the alert history with the error message for debugging.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  ALERT HISTORY                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="alert-history">Alert History</h2>
      <p>
        Every alert dispatch attempt is recorded in an in-memory history log. Each entry tracks
        whether the alert was sent successfully or failed, along with the channel, severity, IP,
        threat type, and any error message.
      </p>

      <h3>AlertHistory Fields</h3>
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
            <td>Unique identifier for the history entry.</td>
          </tr>
          <tr>
            <td><code>Timestamp</code></td>
            <td><code>time.Time</code></td>
            <td>When the alert was dispatched.</td>
          </tr>
          <tr>
            <td><code>ThreatID</code></td>
            <td><code>string</code></td>
            <td>The ID of the threat event that triggered the alert.</td>
          </tr>
          <tr>
            <td><code>Channel</code></td>
            <td><code>string</code></td>
            <td>The provider channel: <code>slack</code>, <code>email</code>, or <code>webhook</code>.</td>
          </tr>
          <tr>
            <td><code>Severity</code></td>
            <td><code>Severity</code></td>
            <td>Severity of the threat event.</td>
          </tr>
          <tr>
            <td><code>IP</code></td>
            <td><code>string</code></td>
            <td>Source IP of the attacker.</td>
          </tr>
          <tr>
            <td><code>ThreatType</code></td>
            <td><code>string</code></td>
            <td>The primary threat type that triggered the alert.</td>
          </tr>
          <tr>
            <td><code>Success</code></td>
            <td><code>bool</code></td>
            <td>Whether the alert was delivered successfully.</td>
          </tr>
          <tr>
            <td><code>Error</code></td>
            <td><code>string</code></td>
            <td>Error message if the alert failed (empty on success).</td>
          </tr>
        </tbody>
      </table>

      <p>
        The history buffer retains the last 1,000 entries in memory. Older entries are evicted when
        new ones arrive. The history resets on application restart.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        The Sentinel dashboard includes a dedicated Alerts page that provides visibility into your
        alerting configuration and delivery history.
      </p>

      <ul>
        <li>
          <strong>Configuration overview</strong> — see which providers are active, the current
          severity threshold, and the connection details for each provider.
        </li>
        <li>
          <strong>Alert history</strong> — browse the chronological log of all dispatched alerts
          with their delivery status, channel, severity, source IP, and threat type.
        </li>
        <li>
          <strong>Failure tracking</strong> — quickly identify failed deliveries and their error
          messages to diagnose connectivity or configuration issues.
        </li>
      </ul>

      <p>
        Access the Alerts page at{' '}
        <code>http://localhost:8080/sentinel/ui</code> and navigate to the Alerts section.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  FULL EXAMPLE                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="full-example">Full Configuration Example</h2>
      <p>
        The following example enables the WAF in block mode with Slack alerting for high-severity
        events and a webhook for SIEM integration at medium severity:
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

    sentinel.Mount(r, nil, sentinel.Config{
        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },

        Alerts: sentinel.AlertConfig{
            MinSeverity: sentinel.SeverityHigh,

            Slack: &sentinel.SlackConfig{
                WebhookURL: "https://hooks.slack.com/services/T00/B00/xxxx",
            },

            Email: &sentinel.EmailConfig{
                SMTPHost:   "smtp.gmail.com",
                SMTPPort:   587,
                Username:   "alerts@yourcompany.com",
                Password:   "your-app-specific-password",
                Recipients: []string{
                    "security-team@yourcompany.com",
                },
            },

            Webhook: &sentinel.WebhookConfig{
                URL: "https://your-siem.example.com/api/v1/events",
                Headers: map[string]string{
                    "Authorization": "Bearer your-siem-token",
                },
            },
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/waf">WAF</a> — Configure the detection rules that generate threat events</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> — Protect login endpoints and generate auth-related alerts</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Add behavioral analysis that feeds into alerting</li>
        <li><a href="/docs/threat-intelligence">Threat Intelligence</a> — Profile attackers and enrich alert data with geolocation</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — View alert history and configuration in the UI</li>
      </ul>
    </>
  );
}
