module.exports=[4606,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Alerting"}),(0,b.jsx)("p",{children:"Sentinel includes a built-in alerting system that sends real-time notifications when security events occur. Alerts are dispatched to one or more providers — Slack, email, or a custom webhook — whenever a threat event meets or exceeds your configured severity threshold. This lets your security team respond immediately to attacks without watching the dashboard around the clock."}),(0,b.jsx)(d.default,{type:"info",title:"Pipeline Integration",children:"The alerting system is implemented as a pipeline handler. It processes threat events asynchronously alongside other handlers like the threat profiler and geolocation enricher. No events are dropped or delayed by alert dispatch."}),(0,b.jsx)("h2",{id:"alert-providers",children:"Alert Providers"}),(0,b.jsx)("p",{children:"Sentinel supports three alert providers out of the box. You can enable any combination of them — all three can run simultaneously."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Provider"}),(0,b.jsx)("th",{children:"Channel"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Slack"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"slack"})}),(0,b.jsx)("td",{children:"Sends rich formatted messages to a Slack channel via an incoming webhook URL."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Email"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"email"})}),(0,b.jsx)("td",{children:"Sends HTML-formatted alert emails via SMTP to one or more recipients."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Webhook"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"webhook"})}),(0,b.jsx)("td",{children:"Sends a JSON payload via HTTP POST to any custom URL, with optional custom headers."})]})]})]}),(0,b.jsx)("h2",{id:"configuration",children:"Configuration"}),(0,b.jsxs)("p",{children:["Alerting is configured through the ",(0,b.jsx)("code",{children:"Alerts"})," field on the main"," ",(0,b.jsx)("code",{children:"sentinel.Config"})," struct. Each provider is enabled by providing its corresponding config pointer — ",(0,b.jsx)("code",{children:"nil"})," means the provider is disabled."]}),(0,b.jsx)("h3",{children:"AlertConfig"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MinSeverity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"High"})}),(0,b.jsx)("td",{children:"Minimum severity level required to trigger an alert. Events below this threshold are silently ignored."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Slack"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*SlackConfig"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Slack webhook configuration. Set to enable Slack alerts."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Email"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*EmailConfig"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Email SMTP configuration. Set to enable email alerts."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Webhook"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*WebhookConfig"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Custom webhook configuration. Set to enable webhook alerts."})]})]})]}),(0,b.jsx)("h3",{children:"SlackConfig"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsx)("tbody",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"WebhookURL"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["The Slack incoming webhook URL. Create one at ",(0,b.jsx)("code",{children:"api.slack.com/messaging/webhooks"}),"."]})]})})]}),(0,b.jsx)("h3",{children:"EmailConfig"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SMTPHost"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["SMTP server hostname (e.g., ",(0,b.jsx)("code",{children:"smtp.gmail.com"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SMTPPort"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsxs)("td",{children:["SMTP server port (e.g., ",(0,b.jsx)("code",{children:"587"})," for TLS)."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Username"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["SMTP authentication username, also used as the ",(0,b.jsx)("code",{children:"From"})," address."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Password"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"SMTP authentication password or app-specific password."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Recipients"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsx)("td",{children:"List of email addresses to receive alerts."})]})]})]}),(0,b.jsx)("h3",{children:"WebhookConfig"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"URL"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The endpoint URL that receives the JSON POST request."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Headers"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"map[string]string"})}),(0,b.jsx)("td",{children:"Optional custom HTTP headers to include with every request (e.g., authorization tokens)."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"core/config.go",code:`// AlertConfig configures the alerting system.
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
}`}),(0,b.jsx)("h2",{id:"severity-filtering",children:"Severity Filtering"}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"MinSeverity"})," field controls which threat events trigger alerts. Only events with a severity equal to or greater than the configured threshold are dispatched. Events below the threshold are silently discarded by the alert dispatcher."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Severity"}),(0,b.jsx)("th",{children:"Level"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Low"})}),(0,b.jsx)("td",{children:"1"}),(0,b.jsx)("td",{children:"Minor events such as informational detections. Alerts on everything."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Medium"})}),(0,b.jsx)("td",{children:"2"}),(0,b.jsx)("td",{children:"Moderate events such as suspicious patterns. Skips Low events."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"High"})}),(0,b.jsx)("td",{children:"3"}),(0,b.jsxs)("td",{children:["Serious events such as confirmed attack attempts. ",(0,b.jsx)("strong",{children:"Default threshold."})]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Critical"})}),(0,b.jsx)("td",{children:"4"}),(0,b.jsx)("td",{children:"Only the most severe events trigger alerts. Use for low-noise channels."})]})]})]}),(0,b.jsxs)(d.default,{type:"warning",title:"Default Severity",children:["When ",(0,b.jsx)("code",{children:"MinSeverity"})," is not set, it defaults to ",(0,b.jsx)("code",{children:"High"}),". This means only"," ",(0,b.jsx)("code",{children:"High"})," and ",(0,b.jsx)("code",{children:"Critical"})," events trigger alerts by default. Set it to"," ",(0,b.jsx)("code",{children:"sentinel.SeverityLow"})," if you want to be alerted on all events, but be aware this can be noisy in high-traffic environments."]}),(0,b.jsx)(c.default,{language:"go",code:`// Alert on everything (noisy)
Alerts: sentinel.AlertConfig{
    MinSeverity: sentinel.SeverityLow,
    // ...providers
}

// Alert only on critical events (quiet)
Alerts: sentinel.AlertConfig{
    MinSeverity: sentinel.SeverityCritical,
    // ...providers
}`}),(0,b.jsx)("h2",{id:"how-it-works",children:"How It Works"}),(0,b.jsxs)("p",{children:["The alert ",(0,b.jsx)("code",{children:"Dispatcher"})," is registered as a handler in the Sentinel event pipeline. When any detection feature (WAF, Auth Shield, Anomaly Detection, Rate Limiting) produces a threat event, the pipeline delivers it to the dispatcher. The dispatcher then:"]}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Checks the severity threshold"})," — if the event severity is below"," ",(0,b.jsx)("code",{children:"MinSeverity"}),", it is ignored."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Deduplicates"})," — repeated alerts for the same IP and threat type combination are suppressed within a 5-minute window to prevent alert fatigue."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Dispatches concurrently"})," — the event is sent to all configured providers in parallel. A failure in one provider does not affect the others."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Retries on failure"})," — each provider has up to 3 attempts with exponential backoff (1s, 2s, 4s) before the alert is marked as failed."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Records history"})," — every dispatch attempt (success or failure) is recorded in the alert history, which is accessible via the dashboard and API."]})]}),(0,b.jsx)(d.default,{type:"success",title:"Deduplication",children:"The dispatcher automatically suppresses duplicate alerts for the same IP and threat type within a 5-minute window. If an attacker triggers 100 SQL injection events in a row, you receive one alert, not 100. After 5 minutes, a new alert is sent if the attack is still ongoing."}),(0,b.jsx)("h2",{id:"slack-integration",children:"Slack Integration"}),(0,b.jsx)("p",{children:"The Slack provider sends rich formatted messages using Slack Block Kit. Each alert includes the severity level, threat type, source IP (with country if geolocation is enabled), the targeted route, whether the request was blocked, and the timestamp."}),(0,b.jsx)("h3",{children:"Configuration"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
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
})`}),(0,b.jsx)("h3",{children:"Message Format"}),(0,b.jsx)("p",{children:"Slack alerts are formatted with Block Kit sections. The message includes a header with a severity indicator, a divider, and a details section:"}),(0,b.jsx)(c.default,{language:"text",showLineNumbers:!1,code:`--- Slack message ---

  High Threat Detected

  ────────────────────

  Type:    SQLInjection
  IP:      203.0.113.50 (United States)
  Route:   GET /api/users?id=1' OR '1'='1
  Blocked: Yes
  Time:    2025-01-15T14:30:00Z`}),(0,b.jsxs)(d.default,{type:"info",title:"Slack Webhook Setup",children:["To create a Slack webhook URL, go to ",(0,b.jsx)("strong",{children:"api.slack.com/apps"}),", create a new app (or select an existing one), enable ",(0,b.jsx)("strong",{children:"Incoming Webhooks"}),", and add a new webhook to the channel where you want to receive alerts. Copy the generated URL into your Sentinel config."]}),(0,b.jsx)("h2",{id:"email-integration",children:"Email Integration"}),(0,b.jsx)("p",{children:"The email provider sends HTML-formatted alert emails via SMTP. Each email includes the severity level, threat type, source IP, targeted route, block status, and timestamp in a styled table layout."}),(0,b.jsx)("h3",{children:"Configuration"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
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
})`}),(0,b.jsxs)("p",{children:["The email subject line follows the format:"," ",(0,b.jsx)("code",{children:"[Sentinel] High Threat: SQLInjection from 203.0.113.50"}),". The body is an HTML table with the same details as the Slack message, styled for readability in email clients."]}),(0,b.jsxs)(d.default,{type:"warning",title:"Gmail App Passwords",children:["If you use Gmail as your SMTP provider, you need to generate an app-specific password rather than using your regular account password. Go to your Google Account security settings and create an app password under ",(0,b.jsx)("strong",{children:"2-Step Verification"}),". Use that password in the"," ",(0,b.jsx)("code",{children:"Password"})," field."]}),(0,b.jsx)("h2",{id:"webhook-integration",children:"Webhook Integration"}),(0,b.jsx)("p",{children:"The webhook provider sends a JSON payload via HTTP POST to any URL you specify. This is ideal for integrating with custom SIEM systems, PagerDuty, Opsgenie, Datadog, or any service that accepts JSON webhooks. You can include custom headers for authentication."}),(0,b.jsx)("h3",{children:"Configuration"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
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
})`}),(0,b.jsx)("h3",{children:"JSON Payload Structure"}),(0,b.jsx)("p",{children:"Every webhook request sends a JSON payload with the following fields:"}),(0,b.jsx)(c.default,{language:"json",filename:"Webhook Payload",showLineNumbers:!1,code:`{
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
}`}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"event"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["Always ",(0,b.jsx)("code",{children:'"threat_detected"'}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"threat_id"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Unique identifier for the threat event."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"timestamp"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"ISO 8601 / RFC 3339 timestamp in UTC."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ip"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Source IP address of the attacker."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"method"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"HTTP method of the request (GET, POST, etc.)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"path"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Request path that triggered the detection."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"threat_types"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsxs)("td",{children:["List of detected threat types (e.g., ",(0,b.jsx)("code",{children:"SQLInjection"}),", ",(0,b.jsx)("code",{children:"XSS"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"severity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["Severity level: ",(0,b.jsx)("code",{children:"Low"}),", ",(0,b.jsx)("code",{children:"Medium"}),", ",(0,b.jsx)("code",{children:"High"}),", or ",(0,b.jsx)("code",{children:"Critical"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"confidence"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:"Detection confidence score (0-100)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"blocked"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:"Whether the request was blocked by the WAF."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"country"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Country of origin (empty if geolocation is not enabled)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"evidence"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The matched pattern or payload snippet that triggered the detection."})]})]})]}),(0,b.jsx)(d.default,{type:"info",title:"Response Handling",children:"The webhook provider expects a 2xx status code from the receiving endpoint. Any non-2xx response triggers the retry mechanism (up to 3 attempts with exponential backoff). The request has a 10-second timeout per attempt."}),(0,b.jsx)("h2",{id:"multiple-providers",children:"Multiple Providers"}),(0,b.jsx)("p",{children:"You can configure all three providers simultaneously. When a qualifying threat event occurs, the dispatcher sends alerts to every configured provider concurrently. A failure in one provider does not prevent the others from receiving the alert."}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
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
})`}),(0,b.jsx)(d.default,{type:"success",title:"Independent Delivery",children:"Each provider runs in its own goroutine with independent retry logic. If your SMTP server is temporarily unreachable, Slack and webhook alerts still go through. Failed attempts are recorded in the alert history with the error message for debugging."}),(0,b.jsx)("h2",{id:"alert-history",children:"Alert History"}),(0,b.jsx)("p",{children:"Every alert dispatch attempt is recorded in an in-memory history log. Each entry tracks whether the alert was sent successfully or failed, along with the channel, severity, IP, threat type, and any error message."}),(0,b.jsx)("h3",{children:"AlertHistory Fields"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Unique identifier for the history entry."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Timestamp"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Time"})}),(0,b.jsx)("td",{children:"When the alert was dispatched."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ThreatID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The ID of the threat event that triggered the alert."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Channel"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["The provider channel: ",(0,b.jsx)("code",{children:"slack"}),", ",(0,b.jsx)("code",{children:"email"}),", or ",(0,b.jsx)("code",{children:"webhook"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsx)("td",{children:"Severity of the threat event."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"IP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Source IP of the attacker."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ThreatType"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The primary threat type that triggered the alert."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Success"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:"Whether the alert was delivered successfully."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Error"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Error message if the alert failed (empty on success)."})]})]})]}),(0,b.jsx)("p",{children:"The history buffer retains the last 1,000 entries in memory. Older entries are evicted when new ones arrive. The history resets on application restart."}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsx)("p",{children:"The Sentinel dashboard includes a dedicated Alerts page that provides visibility into your alerting configuration and delivery history."}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Configuration overview"})," — see which providers are active, the current severity threshold, and the connection details for each provider."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Alert history"})," — browse the chronological log of all dispatched alerts with their delivery status, channel, severity, source IP, and threat type."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Failure tracking"})," — quickly identify failed deliveries and their error messages to diagnose connectivity or configuration issues."]})]}),(0,b.jsxs)("p",{children:["Access the Alerts page at"," ",(0,b.jsx)("code",{children:"http://localhost:8080/sentinel/ui"})," and navigate to the Alerts section."]}),(0,b.jsx)("h2",{id:"full-example",children:"Full Configuration Example"}),(0,b.jsx)("p",{children:"The following example enables the WAF in block mode with Slack alerting for high-severity events and a webhook for SIEM integration at medium severity:"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

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
}`}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF"})," — Configure the detection rules that generate threat events"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," — Protect login endpoints and generate auth-related alerts"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/anomaly-detection",children:"Anomaly Detection"})," — Add behavioral analysis that feeds into alerting"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/threat-intelligence",children:"Threat Intelligence"})," — Profile attackers and enrich alert data with geolocation"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — View alert history and configuration in the UI"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Alerting - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_alerting_page_jsx_68d3b69d._.js.map