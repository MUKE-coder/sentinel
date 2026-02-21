import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Web Application Firewall (WAF) - Sentinel Docs',
  description:
    "Configure Sentinel's WAF to detect and block SQL injection, XSS, path traversal, and command injection attacks in your Go application.",
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/waf',
  },
  openGraph: {
    title: 'Web Application Firewall (WAF) - Sentinel Docs',
    description:
      "Configure Sentinel's WAF to detect and block SQL injection, XSS, path traversal, and command injection attacks in your Go application.",
    url: 'https://sentinel-go-sdk.vercel.app/docs/waf',
    type: 'article',
  },
};

export default function WAF() {
  return (
    <>
      <FAQSchema
        questions={[
          {
            q: 'What attacks does the Sentinel WAF detect?',
            a: 'Sentinel WAF detects eight attack categories covering the OWASP Top 10: SQL injection, cross-site scripting (XSS), path traversal, command injection, server-side request forgery (SSRF), XML external entity injection (XXE), local file inclusion (LFI), and open redirect attacks.',
          },
          {
            q: 'What is the difference between ModeLog and ModeBlock?',
            a: 'ModeLog detects and records threats but allows requests to proceed, making it ideal for initial rollout and auditing. ModeBlock detects threats and rejects requests with HTTP 403 Forbidden, preventing malicious payloads from reaching your application handlers.',
          },
          {
            q: 'How do I add custom WAF rules in Sentinel?',
            a: 'Add custom rules via the CustomRules field using WAFRule structs. Each rule specifies a regex pattern, which request parts to inspect (path, query, headers, body), a severity level, and an action (block or log). Custom rules are compiled once at startup for performance.',
          },
          {
            q: 'How do I exclude routes from WAF inspection?',
            a: 'Use the ExcludeRoutes field with a list of URL paths like /health or /metrics to skip WAF inspection entirely. You can also use ExcludeIPs with IP addresses or CIDR ranges to bypass the WAF for trusted internal services or monitoring systems.',
          },
        ]}
      />
      <TechArticleSchema
        title="Sentinel Web Application Firewall (WAF)"
        description="Configure Sentinel's WAF to detect and block SQL injection, XSS, path traversal, and command injection attacks in your Go application."
        url="https://sentinel-go-sdk.vercel.app/docs/waf"
      />
      <SpeakableSchema
        url="https://sentinel-go-sdk.vercel.app/docs/waf"
        cssSelector={['.prose h1', '.prose h2', '.prose p']}
      />
      <h1>Web Application Firewall (WAF)</h1>
      <p>
        Sentinel includes a built-in Web Application Firewall that inspects every incoming HTTP
        request for malicious payloads. It provides comprehensive coverage for the{' '}
        <strong>OWASP Top 10</strong> attack categories, including SQL injection, cross-site scripting
        (XSS), path traversal, command injection, server-side request forgery (SSRF), XML external
        entity injection (XXE), local file inclusion (LFI), and open redirect attacks.
      </p>
      <p>
        The WAF operates as Gin middleware registered by <code>sentinel.Mount()</code>. It runs before
        your application handlers, so malicious requests are intercepted before they reach your
        business logic. All detections are recorded as security events and are visible in the Sentinel
        dashboard.
      </p>

      <Callout type="info" title="Zero False Positives by Default">
        Sentinel ships with carefully tuned regex patterns at multiple strictness levels. Start with
        the defaults, observe traffic in <code>ModeLog</code>, and adjust sensitivity per category as
        needed for your application.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  ENABLING THE WAF                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="enabling">Enabling the WAF</h2>
      <p>
        The WAF is disabled by default. To enable it, set <code>Enabled: true</code> in your{' '}
        <code>WAFConfig</code> and choose a mode. The simplest configuration enables blocking mode
        with all default rule sensitivities:
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
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      <p>
        With this configuration, Sentinel inspects every request against all built-in rule categories
        at their default strictness levels. Malicious requests receive an HTTP 403 response and are
        logged as security events.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  WAF MODES                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="modes">WAF Modes</h2>
      <p>
        The WAF supports two primary operating modes. The mode determines what happens when a
        malicious payload is detected.
      </p>

      <table>
        <thead>
          <tr>
            <th>Mode</th>
            <th>Constant</th>
            <th>Behavior</th>
            <th>Use Case</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Log</td>
            <td><code>sentinel.ModeLog</code></td>
            <td>Detects and records threats but <strong>allows the request to proceed</strong>. The event is logged and visible in the dashboard.</td>
            <td>Initial rollout, testing, auditing</td>
          </tr>
          <tr>
            <td>Block</td>
            <td><code>sentinel.ModeBlock</code></td>
            <td>Detects threats and <strong>rejects the request with HTTP 403 Forbidden</strong>. The response includes a JSON body with the block reason.</td>
            <td>Production enforcement</td>
          </tr>
        </tbody>
      </table>

      <h3>ModeLog (Detect Only)</h3>
      <p>
        In log mode, the WAF identifies malicious payloads and creates security events, but it does
        not block the request. This is ideal for initial deployment when you want to observe what the
        WAF detects without impacting real traffic.
      </p>
      <CodeBlock
        language="go"
        code={`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeLog, // Detect and log, but don't block
}`}
      />
      <p>
        When a threat is detected in log mode, the request continues to your handler normally. The
        detection is recorded and appears in the dashboard under the Events page with full details
        including the matched pattern, severity, and request metadata.
      </p>

      <h3>ModeBlock (Block Malicious Requests)</h3>
      <p>
        In block mode, detected threats are rejected immediately with an HTTP 403 status code. The
        request never reaches your application handler. The response body contains a JSON object
        describing the block:
      </p>
      <CodeBlock
        language="go"
        code={`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock, // Detect and block with 403
}`}
      />
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Example blocked response
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Request blocked by WAF",
  "reason": "SQL Injection detected",
  "request_id": "abc123"
}`}
      />

      <Callout type="success" title="Recommended Rollout Strategy">
        Start with <code>sentinel.ModeLog</code> in production for 1-2 weeks to observe detections
        and identify any false positives. Review the dashboard, tune rule sensitivities and exclusions,
        then switch to <code>sentinel.ModeBlock</code> when you are confident in the configuration.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  BUILT-IN RULES                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="built-in-rules">Built-in Rules</h2>
      <p>
        Sentinel ships with eight built-in detection rule categories that cover the most common web
        attack vectors. Each category has its own set of regex patterns and can be independently
        configured with a strictness level.
      </p>

      <h3>Rule Categories</h3>
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Field</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>SQL Injection</td>
            <td><code>SQLInjection</code></td>
            <td><code>RuleStrict</code></td>
            <td>Detects SQL injection attempts including UNION-based, boolean-based, time-based blind, and error-based injection patterns.</td>
          </tr>
          <tr>
            <td>Cross-Site Scripting</td>
            <td><code>XSS</code></td>
            <td><code>RuleStrict</code></td>
            <td>Detects XSS payloads including script tags, event handlers (<code>onerror</code>, <code>onload</code>), <code>javascript:</code> URIs, and encoded variants.</td>
          </tr>
          <tr>
            <td>Path Traversal</td>
            <td><code>PathTraversal</code></td>
            <td><code>RuleStrict</code></td>
            <td>Detects directory traversal sequences (<code>../</code>, <code>..%2f</code>) targeting sensitive system files like <code>/etc/passwd</code> or <code>web.config</code>.</td>
          </tr>
          <tr>
            <td>Command Injection</td>
            <td><code>CommandInjection</code></td>
            <td><code>RuleStrict</code></td>
            <td>Detects OS command injection via shell metacharacters (<code>;</code>, <code>|</code>, <code>&&</code>, backticks) and common commands (<code>cat</code>, <code>wget</code>, <code>curl</code>).</td>
          </tr>
          <tr>
            <td>SSRF</td>
            <td><code>SSRF</code></td>
            <td><code>RuleMedium</code></td>
            <td>Detects server-side request forgery attempts targeting internal networks (<code>127.0.0.1</code>, <code>169.254.169.254</code>, <code>localhost</code>, private IP ranges).</td>
          </tr>
          <tr>
            <td>XXE</td>
            <td><code>XXE</code></td>
            <td><code>RuleStrict</code></td>
            <td>Detects XML external entity injection via <code>DOCTYPE</code> declarations, <code>ENTITY</code> definitions, and <code>SYSTEM</code> identifiers in request bodies.</td>
          </tr>
          <tr>
            <td>LFI</td>
            <td><code>LFI</code></td>
            <td><code>RuleStrict</code></td>
            <td>Detects local file inclusion attempts targeting common sensitive paths (<code>/etc/shadow</code>, <code>/proc/self</code>, <code>php://filter</code>).</td>
          </tr>
          <tr>
            <td>Open Redirect</td>
            <td><code>OpenRedirect</code></td>
            <td><code>RuleMedium</code></td>
            <td>Detects open redirect attempts via URL parameters containing external URLs or protocol-relative URLs (<code>//evil.com</code>).</td>
          </tr>
        </tbody>
      </table>

      <h3>Strictness Levels</h3>
      <p>
        Each rule category supports three strictness levels that control how aggressively patterns are
        matched. Higher strictness catches more edge cases but may produce more false positives for
        certain applications.
      </p>

      <table>
        <thead>
          <tr>
            <th>Level</th>
            <th>Constant</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Off</td>
            <td><code>sentinel.RuleOff</code></td>
            <td>Completely disables this rule category. No patterns are evaluated.</td>
          </tr>
          <tr>
            <td>Basic</td>
            <td><code>sentinel.RuleBasic</code></td>
            <td>Matches only the most obvious and high-confidence attack patterns. Lowest false positive rate.</td>
          </tr>
          <tr>
            <td>Strict</td>
            <td><code>sentinel.RuleStrict</code></td>
            <td>Matches a comprehensive set of patterns including encoded and obfuscated variants. Highest coverage, but may require exclusions for some applications.</td>
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
        SQLInjection:     sentinel.RuleStrict,  // Maximum SQL injection coverage
        XSS:              sentinel.RuleStrict,  // Maximum XSS coverage
        PathTraversal:    sentinel.RuleStrict,  // Catch encoded traversal sequences
        CommandInjection: sentinel.RuleBasic,   // Basic only — reduces false positives for CLI tools
        SSRF:             sentinel.RuleMedium,  // Balanced SSRF detection
        XXE:              sentinel.RuleStrict,  // Full XXE protection
        LFI:              sentinel.RuleStrict,  // Full LFI protection
        OpenRedirect:     sentinel.RuleOff,     // Disabled — app handles redirects internally
    },
}`}
      />

      <Callout type="warning" title="Disabling Rules">
        Setting a rule category to <code>sentinel.RuleOff</code> completely disables that detection
        class. Only do this if you are certain your application is not vulnerable to that attack
        vector, or if you have other defenses in place (e.g., a cloud WAF handling that category).
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  CUSTOM RULES                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="custom-rules">Custom Rules</h2>
      <p>
        In addition to the built-in rules, you can define custom rules to detect application-specific
        attack patterns. Custom rules are defined as <code>WAFRule</code> structs and are evaluated
        alongside the built-in rules during request inspection.
      </p>

      <h3>WAFRule Struct</h3>
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
            <td>Unique identifier for the rule. Used in event logs and the dashboard. Must be unique across all custom rules.</td>
          </tr>
          <tr>
            <td><code>Name</code></td>
            <td><code>string</code></td>
            <td>Human-readable name displayed in the dashboard and event details.</td>
          </tr>
          <tr>
            <td><code>Pattern</code></td>
            <td><code>string</code></td>
            <td>Go-compatible regular expression. Compiled once at startup for performance. Use raw strings (<code>{"`...`"}</code>) to avoid double-escaping.</td>
          </tr>
          <tr>
            <td><code>AppliesTo</code></td>
            <td><code>[]string</code></td>
            <td>Which parts of the request to inspect. Valid values: <code>"path"</code>, <code>"query"</code>, <code>"headers"</code>, <code>"body"</code>. You can specify multiple.</td>
          </tr>
          <tr>
            <td><code>Severity</code></td>
            <td><code>Severity</code></td>
            <td>Severity level assigned to matches. Options: <code>sentinel.SeverityLow</code>, <code>sentinel.SeverityMedium</code>, <code>sentinel.SeverityHigh</code>, <code>sentinel.SeverityCritical</code>.</td>
          </tr>
          <tr>
            <td><code>Action</code></td>
            <td><code>string</code></td>
            <td>Action to take when the pattern matches: <code>"block"</code> (reject with 403) or <code>"log"</code> (record but allow). This overrides the global WAF mode for this specific rule.</td>
          </tr>
          <tr>
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td>Whether the rule is active. Set to <code>false</code> to disable a rule without removing it from the configuration.</td>
          </tr>
        </tbody>
      </table>

      <h3>AppliesTo Targets</h3>
      <table>
        <thead>
          <tr>
            <th>Target</th>
            <th>What Is Inspected</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>"path"</code></td>
            <td>The URL path (e.g., <code>/api/users/123</code>)</td>
          </tr>
          <tr>
            <td><code>"query"</code></td>
            <td>The raw query string (e.g., <code>id=1&name=test</code>)</td>
          </tr>
          <tr>
            <td><code>"headers"</code></td>
            <td>All HTTP request headers concatenated (key: value pairs)</td>
          </tr>
          <tr>
            <td><code>"body"</code></td>
            <td>The request body (for POST, PUT, PATCH requests)</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`CustomRules: []sentinel.WAFRule{
    {
        ID:        "block-wp-admin",
        Name:      "Block WordPress admin probes",
        Pattern:   \`(?i)/(wp-admin|wp-login\\.php|xmlrpc\\.php|wp-content)\`,
        AppliesTo: []string{"path"},
        Severity:  sentinel.SeverityMedium,
        Action:    "block",
        Enabled:   true,
    },
    {
        ID:        "block-sensitive-files",
        Name:      "Block sensitive file access",
        Pattern:   \`(?i)\\.(env|git|bak|sql|log|ini|cfg|conf|swp)$\`,
        AppliesTo: []string{"path"},
        Severity:  sentinel.SeverityHigh,
        Action:    "block",
        Enabled:   true,
    },
    {
        ID:        "block-scanner-bots",
        Name:      "Block known scanner user agents",
        Pattern:   \`(?i)(sqlmap|nikto|nessus|dirbuster|gobuster|masscan|nmap)\`,
        AppliesTo: []string{"headers"},
        Severity:  sentinel.SeverityHigh,
        Action:    "block",
        Enabled:   true,
    },
    {
        ID:        "log-api-key-exposure",
        Name:      "Detect API key in query string",
        Pattern:   \`(?i)(api[_-]?key|apikey|secret|token|password)=.+\`,
        AppliesTo: []string{"query"},
        Severity:  sentinel.SeverityMedium,
        Action:    "log",
        Enabled:   true,
    },
}`}
      />

      <Callout type="info" title="Rule Action vs Global Mode">
        Each custom rule has its own <code>Action</code> field that overrides the global WAF mode for
        that specific rule. This means you can set the WAF to <code>ModeLog</code> globally but have
        individual custom rules that block, or vice versa. Built-in rules always follow the global mode.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  EXCLUDING ROUTES AND IPS                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="exclusions">Excluding Routes and IPs</h2>
      <p>
        You can exclude specific routes and IP addresses from WAF inspection. Excluded routes and IPs
        bypass the WAF entirely — no patterns are evaluated and no events are generated for these
        requests.
      </p>

      <h3>ExcludeRoutes</h3>
      <p>
        Use <code>ExcludeRoutes</code> to skip WAF inspection for specific URL paths. This is
        commonly used for health check endpoints, metrics endpoints, or routes that legitimately
        handle content that might trigger WAF rules (e.g., a CMS editor).
      </p>
      <CodeBlock
        language="go"
        code={`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
    ExcludeRoutes: []string{
        "/health",           // Health check endpoint
        "/readiness",        // Kubernetes readiness probe
        "/metrics",          // Prometheus metrics
        "/api/v1/webhooks",  // Incoming webhooks may contain arbitrary content
    },
}`}
      />

      <h3>ExcludeIPs</h3>
      <p>
        Use <code>ExcludeIPs</code> to skip WAF inspection for trusted IP addresses or CIDR ranges.
        This is useful for internal services, monitoring systems, or CI/CD pipelines that might
        trigger false positives.
      </p>
      <CodeBlock
        language="go"
        code={`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
    ExcludeIPs: []string{
        "127.0.0.1",       // Localhost
        "10.0.0.0/8",      // Internal network
        "172.16.0.0/12",   // Docker networks
        "192.168.0.0/16",  // Private network
        "203.0.113.50",    // Monitoring server
    },
}`}
      />

      <Callout type="warning" title="Be Careful with IP Exclusions">
        Excluded IPs bypass all WAF rules including custom rules. Only exclude IPs you fully trust.
        If an attacker can spoof a trusted IP (e.g., via the <code>X-Forwarded-For</code> header),
        they could bypass the WAF. Make sure your reverse proxy sets the client IP correctly and that
        Gin is configured to trust the right proxy headers.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  HOW DETECTION WORKS                                                */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-detection-works">How Detection Works</h2>
      <p>
        Understanding the WAF detection pipeline helps you configure it effectively and debug
        false positives.
      </p>

      <h3>Request Inspection Flow</h3>
      <ol>
        <li>
          <strong>Exclusion Check</strong> — The middleware first checks if the request IP or route
          is in the exclusion lists. If so, the request is passed through without inspection.
        </li>
        <li>
          <strong>Request Decomposition</strong> — The classifier extracts four components from the
          request: the URL <strong>path</strong>, the raw <strong>query string</strong>, all
          HTTP <strong>headers</strong> (concatenated), and the request <strong>body</strong> (if present).
        </li>
        <li>
          <strong>Pattern Matching</strong> — Each extracted component is evaluated against the
          compiled regex patterns for all enabled rule categories. The patterns are compiled once at
          startup for performance. Both built-in rules and custom rules are evaluated.
        </li>
        <li>
          <strong>Threat Event Creation</strong> — When a pattern matches, a <code>ThreatEvent</code> is
          created containing the rule ID, category, severity, matched pattern, the request component
          that matched, and full request metadata (IP, user agent, timestamp).
        </li>
        <li>
          <strong>Async Pipeline</strong> — The threat event is sent to the async event pipeline via
          a non-blocking ring buffer. Worker goroutines pick up the event and persist it to storage,
          update threat actor profiles, recompute security scores, and dispatch alerts if the severity
          threshold is met.
        </li>
        <li>
          <strong>Response</strong> — Based on the WAF mode (or the custom rule action), the request
          is either blocked with a 403 response or allowed to proceed to the next handler.
        </li>
      </ol>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# The detection flow visualized:
#
# Request ──> Exclusion Check ──> Decompose Request ──> Pattern Matching
#                  │                                         │
#                  │ (excluded)                    ┌─────────┴─────────┐
#                  v                               v                   v
#              Pass Through                  No Match              Match Found
#                                               │                     │
#                                               v                     v
#                                          Pass Through         Create ThreatEvent
#                                                                     │
#                                                          ┌──────────┴──────────┐
#                                                          v                      v
#                                                      ModeLog              ModeBlock
#                                                          │                      │
#                                                          v                      v
#                                                   Log + Continue          Log + 403`}
      />

      <Callout type="info" title="Non-Blocking Event Pipeline">
        The WAF detection and event logging are decoupled. Pattern matching happens synchronously in
        the request path, but event persistence, threat profiling, score computation, and alerting all
        happen asynchronously via the pipeline. This means the WAF adds minimal latency to your
        requests even under heavy attack traffic.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING THE WAF                                                    */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing the WAF</h2>
      <p>
        After enabling the WAF, you should test it to verify that it correctly detects and handles
        malicious requests. Below are curl commands you can use to test each major attack category.
      </p>

      <h3>Testing SQL Injection</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Classic SQL injection in query parameter
curl -v "http://localhost:8080/api/users?id=1'+OR+'1'='1"

# UNION-based SQL injection
curl -v "http://localhost:8080/api/users?id=1+UNION+SELECT+username,password+FROM+users--"

# Boolean-based blind injection
curl -v "http://localhost:8080/api/users?id=1+AND+1=1"

# SQL injection in POST body
curl -v -X POST http://localhost:8080/api/search \\
  -H "Content-Type: application/json" \\
  -d '{"query": "test\\"; DROP TABLE users; --"}'`}
      />

      <h3>Testing XSS</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Script tag injection
curl -v "http://localhost:8080/api/search?q=<script>alert('xss')</script>"

# Event handler injection
curl -v "http://localhost:8080/api/search?q=<img+src=x+onerror=alert(1)>"

# JavaScript URI
curl -v "http://localhost:8080/api/search?q=javascript:alert(document.cookie)"`}
      />

      <h3>Testing Path Traversal</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Basic path traversal
curl -v "http://localhost:8080/api/files/../../../../etc/passwd"

# URL-encoded traversal
curl -v "http://localhost:8080/api/files/..%2f..%2f..%2fetc%2fpasswd"

# Double-encoded traversal
curl -v "http://localhost:8080/api/files/..%252f..%252f..%252fetc%252fpasswd"`}
      />

      <h3>Testing Command Injection</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Semicolon injection
curl -v "http://localhost:8080/api/ping?host=127.0.0.1;cat+/etc/passwd"

# Pipe injection
curl -v "http://localhost:8080/api/ping?host=127.0.0.1|whoami"

# Backtick injection
curl -v "http://localhost:8080/api/ping?host=\\\`whoami\\\`"`}
      />

      <h3>Expected Responses</h3>
      <p>
        The response you receive depends on the WAF mode:
      </p>

      <h4>ModeBlock Response (403 Forbidden)</h4>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`$ curl -s "http://localhost:8080/api/users?id=1'+OR+'1'='1" | jq .
{
  "error": "Request blocked by WAF",
  "reason": "SQL Injection detected",
  "request_id": "req_abc123def456"
}`}
      />

      <h4>ModeLog Response (200 OK, event logged)</h4>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`$ curl -s "http://localhost:8080/api/users?id=1'+OR+'1'='1" | jq .
{
  "users": []
}
# The request succeeds, but a WAF event is logged in the dashboard.
# Check the Sentinel Events page to see the detection.`}
      />

      <Callout type="danger" title="Testing in Production">
        Only run these tests against development or staging environments. Running attack payloads
        against a production system could trigger alerts, IP bans, or lock out your own IP address
        if Auth Shield or IP reputation features are also enabled.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  CUSTOM RULE EXAMPLES                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="custom-rule-examples">Custom Rule Examples</h2>
      <p>
        Below are practical custom rule examples for common use cases. These demonstrate the
        flexibility of the WAF rule engine for application-specific security needs.
      </p>

      <h3>Block WordPress and CMS Admin Probes</h3>
      <p>
        Bots constantly scan for common CMS admin panels. If your application is not WordPress,
        block these immediately to reduce noise.
      </p>
      <CodeBlock
        language="go"
        code={`{
    ID:        "block-cms-probes",
    Name:      "Block CMS admin panel probes",
    Pattern:   \`(?i)/(wp-admin|wp-login\\.php|wp-content|wp-includes|xmlrpc\\.php|administrator|phpmyadmin|adminer|cgi-bin)\`,
    AppliesTo: []string{"path"},
    Severity:  sentinel.SeverityMedium,
    Action:    "block",
    Enabled:   true,
}`}
      />

      <h3>Block Sensitive File Extensions</h3>
      <p>
        Prevent access to backup files, configuration files, and version control artifacts that
        should never be served by your application.
      </p>
      <CodeBlock
        language="go"
        code={`{
    ID:        "block-sensitive-extensions",
    Name:      "Block sensitive file extensions",
    Pattern:   \`(?i)\\.(env|git|gitignore|bak|sql|log|ini|cfg|conf|swp|old|orig|dist|save|DS_Store|htaccess|htpasswd)$\`,
    AppliesTo: []string{"path"},
    Severity:  sentinel.SeverityHigh,
    Action:    "block",
    Enabled:   true,
}`}
      />

      <h3>Block Known Scanner User Agents</h3>
      <p>
        Automated security scanners identify themselves via their User-Agent header. Block known
        scanner signatures to reduce noise in your security logs.
      </p>
      <CodeBlock
        language="go"
        code={`{
    ID:        "block-scanner-agents",
    Name:      "Block known vulnerability scanner agents",
    Pattern:   \`(?i)(sqlmap|nikto|nessus|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf|burpsuite|zap|acunetix|qualys|openvas)\`,
    AppliesTo: []string{"headers"},
    Severity:  sentinel.SeverityHigh,
    Action:    "block",
    Enabled:   true,
}`}
      />

      <h3>Detect API Keys in Query Strings</h3>
      <p>
        API keys should be sent in headers, not query strings (which appear in logs and browser
        history). This rule logs a warning when credentials appear in URLs.
      </p>
      <CodeBlock
        language="go"
        code={`{
    ID:        "detect-credentials-in-url",
    Name:      "Detect credentials in query string",
    Pattern:   \`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)=[^&]+\`,
    AppliesTo: []string{"query"},
    Severity:  sentinel.SeverityMedium,
    Action:    "log",  // Log only — don't block, just alert
    Enabled:   true,
}`}
      />

      <h3>Full Custom Rules Configuration</h3>
      <p>
        Here is a complete example combining multiple custom rules with the built-in rule set:
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
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
                ID:        "block-cms-probes",
                Name:      "Block CMS admin panel probes",
                Pattern:   \`(?i)/(wp-admin|wp-login\\.php|xmlrpc\\.php|phpmyadmin)\`,
                AppliesTo: []string{"path"},
                Severity:  sentinel.SeverityMedium,
                Action:    "block",
                Enabled:   true,
            },
            {
                ID:        "block-sensitive-extensions",
                Name:      "Block sensitive file extensions",
                Pattern:   \`(?i)\\.(env|git|bak|sql|log|swp)$\`,
                AppliesTo: []string{"path"},
                Severity:  sentinel.SeverityHigh,
                Action:    "block",
                Enabled:   true,
            },
            {
                ID:        "block-scanner-agents",
                Name:      "Block scanner user agents",
                Pattern:   \`(?i)(sqlmap|nikto|nessus|dirbuster|gobuster|nmap)\`,
                AppliesTo: []string{"headers"},
                Severity:  sentinel.SeverityHigh,
                Action:    "block",
                Enabled:   true,
            },
            {
                ID:        "detect-credentials-in-url",
                Name:      "Detect credentials in query string",
                Pattern:   \`(?i)(api[_-]?key|secret|token|password)=[^&]+\`,
                AppliesTo: []string{"query"},
                Severity:  sentinel.SeverityMedium,
                Action:    "log",
                Enabled:   true,
            },
        },
        ExcludeRoutes: []string{"/health", "/readiness", "/metrics"},
        ExcludeIPs:    []string{"10.0.0.0/8", "172.16.0.0/12"},
    },
})`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">WAF Dashboard</h2>
      <p>
        The Sentinel dashboard includes a dedicated WAF page that provides a visual interface for
        managing and monitoring the Web Application Firewall.
      </p>

      <h3>Dashboard Capabilities</h3>
      <ul>
        <li>
          <strong>Rule Management</strong> — View all active built-in and custom rules. Enable or
          disable individual rules, and adjust strictness levels without restarting the application.
        </li>
        <li>
          <strong>Live Input Testing</strong> — Test arbitrary input strings against the active rule
          set directly from the dashboard. The tester shows which rules would match, the severity,
          and what action would be taken.
        </li>
        <li>
          <strong>Detection Statistics</strong> — View real-time stats on total detections,
          detections by category, top blocked IPs, most targeted routes, and detection trends over
          time.
        </li>
        <li>
          <strong>Event Log</strong> — Browse all WAF events with filtering by category, severity,
          IP, time range, and rule ID. Each event shows the full request details and matched pattern.
        </li>
        <li>
          <strong>Custom Rule Editor</strong> — Create, edit, and test custom rules directly from the
          dashboard UI without modifying Go code.
        </li>
      </ul>

      <p>
        Access the WAF dashboard page at{' '}
        <code>http://localhost:8080/sentinel/ui</code> and navigate to the WAF section.
      </p>

      <Callout type="info" title="Dashboard Rule Changes">
        Rules created or modified via the dashboard are persisted to storage and take effect
        immediately. They are evaluated alongside rules defined in your Go configuration. If you
        restart the application, rules from the Go config are always re-applied, while dashboard-created
        rules are loaded from storage.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> — Layer rate limiting on top of WAF protection</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> — Protect authentication endpoints from brute force attacks</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Add behavioral analysis for advanced threat detection</li>
        <li><a href="/docs/alerting">Alerting</a> — Get notified when the WAF detects high-severity threats</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the full security dashboard</li>
      </ul>
    </>
  );
}
