import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'API Reference - Sentinel Docs',
  description:
    'Complete REST API reference for Sentinel with 40+ endpoints covering threats, actors, WAF, rate limits, AI, reports, and WebSocket streams.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/api-reference',
  },
  openGraph: {
    title: 'API Reference - Sentinel Docs',
    description:
      'Complete REST API reference for Sentinel with 40+ endpoints covering threats, actors, WAF, rate limits, AI, reports, and WebSocket streams.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/api-reference',
    siteName: 'Sentinel',
    type: 'article',
  },
};

export default function ApiReference() {
  return (
    <>
      <FAQSchema
        faqs={[
          {
            question: 'How do I authenticate with the Sentinel API?',
            answer: 'Call POST /sentinel/api/auth/login with your dashboard username and password as JSON. The response contains a JWT token. Include it in subsequent requests as an Authorization: Bearer <token> header. The login endpoint is the only one that does not require authentication.',
          },
          {
            question: 'What is the base URL for the Sentinel API?',
            answer: 'All API paths are relative to your configured prefix, which defaults to /sentinel. For example, the threats endpoint is accessed at /sentinel/api/threats. If you set a custom prefix like /admin/security, the full path becomes /admin/security/api/threats.',
          },
          {
            question: 'How is pagination handled in the Sentinel API?',
            answer: 'All list endpoints return data in a standard paginated envelope with a data array and a meta object containing total count, current page, and page_size. Use the page and page_size query parameters to navigate results. Default page size is 20.',
          },
          {
            question: 'Does Sentinel have WebSocket endpoints for real-time data?',
            answer: 'Yes. Sentinel exposes two WebSocket endpoints: /ws/threats for live threat event streaming and /ws/metrics for real-time performance metrics. Authenticate via a token query parameter instead of the Authorization header since browser WebSocket APIs do not support custom headers.',
          },
        ]}
      />
      <TechArticleSchema
        title="API Reference - Sentinel Docs"
        description="Complete REST API reference for Sentinel with 40+ endpoints covering threats, actors, WAF, rate limits, AI, reports, and WebSocket streams."
        url="https://sentinel-go-sdk.vercel.app/docs/api-reference"
      />
      <SpeakableSchema url="https://sentinel-go-sdk.vercel.app/docs/api-reference" />

      <h1>API Reference</h1>
      <p>
        This is the comprehensive reference for every HTTP and WebSocket endpoint exposed by
        Sentinel's dashboard API. All endpoints are served under your configured prefix (default:{' '}
        <code>/sentinel</code>). For example, the login endpoint is available at{' '}
        <code>/sentinel/api/auth/login</code>.
      </p>

      <Callout type="info" title="Authentication Required">
        Unless otherwise noted, all API endpoints require a valid JWT token in the{' '}
        <code>Authorization</code> header. Obtain a token by calling the{' '}
        <code>POST /api/auth/login</code> endpoint. Include it in subsequent requests as:{' '}
        <code>Authorization: Bearer &lt;token&gt;</code>. If the token is missing, expired, or
        invalid, the API responds with HTTP <code>401 Unauthorized</code>.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  STANDARD RESPONSE FORMAT                                          */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="response-format">Standard Response Format</h2>
      <p>
        All list endpoints return data in a standard paginated envelope. Single-resource endpoints
        return the object directly under the <code>data</code> key without pagination metadata.
      </p>

      <CodeBlock
        language="json"
        filename="Paginated Response"
        showLineNumbers={false}
        code={`{
  "data": [ ... ],
  "meta": {
    "total": 142,
    "page": 1,
    "page_size": 20
  }
}`}
      />

      <p>
        Action endpoints (resolve, block, delete, etc.) return a simple success response:
      </p>

      <CodeBlock
        language="json"
        filename="Action Response"
        showLineNumbers={false}
        code={`{
  "success": true,
  "message": "Threat resolved successfully"
}`}
      />

      <p>
        Error responses use standard HTTP status codes with a JSON body:
      </p>

      <CodeBlock
        language="json"
        filename="Error Response"
        showLineNumbers={false}
        code={`{
  "error": "Invalid credentials"
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  BASE URL                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="base-url">Base URL</h2>
      <p>
        All API paths in this reference are relative to your configured prefix. The default prefix
        is <code>/sentinel</code>, so an endpoint documented as <code>/api/threats</code> is
        accessed at <code>/sentinel/api/threats</code>. If you set a custom prefix (e.g.,{' '}
        <code>/admin/security</code>), the full path becomes{' '}
        <code>/admin/security/api/threats</code>.
      </p>
      <p>
        All curl examples in this document use <code>http://localhost:8080/sentinel</code> as
        the base URL.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  AUTHENTICATION                                                    */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="authentication">Authentication</h2>
      <p>
        Endpoints for logging in, logging out, and verifying JWT tokens.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/auth/login</code></td>
            <td>Authenticate with username and password. Returns a JWT token. <strong>No auth header required.</strong></td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/auth/logout</code></td>
            <td>Invalidate the current session token.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/auth/verify</code></td>
            <td>Verify that the current token is still valid. Returns HTTP 200 if valid, 401 if not.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Login"
        showLineNumbers={false}
        code={`# Authenticate and obtain a JWT token
curl -X POST http://localhost:8080/sentinel/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "your-password"}'

# Response:
# {"token": "eyJhbGciOiJIUzI1NiIs..."}`}
      />

      <CodeBlock
        language="bash"
        filename="Verify Token"
        showLineNumbers={false}
        code={`# Verify that a token is still valid
curl http://localhost:8080/sentinel/api/auth/verify \\
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        Endpoints that power the main dashboard overview page.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/dashboard/summary</code></td>
            <td>Returns the dashboard summary including total threats, blocked count, active actors, requests per minute, and recent threat events.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/security-score</code></td>
            <td>Returns the computed security score (0-100) with a component-level breakdown showing how each factor contributes to the overall score.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Dashboard Summary"
        showLineNumbers={false}
        code={`curl http://localhost:8080/sentinel/api/dashboard/summary \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  THREATS                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="threats">Threats</h2>
      <p>
        Endpoints for querying, inspecting, and managing threat events.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/threats</code></td>
            <td>List threat events with pagination and filtering. Supports query parameters: <code>page</code>, <code>page_size</code>, <code>severity</code> (low, medium, high, critical), and <code>type</code> (sqli, xss, path_traversal, etc.).</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/threats/:id</code></td>
            <td>Get full details for a specific threat event, including request metadata, matched WAF rule, payload, and geographic information.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/threats/:id/resolve</code></td>
            <td>Mark a threat as reviewed and resolved.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/threats/:id/false-positive</code></td>
            <td>Flag a threat detection as a false positive for tuning.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="List Threats"
        showLineNumbers={false}
        code={`# List high-severity SQL injection threats, page 1
curl "http://localhost:8080/sentinel/api/threats?page=1&page_size=20&severity=high&type=sqli" \\
  -H "Authorization: Bearer <token>"

# Response:
# {
#   "data": [
#     {
#       "id": "abc123",
#       "type": "sqli",
#       "severity": "high",
#       "ip": "203.0.113.42",
#       "route": "/api/users",
#       "blocked": true,
#       "timestamp": "2025-01-15T10:30:00Z"
#     },
#     ...
#   ],
#   "meta": { "total": 47, "page": 1, "page_size": 20 }
# }`}
      />

      <CodeBlock
        language="bash"
        filename="Resolve a Threat"
        showLineNumbers={false}
        code={`# Mark threat abc123 as resolved
curl -X POST http://localhost:8080/sentinel/api/threats/abc123/resolve \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  ACTORS                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="actors">Actors</h2>
      <p>
        Endpoints for viewing threat actor profiles aggregated by IP address.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/actors</code></td>
            <td>List all threat actors with pagination. Supports <code>page</code> and <code>page_size</code> query parameters. Each actor includes risk score, event count, and first/last seen timestamps.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/actors/:ip</code></td>
            <td>Get the full profile for a specific threat actor by IP address, including risk score, severity breakdown, and geographic location.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/actors/:ip/threats</code></td>
            <td>List all threat events associated with a specific actor IP.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/actors/:ip/block</code></td>
            <td>Block an actor by adding their IP to the blacklist immediately.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Block an Actor"
        showLineNumbers={false}
        code={`# Block the actor at 203.0.113.42
curl -X POST http://localhost:8080/sentinel/api/actors/203.0.113.42/block \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  IP MANAGEMENT                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="ip-management">IP Management</h2>
      <p>
        Endpoints for managing IP whitelists and blacklists.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/ip-lists</code></td>
            <td>List all whitelist and blacklist entries with their type, creation timestamp, and reason.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/ip-lists</code></td>
            <td>Add an IP address or CIDR range to the whitelist or blacklist. Body requires <code>ip</code>, <code>type</code> (block or allow), and optional <code>reason</code>.</td>
          </tr>
          <tr>
            <td><code>DELETE</code></td>
            <td><code>/api/ip-lists/:id</code></td>
            <td>Remove an IP entry from the whitelist or blacklist by its ID.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Add IP to Blacklist"
        showLineNumbers={false}
        code={`# Block an IP range
curl -X POST http://localhost:8080/sentinel/api/ip-lists \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"ip": "198.51.100.0/24", "type": "block", "reason": "Known botnet range"}'`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  WAF                                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="waf">WAF</h2>
      <p>
        Endpoints for managing Web Application Firewall rules.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/waf/rules</code></td>
            <td>List all WAF rules including built-in and custom rules. Shows rule ID, name, pattern, severity, enabled status, and strictness level.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/waf/rules</code></td>
            <td>Create a new custom WAF rule. Body requires rule name, regex pattern, severity, and action.</td>
          </tr>
          <tr>
            <td><code>PUT</code></td>
            <td><code>/api/waf/rules/:id</code></td>
            <td>Update an existing WAF rule. Can toggle enabled/disabled status, change pattern, severity, or strictness.</td>
          </tr>
          <tr>
            <td><code>DELETE</code></td>
            <td><code>/api/waf/rules/:id</code></td>
            <td>Delete a custom WAF rule by its ID. Built-in rules cannot be deleted, only disabled.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/waf/test</code></td>
            <td>Test arbitrary input against the active rule set. Returns which rules would match and their details. Useful for validating rules before deployment.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Test WAF Rules"
        showLineNumbers={false}
        code={`# Test an input string against all active WAF rules
curl -X POST http://localhost:8080/sentinel/api/waf/test \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"input": "SELECT * FROM users WHERE id=1 OR 1=1"}'`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  RATE LIMITS                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="rate-limits">Rate Limits</h2>
      <p>
        Endpoints for viewing and managing rate limit configuration and live counter states.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/rate-limits</code></td>
            <td>Get the current rate limit configuration including requests per window, window duration, and per-route overrides.</td>
          </tr>
          <tr>
            <td><code>PUT</code></td>
            <td><code>/api/rate-limits</code></td>
            <td>Update the rate limit configuration. Changes take effect immediately.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/rate-limits/current</code></td>
            <td>Get live counter states showing current window usage per IP, user, route, and global counters.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/rate-limits/reset/:key</code></td>
            <td>Reset a specific rate limit counter by key. Useful for unblocking a legitimate user who hit a limit.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="View Live Counters"
        showLineNumbers={false}
        code={`# Get current rate limit counter states
curl http://localhost:8080/sentinel/api/rate-limits/current \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  AI                                                                */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="ai">AI</h2>
      <p>
        AI-powered analysis endpoints. These require an AI provider (Claude, OpenAI, or Gemini) to
        be configured. If no provider is configured, these endpoints return HTTP 503.
      </p>

      <Callout type="warning" title="AI Provider Required">
        All <code>/api/ai/*</code> endpoints require an AI provider to be configured in your
        Sentinel config. Without one, these endpoints return{' '}
        <code>503 Service Unavailable</code>. See the{' '}
        <a href="/docs/configuration#ai">AI Configuration</a> section for setup instructions.
      </Callout>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/ai/analyze-threat/:id</code></td>
            <td>Perform AI-powered deep analysis of a specific threat event. Returns analysis of the attack vector, potential impact, and recommended mitigations.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/ai/analyze-actor/:ip</code></td>
            <td>Generate an AI assessment of a threat actor's behavior pattern, risk level, and recommended response.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/ai/daily-summary</code></td>
            <td>Get an AI-generated summary of the past 24 hours of security activity with notable trends and recommendations.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/api/ai/query</code></td>
            <td>Ask a natural-language question about your security data. Body requires a <code>query</code> string.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/ai/waf-recommendations</code></td>
            <td>Get AI-generated suggestions for WAF rule improvements based on recent threat data.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="AI Natural Language Query"
        showLineNumbers={false}
        code={`# Ask a question about your security data
curl -X POST http://localhost:8080/sentinel/api/ai/query \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"query": "What were the most common attack types this week?"}'`}
      />

      <CodeBlock
        language="bash"
        filename="Analyze a Threat"
        showLineNumbers={false}
        code={`# Get AI analysis for threat abc123
curl -X POST http://localhost:8080/sentinel/api/ai/analyze-threat/abc123 \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  REPORTS                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="reports">Reports</h2>
      <p>
        Compliance report generation endpoints. Reports are generated on demand based on current
        system state and threat data within the specified time window.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/reports/gdpr</code></td>
            <td>Generate a GDPR compliance report. Supports optional <code>window</code> query parameter (e.g., <code>720h</code> for 30 days). Covers data protection, access logging, retention policies, and breach notification readiness.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/reports/pci-dss</code></td>
            <td>Generate a PCI-DSS compliance report. Covers WAF status, access controls, audit logging, rate limiting on sensitive endpoints, and encryption posture.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/reports/soc2</code></td>
            <td>Generate a SOC 2 compliance report. Supports optional <code>window</code> query parameter. Covers security monitoring, incident response, access management, and anomaly detection.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Generate GDPR Report"
        showLineNumbers={false}
        code={`# Generate a GDPR report for the last 30 days
curl "http://localhost:8080/sentinel/api/reports/gdpr?window=720h" \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  ANALYTICS                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="analytics">Analytics</h2>
      <p>
        Endpoints for security analytics and trend data used by the Analytics dashboard page.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/analytics/trends</code></td>
            <td>Get attack trend data over time. Supports <code>window</code> (e.g., <code>24h</code>, <code>7d</code>) and <code>interval</code> (e.g., <code>hour</code>, <code>day</code>) query parameters. Returns time-series data broken down by attack type.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/analytics/geographic</code></td>
            <td>Get geographic breakdown of threat sources by country with event counts and percentages.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/analytics/top-routes</code></td>
            <td>Get the most targeted routes in your application ranked by attack volume.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/analytics/time-pattern</code></td>
            <td>Get attack distribution by hour of day and day of week to identify automated attack patterns.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Attack Trends"
        showLineNumbers={false}
        code={`# Get hourly attack trends for the last 24 hours
curl "http://localhost:8080/sentinel/api/analytics/trends?window=24h&interval=hour" \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  USERS, AUDIT, ALERTS                                              */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="other">Users, Audit Logs & Alerts</h2>
      <p>
        Endpoints for user tracking, audit trail, and alert management.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/users</code></td>
            <td>List tracked users extracted by your <code>UserExtractor</code> function. Shows request counts, last active timestamps, and associated security events.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/audit-logs</code></td>
            <td>List audit log entries recording all administrative and security actions including dashboard logins, IP list changes, threat resolutions, and WAF rule modifications.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/alerts</code></td>
            <td>List dispatched alert history with timestamps, severity, triggering event, delivery channel, and delivery status.</td>
          </tr>
          <tr>
            <td><code>PUT</code></td>
            <td><code>/api/alerts/config</code></td>
            <td>Update alert configuration including minimum severity threshold and notification channel settings.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  PERFORMANCE                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="performance">Performance</h2>
      <p>
        Endpoints for route-level performance metrics and latency tracking.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/performance/overview</code></td>
            <td>Get an overview of system performance including aggregate latency percentiles, error rates, and throughput metrics.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/api/performance/routes</code></td>
            <td>Get per-route performance metrics including p50, p95, and p99 latency percentiles, error rates, and request counts. Routes exceeding the slow request threshold are flagged.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        filename="Route Performance"
        showLineNumbers={false}
        code={`# Get per-route latency metrics
curl http://localhost:8080/sentinel/api/performance/routes \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  WEBSOCKET                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="websocket">WebSocket</h2>
      <p>
        Sentinel exposes two WebSocket endpoints for real-time streaming. WebSocket connections
        authenticate via the <code>token</code> query parameter rather than the{' '}
        <code>Authorization</code> header, since the browser WebSocket API does not support custom
        headers.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>WS</code></td>
            <td><code>/ws/threats</code></td>
            <td>Streams live threat events as they are detected. Each message is a JSON object with the full threat event payload including IP, route, threat type, severity, and timestamp.</td>
          </tr>
          <tr>
            <td><code>WS</code></td>
            <td><code>/ws/metrics</code></td>
            <td>Streams real-time performance and system metrics including request rates, latency percentiles, active connections, and resource usage.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="WebSocket Authentication">
        Pass the JWT token as a <code>token</code> query parameter when connecting:{' '}
        <code>ws://localhost:8080/sentinel/ws/threats?token=&lt;jwt&gt;</code>. The protocol is
        automatically upgraded to <code>wss:</code> when your application uses HTTPS.
      </Callout>

      <CodeBlock
        language="javascript"
        filename="WebSocket Connection"
        showLineNumbers={false}
        code={`// Connect to the live threat stream
const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(
  \`\${proto}//\${window.location.host}/sentinel/ws/threats?token=\${jwt}\`
);

ws.onmessage = (event) => {
  const threat = JSON.parse(event.data);
  console.log('New threat:', threat.type, threat.severity, threat.ip);
};

ws.onclose = () => {
  // Reconnect with backoff
  setTimeout(() => connect(), 5000);
};`}
      />

      <CodeBlock
        language="bash"
        filename="WebSocket via curl"
        showLineNumbers={false}
        code={`# Connect to WebSocket using curl (for testing)
curl --include \\
  --no-buffer \\
  --header "Connection: Upgrade" \\
  --header "Upgrade: websocket" \\
  --header "Sec-WebSocket-Version: 13" \\
  --header "Sec-WebSocket-Key: $(openssl rand -base64 16)" \\
  "http://localhost:8080/sentinel/ws/threats?token=<jwt>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  QUICK REFERENCE                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="quick-reference">Quick Reference</h2>
      <p>
        Complete endpoint listing at a glance. All paths are relative to your configured prefix
        (default: <code>/sentinel</code>).
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Auth</th>
          </tr>
        </thead>
        <tbody>
          <tr><td><code>POST</code></td><td><code>/api/auth/login</code></td><td>No</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/auth/logout</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/auth/verify</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/dashboard/summary</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/security-score</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/threats</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/threats/:id</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/threats/:id/resolve</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/threats/:id/false-positive</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/actors</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/actors/:ip</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/actors/:ip/threats</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/actors/:ip/block</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/ip-lists</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/ip-lists</code></td><td>Yes</td></tr>
          <tr><td><code>DELETE</code></td><td><code>/api/ip-lists/:id</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/waf/rules</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/waf/rules</code></td><td>Yes</td></tr>
          <tr><td><code>PUT</code></td><td><code>/api/waf/rules/:id</code></td><td>Yes</td></tr>
          <tr><td><code>DELETE</code></td><td><code>/api/waf/rules/:id</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/waf/test</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/rate-limits</code></td><td>Yes</td></tr>
          <tr><td><code>PUT</code></td><td><code>/api/rate-limits</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/rate-limits/current</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/rate-limits/reset/:key</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/ai/analyze-threat/:id</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/ai/analyze-actor/:ip</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/ai/daily-summary</code></td><td>Yes</td></tr>
          <tr><td><code>POST</code></td><td><code>/api/ai/query</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/ai/waf-recommendations</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/reports/gdpr</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/reports/pci-dss</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/reports/soc2</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/analytics/trends</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/analytics/geographic</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/analytics/top-routes</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/analytics/time-pattern</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/users</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/audit-logs</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/alerts</code></td><td>Yes</td></tr>
          <tr><td><code>PUT</code></td><td><code>/api/alerts/config</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/performance/overview</code></td><td>Yes</td></tr>
          <tr><td><code>GET</code></td><td><code>/api/performance/routes</code></td><td>Yes</td></tr>
          <tr><td><code>WS</code></td><td><code>/ws/threats</code></td><td>Token param</td></tr>
          <tr><td><code>WS</code></td><td><code>/ws/metrics</code></td><td>Token param</td></tr>
        </tbody>
      </table>

      <Callout type="success" title="Prefix Applies to All Paths">
        Every path listed above is relative to your configured prefix. The default prefix is{' '}
        <code>/sentinel</code>, so <code>/api/threats</code> becomes{' '}
        <code>/sentinel/api/threats</code>. WebSocket paths follow the same pattern:{' '}
        <code>/ws/threats</code> becomes <code>/sentinel/ws/threats</code>.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/the-dashboard">The Dashboard</a> -- Visual walkthrough of every dashboard page</li>
        <li><a href="/docs/configuration">Configuration</a> -- Full reference for all config fields</li>
        <li><a href="/docs/waf">WAF Deep Dive</a> -- Advanced WAF configuration and custom rules</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> -- Rate limit configuration and strategies</li>
        <li><a href="/docs/alerting">Alerting</a> -- Configure Slack, email, and webhook notifications</li>
      </ul>
    </>
  );
}
