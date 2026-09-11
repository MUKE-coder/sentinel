import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'API Reference - Sentinel Docs',
  description:
    'REST API reference for Sentinel: threats, actors, IP blocks, WAF, rate limits, users, audit logs, AI, compliance reports, analytics, and WebSocket streams.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/api-reference',
  },
  openGraph: {
    title: 'API Reference - Sentinel Docs',
    description:
      'REST API reference for Sentinel: threats, actors, IP blocks, WAF, rate limits, users, audit logs, AI, compliance reports, analytics, and WebSocket streams.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/api-reference',
    siteName: 'Sentinel',
    type: 'article',
  },
};

function Endpoints({ rows }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Method</th>
          <th>Path</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([method, path, description]) => (
          <tr key={method + path}>
            <td><code>{method}</code></td>
            <td><code>{path}</code></td>
            <td>{description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function ApiReference() {
  return (
    <>
      <FAQSchema
        faqs={[
          {
            question: 'How do I authenticate with the Sentinel API?',
            answer: 'Call POST /sentinel/api/auth/login with your dashboard username and password as JSON. The response contains a JWT valid for 24 hours. Send it as an Authorization: Bearer <token> header on every other API request.',
          },
          {
            question: 'What is the base URL for the Sentinel API?',
            answer: 'All API paths are relative to your configured prefix, which defaults to /sentinel. The threats endpoint is /sentinel/api/threats; with a custom prefix like /admin/security it becomes /admin/security/api/threats.',
          },
          {
            question: 'How is pagination handled in the Sentinel API?',
            answer: 'Paginated list endpoints return a data array and a meta object with total, page, and page_size. Use the page and page_size query parameters; the default page size is 20.',
          },
          {
            question: 'Does Sentinel have WebSocket endpoints for real-time data?',
            answer: 'Yes: /ws/threats, /ws/metrics, and /ws/alerts. Browsers cannot set headers on WebSocket connections, so pass the JWT as a token query parameter.',
          },
        ]}
      />
      <TechArticleSchema
        title="API Reference - Sentinel Docs"
        description="REST API reference for Sentinel: threats, actors, IP blocks, WAF, rate limits, users, audit logs, AI, compliance reports, analytics, and WebSocket streams."
        url="https://sentinel-go-sdk.vercel.app/docs/api-reference"
      />
      <SpeakableSchema url="https://sentinel-go-sdk.vercel.app/docs/api-reference" />

      <h1>API Reference</h1>
      <p>
        Every HTTP and WebSocket endpoint the Sentinel dashboard API exposes. Paths are relative to
        your configured prefix (default <code>/sentinel</code>), so <code>/api/threats</code> is served
        at <code>/sentinel/api/threats</code>. Examples use <code>http://localhost:8080/sentinel</code>.
      </p>

      <Callout type="info" title="Authentication">
        Every endpoint except <code>POST /api/auth/login</code>, <code>POST /api/auth/logout</code>,
        and <code>POST /csp-report</code> requires <code>Authorization: Bearer &lt;token&gt;</code>. A
        missing, expired, or invalid token returns <code>401</code>.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      <h2 id="response-format">Response Format</h2>
      <p>Paginated lists wrap results in <code>data</code> with a <code>meta</code> object:</p>
      <CodeBlock
        language="json"
        filename="Paginated Response"
        showLineNumbers={false}
        code={`{
  "data": [ ... ],
  "meta": { "total": 142, "page": 1, "page_size": 20 }
}`}
      />
      <p>Single resources come back as <code>{'{ "data": { ... } }'}</code>; actions return a message:</p>
      <CodeBlock
        language="json"
        filename="Action and Error Responses"
        showLineNumbers={false}
        code={`{ "message": "Threat resolved" }

{ "error": "Invalid credentials", "code": "UNAUTHORIZED" }`}
      />
      <p>
        Errors use standard status codes with an <code>error</code> message and a machine-readable{' '}
        <code>code</code> such as <code>BAD_REQUEST</code>, <code>NOT_FOUND</code>,{' '}
        <code>RATE_LIMITED</code>, <code>WAF_DISABLED</code>, or <code>EPHEMERAL_STORAGE</code>.
      </p>

      {/* ------------------------------------------------------------------ */}
      <h2 id="authentication">Authentication</h2>
      <Endpoints
        rows={[
          ['POST', '/api/auth/login', <>Exchange <code>{'{"username","password"}'}</code> for a JWT (<code>{'{"token","expires_in":86400}'}</code>). Limited to 10 attempts per 15 minutes per client IP; every attempt is written to the audit log.</>],
          ['POST', '/api/auth/logout', 'Returns success. Tokens are stateless and are not revoked — discard the token client-side.'],
          ['GET', '/api/auth/verify', 'Returns 200 if the token is valid, 401 if not.'],
        ]}
      />
      <CodeBlock
        language="bash"
        filename="Login"
        showLineNumbers={false}
        code={`TOKEN=$(curl -s -X POST http://localhost:8080/sentinel/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "your-password"}' | jq -r .token)`}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="threats">Threats</h2>
      <Endpoints
        rows={[
          ['GET', '/api/threats', <>Paginated threat events. Filters: <code>severity</code> (<code>Low</code>, <code>Medium</code>, <code>High</code>, <code>Critical</code>), <code>type</code> (e.g. <code>SQLi</code>, <code>XSS</code>), <code>ip</code>, <code>search</code> (path, IP, User-Agent), <code>start_time</code> / <code>end_time</code> (RFC 3339). Sort: <code>sort_by</code> = <code>timestamp</code> | <code>severity</code> | <code>ip</code> | <code>path</code>, <code>sort_order</code> = <code>asc</code> | <code>desc</code>.</>],
          ['GET', '/api/threats/:id', 'One threat event with its evidence, request metadata, CVSS score, and location.'],
          ['POST', '/api/threats/:id/resolve', 'Mark a threat resolved. Audited.'],
          ['POST', '/api/threats/:id/false-positive', 'Mark a threat as a false positive (and resolved). Audited.'],
        ]}
      />
      <CodeBlock
        language="bash"
        filename="List Threats"
        showLineNumbers={false}
        code={`curl "http://localhost:8080/sentinel/api/threats?severity=High&type=SQLi&page=1&page_size=20" \\
  -H "Authorization: Bearer $TOKEN"

# {
#   "data": [
#     {
#       "id": "3f9c...",
#       "timestamp": "2026-09-11T10:30:00Z",
#       "ip": "203.0.113.42",
#       "method": "GET",
#       "path": "/api/users",
#       "threat_types": ["SQLi"],
#       "severity": "High",
#       "confidence": 80,
#       "blocked": true,
#       "cvss": 9.8,
#       ...
#     }
#   ],
#   "meta": { "total": 47, "page": 1, "page_size": 20 }
# }`}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="actors">Actors and IP Blocks</h2>
      <Endpoints
        rows={[
          ['GET', '/api/actors', <>Paginated threat actors (one per source IP). Filters: <code>status</code>, <code>search</code>, <code>min_risk</code>.</>],
          ['GET', '/api/actors/:ip', 'One actor profile: risk score, counts, attack types, targeted routes, location.'],
          ['GET', '/api/actors/:ip/requests', 'Paginated threat events from one IP.'],
          ['POST', '/api/actors/:ip/block', <>Block the actor's IP. Optional body <code>{'{"reason","permanent"}'}</code>; blocks last 24 hours unless <code>permanent</code> is true. Audited.</>],
          ['GET', '/api/ip/blocked', 'Every blocked IP and CIDR with reason and expiry.'],
          ['POST', '/api/ip/block', <>Block an IP or CIDR. Body <code>{'{"ip","reason","expiry","permanent"}'}</code>; <code>expiry</code> is RFC 3339, default 24 hours. Audited.</>],
          ['DELETE', '/api/ip/block/:ip', <>Unblock. Write a CIDR with <code>_</code> for <code>/</code> (<code>10.0.0.0_8</code>). Audited.</>],
          ['GET', '/api/ip/:ip/reputation', 'AbuseIPDB lookup (cached 24 hours). Blocks the IP when AutoBlock is on and the score clears MinAbuseScore.'],
        ]}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="waf">WAF</h2>
      <Endpoints
        rows={[
          ['GET', '/api/waf/rules', <>The running WAF's <code>mode</code> and per-category <code>rules</code> (sensitivity levels), and whether the WAF is <code>enabled</code>.</>],
          ['PUT', '/api/waf/rules', <>Change the running WAF: body <code>{'{"mode":"block","rules":{"SQLInjection":"strict"}}'}</code>. Rule fields you omit keep their value. Invalid mode or level → 400; WAF disabled → 409 <code>WAF_DISABLED</code>. Applies immediately, not persisted across restart. Audited.</>],
          ['GET', '/api/waf/custom-rules', 'All custom rules.'],
          ['POST', '/api/waf/custom-rules', <>Add a custom rule: <code>id</code>, <code>name</code>, <code>pattern</code>, <code>applies_to</code>, <code>severity</code>, <code>action</code> (<code>block</code> or <code>log</code>), <code>enabled</code>. Invalid regex or action → 400. Audited.</>],
          ['DELETE', '/api/waf/custom-rules/:id', 'Remove a custom rule. Audited.'],
          ['POST', '/api/waf/test', <>Test a string against the built-in patterns and custom rules: body <code>{'{"payload":"..."}'}</code>. Returns each match with pattern, threat type, location, severity, and confidence.</>],
        ]}
      />
      <CodeBlock
        language="bash"
        filename="Switch the running WAF to block mode"
        showLineNumbers={false}
        code={`curl -X PUT http://localhost:8080/sentinel/api/waf/rules \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"mode": "block", "rules": {"OpenRedirect": "off"}}'

curl -X POST http://localhost:8080/sentinel/api/waf/test \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"payload": "1 UNION SELECT password FROM users"}'`}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="rate-limits">Rate Limits</h2>
      <Endpoints
        rows={[
          ['GET', '/api/rate-limits', <>Configuration in effect: <code>enabled</code>, <code>strategy</code>, <code>by_ip</code>, <code>by_user</code>, <code>global</code>, and the live <code>by_route</code> table.</>],
          ['PUT', '/api/rate-limits', <>Change route limits on the running limiter: body <code>{'{"by_route":{"/api/search":{"requests":10,"window":"1m"}}}'}</code>. <code>requests: 0</code> removes a route's limit. Every entry is validated first and the update is all-or-nothing (400 on a bad window, missing leading <code>/</code>, or unmatchable pattern); rate limiting disabled → 409 <code>RATE_LIMIT_DISABLED</code>. Not persisted across restart. Audited.</>],
          ['GET', '/api/rate-limits/current', <>Active counters: <code>key</code>, <code>count</code> (usage now), <code>limit</code>, <code>remaining</code>, <code>window_end</code>.</>],
          ['POST', '/api/rate-limits/reset/:key', 'Delete one counter so the client can send again immediately. Audited.'],
        ]}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="users-audit">Users, Audit Logs, and AuthShield</h2>
      <Endpoints
        rows={[
          ['GET', '/api/users', <>Users seen by your <code>UserExtractor</code>: activity count, threat count, last seen. Empty without an extractor.</>],
          ['GET', '/api/users/:user_id/activity', <>Paginated activity for one user; <code>start_time</code> / <code>end_time</code> filters.</>],
          ['GET', '/api/users/:user_id/threats', 'Paginated threats attributed to one user.'],
          ['GET', '/api/audit-logs', <>Paginated audit entries — GORM data changes, dashboard actions, logins. Filters: <code>user_id</code>, <code>action</code>, <code>resource</code>, <code>start_time</code>, <code>end_time</code>. Read-only: there is no endpoint to edit or delete an entry.</>],
          ['GET', '/api/auth-shield/status', 'Per-IP AuthShield state: failed attempts, lockout, CAPTCHA tier.'],
          ['POST', '/api/auth/unblock-user/:username', 'Lift an AuthShield lockout for a username. Audited.'],
        ]}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="alerts">Alerts</h2>
      <Endpoints
        rows={[
          ['GET', '/api/alerts/config', 'The alert threshold in effect and which channels are configured (URLs masked).'],
          ['PUT', '/api/alerts/config', <>Change the running dispatcher's threshold: <code>{'{"min_severity":"High"}'}</code> (<code>Low</code>, <code>Medium</code>, <code>High</code>, <code>Critical</code>; any case). Unknown value → 400. Not persisted across restart. Audited.</>],
          ['POST', '/api/alerts/test', 'Report how many providers are configured (does not deliver an alert).'],
          ['GET', '/api/alerts/history', 'The last 1,000 delivery attempts with channel, outcome, and error.'],
        ]}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="ai">AI</h2>
      <p>
        Without an AI provider configured, these return <code>200</code> with{' '}
        <code>{'{"data": null, "message": "AI not configured"}'}</code>. See{' '}
        <a href="/docs/ai-analysis#data-handling">what each call sends</a> to the provider.
      </p>
      <Endpoints
        rows={[
          ['POST', '/api/ai/analyze-threat/:id', 'Plain-English analysis of one threat event.'],
          ['GET', '/api/ai/analyze-actor/:ip', "Assessment of an actor's intent, sophistication, and risk."],
          ['GET', '/api/ai/daily-summary', 'Summary of the last 24 hours from aggregate statistics.'],
          ['POST', '/api/ai/query', <>Ask a question about your security data: <code>{'{"query":"..."}'}</code>.</>],
          ['GET', '/api/ai/waf-recommendations', 'Suggested custom rules from recent attack patterns.'],
        ]}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="reports">Compliance Reports</h2>
      <Endpoints
        rows={[
          ['GET', '/api/reports/gdpr', <>GDPR evidence for <code>window</code> (Go duration, default <code>720h</code>).</>],
          ['GET', '/api/reports/pci-dss', 'PCI-DSS evidence for the last 90 days.'],
          ['GET', '/api/reports/soc2', <>SOC 2 evidence for <code>window</code> (default <code>720h</code>).</>],
        ]}
      />
      <p>
        Each report includes a <code>provenance</code> block and a <code>truncated</code> list. On
        in-memory storage in release mode they return 409 <code>EPHEMERAL_STORAGE</code> unless{' '}
        <code>acknowledge_ephemeral=true</code> is passed. Field-by-field contents are in{' '}
        <a href="/docs/compliance-reports">Compliance Reports</a>.
      </p>

      {/* ------------------------------------------------------------------ */}
      <h2 id="analytics">Score, Analytics, and Performance</h2>
      <Endpoints
        rows={[
          ['GET', '/api/score', 'The security score (0–100) with grade, sub-scores, and recommendations.'],
          ['GET', '/api/analytics/summary', 'Overview figures for the dashboard home page.'],
          ['GET', '/api/analytics/attack-trends', <>Threats per period with per-type counts. <code>window</code> (default <code>168h</code>), <code>interval</code> = <code>hour</code> | <code>day</code>.</>],
          ['GET', '/api/analytics/geographic', <>Threat counts by country. <code>window</code> (default <code>168h</code>).</>],
          ['GET', '/api/analytics/top-targets', <>Most attacked route/method pairs. <code>window</code>, <code>limit</code> (default 10).</>],
          ['GET', '/api/csp-violations/stats', 'Aggregated CSP violation reports.'],
          ['GET', '/api/performance/overview', 'Aggregate latency percentiles, error rate, throughput, and pipeline emitted/dropped counters.'],
          ['GET', '/api/performance/routes', 'Per-route latency percentiles, error rates, and request counts.'],
        ]}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="csp-report">CSP Report Receiver</h2>
      <Endpoints
        rows={[
          ['POST', '/csp-report', 'Receives browser CSP violation reports (legacy and Reporting API formats). No token — browsers do not send one. Limited to 100 reports per minute per client IP.'],
        ]}
      />

      {/* ------------------------------------------------------------------ */}
      <h2 id="websocket">WebSocket</h2>
      <p>
        Browsers can't set headers on a WebSocket, so pass the JWT as a <code>token</code> query
        parameter: <code>ws://localhost:8080/sentinel/ws/threats?token=&lt;jwt&gt;</code>. Connections
        without a valid token are refused.
      </p>
      <Endpoints
        rows={[
          ['WS', '/ws/threats', 'Pipeline events as they happen, including every threat event.'],
          ['WS', '/ws/metrics', 'Live performance and system metrics.'],
          ['WS', '/ws/alerts', 'The same event stream, for the alerts view.'],
        ]}
      />
      <CodeBlock
        language="javascript"
        filename="WebSocket Connection"
        showLineNumbers={false}
        code={`const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(
  \`\${proto}//\${window.location.host}/sentinel/ws/threats?token=\${jwt}\`
);
ws.onmessage = (event) => console.log(JSON.parse(event.data));`}
      />

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/the-dashboard">The Dashboard</a> -- The UI built on these endpoints</li>
        <li><a href="/docs/configuration">Configuration</a> -- Every config field</li>
        <li><a href="/docs/waf">WAF</a> -- Modes, sensitivity levels, and custom rules</li>
        <li><a href="/docs/compliance-reports">Compliance Reports</a> -- Report contents and provenance</li>
      </ul>
    </>
  );
}
