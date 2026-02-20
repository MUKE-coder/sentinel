import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = { title: 'Dashboard - Sentinel Docs' };

export default function TheDashboard() {
  return (
    <>
      <h1>The Dashboard</h1>
      <p>
        Sentinel ships with a fully embedded React security dashboard that gives you real-time
        visibility into every aspect of your application's security posture. The dashboard is built
        with React 19, Vite, TailwindCSS 4, Recharts, and React Router, and is served directly
        from your Go binary at <code>/sentinel/ui</code> — no separate frontend deployment required.
      </p>
      <p>
        The entire UI uses a dark theme optimized for security operations. All assets are compiled
        into your Go binary via <code>go:embed</code>, so the dashboard works out of the box with
        zero external dependencies at runtime.
      </p>

      <Callout type="info" title="Enabled by Default">
        The dashboard is enabled by default when you call <code>sentinel.Mount()</code>. Navigate
        to <code>http://localhost:8080/sentinel/ui</code> to access it. You can disable it by
        setting <code>DashboardConfig.Enabled</code> to <code>false</code>.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  AUTHENTICATION                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="authentication">Authentication</h2>
      <p>
        The dashboard is protected by JWT-based authentication. When you access the UI, you are
        presented with a login screen that accepts a username and password. These credentials are
        configured in the <code>DashboardConfig</code> struct.
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    Dashboard: sentinel.DashboardConfig{
        Username:  "admin",
        Password:  "s3cur3-p4ss!",
        SecretKey: "my-jwt-secret-change-in-production",
    },
})`}
      />

      <p>
        On successful login, the server returns a JWT token. The React app stores this token
        exclusively in React state (via <code>useState</code> inside an <code>AuthContext</code>
        provider) — it is never written to <code>localStorage</code>, <code>sessionStorage</code>,
        or cookies. This means the token is automatically cleared when the browser tab is closed or
        the page is refreshed, providing a secure session model that is immune to XSS-based token
        theft from persistent storage.
      </p>

      <p>
        Every subsequent API call includes the token in the <code>Authorization: Bearer</code>{' '}
        header. If the token expires or becomes invalid, the API responds with HTTP 401 and the
        dashboard automatically redirects to the login page.
      </p>

      <Callout type="warning" title="Change Default Credentials">
        The default username is <code>admin</code> and the default password is{' '}
        <code>sentinel</code>. Always change these in production. The <code>SecretKey</code> is used
        to sign JWT tokens — if compromised, an attacker can forge dashboard sessions.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  PAGES OVERVIEW                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="pages">Pages Overview</h2>
      <p>
        The dashboard contains 13 pages, each focused on a specific aspect of your security
        operations. All pages are accessible from the sidebar navigation after logging in.
      </p>

      <table>
        <thead>
          <tr>
            <th>Page</th>
            <th>Route</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Dashboard</strong></td>
            <td><code>/sentinel/ui</code></td>
            <td>Security overview with security score ring chart, real-time threat timeline, stat cards, and a live event feed powered by WebSocket.</td>
          </tr>
          <tr>
            <td><strong>Threats</strong></td>
            <td><code>/sentinel/ui/threats</code></td>
            <td>Searchable, filterable threat log with pagination. Click any row to open a detail modal. Actions include resolve and mark as false positive.</td>
          </tr>
          <tr>
            <td><strong>Actors</strong></td>
            <td><code>/sentinel/ui/actors</code></td>
            <td>Threat actor profiles aggregated by IP. Shows risk scores, total events, first/last seen timestamps, and a block action to immediately blacklist an actor.</td>
          </tr>
          <tr>
            <td><strong>IP Management</strong></td>
            <td><code>/sentinel/ui/ip-management</code></td>
            <td>Whitelist and blacklist management. Add individual IPs or CIDR ranges. View active entries with creation timestamps and notes.</td>
          </tr>
          <tr>
            <td><strong>WAF</strong></td>
            <td><code>/sentinel/ui/waf</code></td>
            <td>WAF rule management. View built-in and custom rules, toggle rules on/off, create custom rules, and test arbitrary input against the active rule set.</td>
          </tr>
          <tr>
            <td><strong>Rate Limits</strong></td>
            <td><code>/sentinel/ui/rate-limits</code></td>
            <td>Rate limit configuration editor. View live counter states with auto-refresh, see current window usage per IP/user/route, and reset individual counters.</td>
          </tr>
          <tr>
            <td><strong>Analytics</strong></td>
            <td><code>/sentinel/ui/analytics</code></td>
            <td>Visual security analytics: attack trends area chart, threat type distribution pie chart, top targeted routes bar chart, geographic origin breakdown, time-of-day patterns, and security score component breakdown.</td>
          </tr>
          <tr>
            <td><strong>AI Insights</strong></td>
            <td><code>/sentinel/ui/ai-insights</code></td>
            <td>AI-powered analysis: daily security summary, natural-language query interface, threat event analysis, threat actor assessment, and WAF rule recommendations.</td>
          </tr>
          <tr>
            <td><strong>Reports</strong></td>
            <td><code>/sentinel/ui/reports</code></td>
            <td>Compliance report generators for GDPR, PCI-DSS, and SOC 2 frameworks. Generate reports on demand and export as JSON.</td>
          </tr>
          <tr>
            <td><strong>Alerts</strong></td>
            <td><code>/sentinel/ui/alerts</code></td>
            <td>Alert configuration management and alert history. View past alerts with timestamps, severity, channel, and delivery status.</td>
          </tr>
          <tr>
            <td><strong>Audit Log</strong></td>
            <td><code>/sentinel/ui/audit</code></td>
            <td>Full audit trail of all actions taken within the dashboard and security system. Tracks who did what and when.</td>
          </tr>
          <tr>
            <td><strong>Performance</strong></td>
            <td><code>/sentinel/ui/performance</code></td>
            <td>Route-level latency metrics with p50, p95, and p99 percentiles. Error rates per route and slow request tracking.</td>
          </tr>
          <tr>
            <td><strong>Users</strong></td>
            <td><code>/sentinel/ui/users</code></td>
            <td>User activity tracking. Shows authenticated users, their request counts, last active timestamps, and associated security events.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD (OVERVIEW)                                               */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-dashboard">Dashboard (Overview)</h3>
      <p>
        The main Dashboard page is the landing page after login. It provides a high-level snapshot
        of your security posture with four key components:
      </p>
      <ul>
        <li>
          <strong>Security Score Ring</strong> — A donut chart that displays your overall security
          score (0-100). The score is computed from WAF coverage, rate limiting configuration,
          threat resolution rate, and other factors.
        </li>
        <li>
          <strong>Stat Cards</strong> — Summary cards showing total threats in the last 24 hours,
          blocked vs. logged counts, active threat actors, and requests per minute.
        </li>
        <li>
          <strong>Threat Timeline</strong> — A table of the most recent threat events with IP,
          route, threat type, severity, timestamp, and blocked status.
        </li>
        <li>
          <strong>Live WebSocket Feed</strong> — New threat events appear in real time via a
          WebSocket connection. The page refreshes its data automatically when a new threat arrives.
        </li>
      </ul>

      {/* ------------------------------------------------------------------ */}
      {/*  THREATS                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-threats">Threats</h3>
      <p>
        The Threats page is a paginated, searchable log of every threat event Sentinel has recorded.
        You can filter by severity, threat type, IP address, time range, and blocked status. Clicking
        a row opens a detail modal showing the full request metadata, matched WAF rule, payload, and
        geographic information.
      </p>
      <p>
        Actions available on each threat:
      </p>
      <ul>
        <li><strong>Resolve</strong> — Mark the threat as reviewed and resolved.</li>
        <li><strong>False Positive</strong> — Flag the detection as a false positive for tuning.</li>
      </ul>

      {/* ------------------------------------------------------------------ */}
      {/*  ACTORS                                                             */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-actors">Actors</h3>
      <p>
        The Actors page aggregates threat data by source IP to build threat actor profiles. Each
        profile includes a computed risk score, total event count, severity breakdown, first and last
        seen timestamps, and geographic location. You can block an actor directly from this page,
        which adds their IP to the blacklist immediately.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  IP MANAGEMENT                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-ip-management">IP Management</h3>
      <p>
        The IP Management page provides a unified interface for managing your whitelist and
        blacklist. You can add individual IP addresses or CIDR ranges (e.g.,{' '}
        <code>10.0.0.0/8</code>, <code>192.168.1.0/24</code>). Each entry supports an optional
        note describing why the IP was listed. Whitelisted IPs bypass all security checks including
        the WAF and rate limiting.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  WAF                                                                */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-waf">WAF</h3>
      <p>
        The WAF page provides full rule management. You can view all built-in rules with their
        current strictness levels, toggle individual rules on or off, create new custom rules with
        regex patterns, and test arbitrary input against the active rule set to see which rules
        would match before deploying changes.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  RATE LIMITS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-rate-limits">Rate Limits</h3>
      <p>
        The Rate Limits page shows the current rate limiting configuration and live counter states.
        Counters auto-refresh to show real-time usage for each IP, user, route, and global limit.
        You can reset individual counters from the UI — useful for unblocking a legitimate user
        who hit a limit.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  ANALYTICS                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-analytics">Analytics</h3>
      <p>
        The Analytics page provides six visualization panels:
      </p>
      <ul>
        <li>
          <strong>Attack Trends</strong> — A stacked area chart showing threat volume over time,
          broken down by attack type. Supports configurable time windows and intervals.
        </li>
        <li>
          <strong>Threat Distribution</strong> — A pie chart showing the proportion of each attack
          type (SQLi, XSS, Path Traversal, etc.) over the selected period.
        </li>
        <li>
          <strong>Top Targeted Routes</strong> — A horizontal bar chart ranking the most attacked
          routes in your application.
        </li>
        <li>
          <strong>Geographic Origin</strong> — A breakdown of threat sources by country, showing
          which geographic regions generate the most attack traffic.
        </li>
        <li>
          <strong>Time Patterns</strong> — Analysis of when attacks occur by hour of day and day of
          week, helping identify automated attack campaigns.
        </li>
        <li>
          <strong>Security Score Breakdown</strong> — A component-level view of your security score
          showing how each factor (WAF, rate limiting, threat resolution, etc.) contributes to the
          overall number.
        </li>
      </ul>

      {/* ------------------------------------------------------------------ */}
      {/*  AI INSIGHTS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-ai-insights">AI Insights</h3>
      <p>
        The AI Insights page requires an AI provider to be configured (Claude, OpenAI, or Gemini).
        It offers five capabilities:
      </p>
      <ul>
        <li>
          <strong>Daily Summary</strong> — An AI-generated summary of the past 24 hours of security
          activity, highlighting notable trends and recommendations.
        </li>
        <li>
          <strong>Natural Language Query</strong> — Ask questions about your security data in plain
          English (e.g., "What were the most common attack types this week?").
        </li>
        <li>
          <strong>Threat Analysis</strong> — Select a specific threat event for AI-powered deep
          analysis of the attack vector, potential impact, and recommended mitigations.
        </li>
        <li>
          <strong>Actor Assessment</strong> — Generate an AI assessment of a threat actor's
          behavior pattern, risk level, and recommended response.
        </li>
        <li>
          <strong>WAF Recommendations</strong> — Get AI-generated suggestions for WAF rule
          improvements based on your recent threat data.
        </li>
      </ul>

      <Callout type="info" title="AI is Optional">
        If no AI provider is configured, the AI Insights page displays a message indicating that AI
        analysis is not available. All other dashboard pages work fully without AI.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  REPORTS                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-reports">Reports</h3>
      <p>
        The Reports page generates compliance reports for three frameworks:
      </p>
      <table>
        <thead>
          <tr>
            <th>Framework</th>
            <th>What It Covers</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>GDPR</strong></td>
            <td>Data protection impact assessments, access logging, data retention policies, and breach notification readiness.</td>
          </tr>
          <tr>
            <td><strong>PCI-DSS</strong></td>
            <td>WAF status, access controls, audit logging, rate limiting on sensitive endpoints, and encryption posture.</td>
          </tr>
          <tr>
            <td><strong>SOC 2</strong></td>
            <td>Security monitoring coverage, incident response workflow, access management, and anomaly detection status.</td>
          </tr>
        </tbody>
      </table>
      <p>
        Reports are generated on demand and can be exported as JSON for ingestion into external
        compliance tooling or record-keeping systems.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  ALERTS                                                             */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-alerts">Alerts</h3>
      <p>
        The Alerts page has two sections: configuration and history. The configuration panel shows
        the current alert settings (minimum severity threshold and configured channels). The history
        panel displays a log of all dispatched alerts with timestamps, severity, the triggering
        event, the delivery channel (Slack, email, webhook), and delivery status.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  AUDIT LOG                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-audit">Audit Log</h3>
      <p>
        The Audit Log page provides a complete trail of all administrative and security actions.
        This includes dashboard logins, IP whitelist/blacklist changes, threat resolutions,
        WAF rule modifications, rate limit resets, and report generations. Each entry records the
        action, the actor (dashboard user or system), a timestamp, and relevant metadata.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  PERFORMANCE                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-performance">Performance</h3>
      <p>
        The Performance page displays route-level latency metrics. For each route in your
        application, it shows:
      </p>
      <ul>
        <li><strong>p50 (median)</strong> — The 50th percentile response time.</li>
        <li><strong>p95</strong> — The 95th percentile response time (tail latency).</li>
        <li><strong>p99</strong> — The 99th percentile response time (worst-case latency).</li>
        <li><strong>Error Rate</strong> — The percentage of responses with non-2xx status codes.</li>
      </ul>
      <p>
        Routes exceeding the <code>SlowRequestThreshold</code> (default 2 seconds) are highlighted.
        This page helps you correlate security events with performance degradation — for example,
        identifying routes under active attack that are experiencing elevated latency.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  USERS                                                              */}
      {/* ------------------------------------------------------------------ */}

      <h3 id="page-users">Users</h3>
      <p>
        The Users page tracks authenticated user activity. It shows each user extracted by your{' '}
        <code>UserExtractor</code> function, their total request count, last active timestamp,
        associated security events, and any anomaly flags. This page requires a{' '}
        <code>UserExtractor</code> to be configured in order to display user-level data.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  CUSTOMIZING THE PREFIX                                             */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="customizing-prefix">Customizing the Prefix</h2>
      <p>
        By default, the dashboard is served at <code>/sentinel/ui</code> and the API at{' '}
        <code>/sentinel/api/*</code>. You can change this by setting{' '}
        <code>DashboardConfig.Prefix</code>:
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    Dashboard: sentinel.DashboardConfig{
        Prefix:   "/admin/security",
        Username: "secops",
        Password: "change-me-in-production",
    },
})`}
      />

      <p>
        With this configuration:
      </p>

      <table>
        <thead>
          <tr>
            <th>Resource</th>
            <th>Default Path</th>
            <th>Custom Path</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Dashboard UI</td>
            <td><code>/sentinel/ui</code></td>
            <td><code>/admin/security/ui</code></td>
          </tr>
          <tr>
            <td>API Endpoints</td>
            <td><code>/sentinel/api/*</code></td>
            <td><code>/admin/security/api/*</code></td>
          </tr>
          <tr>
            <td>Auth Login</td>
            <td><code>/sentinel/api/auth/login</code></td>
            <td><code>/admin/security/api/auth/login</code></td>
          </tr>
          <tr>
            <td>WebSocket (Threats)</td>
            <td><code>/sentinel/ws/threats</code></td>
            <td><code>/admin/security/ws/threats</code></td>
          </tr>
          <tr>
            <td>WebSocket (Metrics)</td>
            <td><code>/sentinel/ws/metrics</code></td>
            <td><code>/admin/security/ws/metrics</code></td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Prefix Must Start with a Slash">
        The prefix must start with a forward slash and should not end with one. For example,{' '}
        <code>/sentinel</code> is correct, while <code>sentinel/</code> is not.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  BUILDING THE DASHBOARD                                             */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="building">Building the Dashboard</h2>
      <p>
        The React dashboard source code lives in the <code>ui/dashboard/</code> directory of the
        Sentinel repository. It is a standard Vite project with React and TailwindCSS. The
        production build output goes into <code>ui/dist/</code>, which is embedded into the Go
        binary via <code>go:embed</code>.
      </p>

      <CodeBlock
        language="bash"
        filename="ui/dashboard/"
        showLineNumbers={false}
        code={`# Install dependencies
npm install

# Run development server (with hot reload)
npm run dev

# Build for production
npm run build`}
      />

      <p>
        The Go embedding is handled by <code>ui/frontend.go</code>:
      </p>

      <CodeBlock
        language="go"
        filename="ui/frontend.go"
        code={`package ui

import (
    "embed"
    "io/fs"
)

//go:embed dist
var distFS embed.FS

// DistFS returns a sub-filesystem rooted at the dist directory.
func DistFS() (fs.FS, error) {
    return fs.Sub(distFS, "dist")
}`}
      />

      <p>
        When you build your Go application with <code>go build</code>, the compiled React assets in{' '}
        <code>ui/dist/</code> are automatically included in the binary. There is no need for a
        separate static file server or CDN — the dashboard is fully self-contained.
      </p>

      <Callout type="success" title="Pre-Built Assets Included">
        You only need to run <code>npm run build</code> if you are modifying the dashboard source
        code. The Sentinel repository ships with pre-built assets in <code>ui/dist/</code>, so the
        dashboard works out of the box when you install Sentinel as a Go module.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  WEBSOCKET                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="websocket">WebSocket Streams</h2>
      <p>
        The dashboard uses two WebSocket endpoints for real-time data. Both require a valid JWT
        token passed as a <code>token</code> query parameter. The connections automatically
        reconnect with a 5-second backoff if disconnected.
      </p>

      <table>
        <thead>
          <tr>
            <th>Endpoint</th>
            <th>Default Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Threats</td>
            <td><code>/sentinel/ws/threats</code></td>
            <td>Streams live threat events as they are detected. Each message is a JSON object with the full threat event payload including IP, route, threat type, severity, and timestamp.</td>
          </tr>
          <tr>
            <td>Metrics</td>
            <td><code>/sentinel/ws/metrics</code></td>
            <td>Streams real-time performance and system metrics. Includes request rates, latency percentiles, active connections, and resource usage.</td>
          </tr>
        </tbody>
      </table>

      <p>
        The WebSocket connection URL is constructed dynamically based on the current page protocol
        and host:
      </p>

      <CodeBlock
        language="javascript"
        filename="Connection URL"
        showLineNumbers={false}
        code={`// Protocol is auto-detected (ws: for http, wss: for https)
const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const url = \`\${proto}//\${window.location.host}/sentinel/ws/threats?token=\${jwt}\`;`}
      />

      <Callout type="info" title="WebSocket Authentication">
        WebSocket connections authenticate via the <code>token</code> query parameter rather than
        the <code>Authorization</code> header, since the browser WebSocket API does not support
        custom headers. The token is the same JWT obtained from the login endpoint.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration#dashboard">Dashboard Configuration</a> — Full reference for <code>DashboardConfig</code> fields</li>
        <li><a href="/docs/waf">WAF Deep Dive</a> — Advanced WAF configuration and custom rules</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> — Configure rate limits visible in the dashboard</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Behavioral analysis feeding dashboard insights</li>
        <li><a href="/docs/threat-intelligence">Threat Intelligence</a> — IP reputation data displayed in actor profiles</li>
      </ul>
    </>
  );
}
