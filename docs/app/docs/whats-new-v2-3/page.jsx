import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = {
  title: "What's New in v2.3 - Sentinel Docs",
  description:
    'Sentinel v2.1–v2.3 release notes: settings and dashboard controls that silently did nothing now work, user activity, audit trail, honest compliance reports, and the v2.2.2 security fixes.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-3',
  },
  openGraph: {
    title: "What's New in v2.3 - Sentinel Docs",
    description:
      'Settings and dashboard controls that silently did nothing now work, plus the v2.2.2 security fixes and an upgrade checklist.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-3',
    type: 'article',
  },
};

export default function WhatsNewV23() {
  return (
    <>
      <h1>What's New in v2.1 – v2.3</h1>
      <p>
        The releases since v2.0.0 share one theme: configuration and dashboard controls that
        compiled, read as correct, and silently did nothing. v2.2.0 added a way to detect that class
        of bug; v2.2.2 fixed security holes found while auditing for it; v2.3.0 made the remaining
        dead settings work. Full details are in{' '}
        <a href="https://github.com/MUKE-coder/sentinel/blob/main/CHANGELOG.md">CHANGELOG.md</a>.
      </p>

      <Callout type="warning" title="Read before upgrading to v2.3.0">
        Rate limits become a real sliding window, audit logs are kept for a year, and compliance
        reports on in-memory storage are refused in release mode. See the{' '}
        <a href="#upgrade">upgrade checklist</a>.
      </Callout>

      <h2 id="v2-3-0">v2.3.0 — settings that did nothing now work</h2>

      <h3>Dashboard edits reach the running middleware</h3>
      <p>
        Changing the WAF mode or rules, route rate limits, or alert severity from the dashboard used
        to update only the API server's copy of the config — enforcement never changed while the
        dashboard showed the new values. Those edits now apply to live requests immediately, are
        validated (bad input returns 400 and changes nothing), and are audited. They are not
        persisted: a restart returns to your configured values.
      </p>

      <h3>WAF sensitivity, rule actions, and rate-limit strategies are enforced</h3>
      <ul>
        <li>
          <code>WAF.Rules</code> levels were never read. <code>RuleOff</code>, <code>RuleLow</code>,{' '}
          <code>RuleMedium</code>, and <code>RuleStrict</code> now change detection — see{' '}
          <a href="/docs/waf#built-in-rules">Strictness Levels</a>. The defaults keep every pattern.
        </li>
        <li>
          <code>WAFRule.Action: "log"</code> records a custom rule's matches without ever blocking,
          even in block mode — watch a new rule against real traffic before trusting it.
        </li>
        <li>
          <code>RateLimit.Strategy</code> was never read; every limit was a fixed window.{' '}
          <code>SlidingWindow</code> (default), <code>FixedWindow</code>, and <code>TokenBucket</code>{' '}
          are now real — see <a href="/docs/rate-limiting#how-it-works">How It Works</a>.
        </li>
      </ul>

      <h3>User activity is recorded</h3>
      <p>
        <code>Config.UserExtractor</code> was never read, so no user activity was stored — the Users
        page, the GDPR report's per-user section, and anomaly detection all saw nothing. It now
        records one entry per authenticated request.
      </p>
      <CodeBlock
        language="go"
        code={`UserExtractor: func(c *gin.Context) *sentinel.UserContext {
    claims, ok := c.Get("claims") // set by your auth middleware
    if !ok {
        return nil // anonymous: not recorded
    }
    u := claims.(*MyClaims)
    return &sentinel.UserContext{ID: u.Subject, Email: u.Email}
},`}
      />

      <h3>An audit trail for Sentinel itself</h3>
      <p>
        Every dashboard action — IP blocks, WAF and rate-limit changes, custom rules, lockout
        releases, threat triage — and every login (dashboard logins, and app logins AuthShield
        observes) is an audit entry. Audit logs keep their own retention,{' '}
        <code>Storage.AuditRetentionDays</code>, default 365. See{' '}
        <a href="/docs/audit-logging#sentinel-entries">Dashboard Actions and Logins</a>.
      </p>

      <h3>Honest compliance reports</h3>
      <p>
        Every report carries a <code>provenance</code> block — storage driver, durability, retention,
        oldest records, and warnings when the data can't support the report. Reports on in-memory
        storage are refused in release mode. The SQLite and Postgres user and analytics queries,
        which were stubs returning nothing, are implemented. See{' '}
        <a href="/docs/compliance-reports">Compliance Reports</a>.
      </p>

      <h2 id="v2-2-2">v2.2.2 — security fixes</h2>
      <ul>
        <li>
          <strong>Client IP spoofing behind a proxy.</strong> The leftmost{' '}
          <code>X-Forwarded-For</code> entry — which the client writes — was trusted. The chain is
          now read right to left past your <code>WAF.TrustedProxies</code>.
        </li>
        <li>
          <strong>Dashboard login brute-force limit</strong> could be reset by rotating{' '}
          <code>X-Forwarded-For</code>; it now uses the same trusted-proxy logic.
        </li>
        <li>
          <strong>SQL injection via <code>sort_by</code></strong> on threat listings (SQLite /
          Postgres) is closed by an allowlist.
        </li>
        <li>
          <strong>SSRF client bypasses</strong> — <code>[::]</code>, NAT64 / 6to4-embedded internal
          addresses, zoned and IPv4-mapped IPv6 literals, Oracle Cloud metadata, trailing-dot
          metadata hostnames — are blocked, and <code>AllowedHosts</code> works for internal hosts.
        </li>
        <li>
          <strong>Compliance report counts</strong> — PCI-DSS blocked threats filtered on the wrong
          field; SOC 2's blocked count could never exceed 1.
        </li>
      </ul>

      <h2 id="v2-2-0">v2.2.0 — <code>ValidateConfig</code></h2>
      <p>
        <code>sentinel.ValidateConfig(cfg)</code> returns every setting that would be silently
        ignored or would silently disable a feature — unknown storage drivers, unmatchable route
        patterns, broken custom rules, alert sinks without credentials, and, since v2.3.0, unknown
        WAF modes, sensitivity levels, rule actions, and rate-limit strategies. <code>Mount</code>{' '}
        logs the findings; call it yourself to fail a deploy.
      </p>
      <CodeBlock
        language="go"
        code={`for _, issue := range sentinel.ValidateConfig(cfg) {
    if issue.Severity == sentinel.IssueError {
        log.Fatalf("sentinel config: %s", issue)
    }
}`}
      />

      <h2 id="v2-1">v2.1.x — WAF false positives and wildcard routes</h2>
      <ul>
        <li>The SSRF pattern no longer matches browser version strings such as <code>Chrome/140.0.0.0</code>, which had blocked every Chromium user in block mode.</li>
        <li>SQL-injection patterns no longer match opaque tokens or scan headers.</li>
        <li><code>WAF.ExcludeRoutes</code> and <code>RateLimit.ByRoute</code> accept wildcard patterns (<code>/v1/*</code>, <code>/api/apps/*/products/**</code>).</li>
        <li>WebSocket endpoints require a dashboard token; dashboard IP blocks default to 24 hours.</li>
      </ul>

      <h2 id="upgrade">Upgrade checklist</h2>
      <ol>
        <li>
          If you run behind a reverse proxy, set <code>WAF.TrustedProxies</code> to its addresses.
          Blocks keyed on spoofed client IPs stop matching after v2.2.2 — that is the point.
        </li>
        <li>
          Rate limiting is a sliding window by default from v2.3.0. For the old behavior set{' '}
          <code>Strategy: sentinel.FixedWindow</code>.
        </li>
        <li>
          If any <code>WAF.Rules</code> category is set to Off, Low, or Medium, check that you
          still want it — those levels now change detection.
        </li>
        <li>
          Audit logs are kept 365 days by default. Lower <code>Storage.AuditRetentionDays</code> if
          disk is tight (PCI-DSS requires 12 months).
        </li>
        <li>Set <code>UserExtractor</code> if you want the Users page, GDPR user data, and anomaly detection.</li>
        <li>Remove <code>AI.DailySummary</code> — it is deprecated and never did anything.</li>
        <li>
          Run <code>sentinel.ValidateConfig</code> in CI and treat <code>IssueError</code> as a
          failed build.
        </li>
      </ol>
    </>
  );
}
