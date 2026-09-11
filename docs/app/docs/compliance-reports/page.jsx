import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Compliance Reports - Sentinel Docs',
  description:
    'Generate GDPR, PCI-DSS, and SOC 2 evidence reports from your Sentinel security data, with provenance showing how far the data can be trusted.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/compliance-reports',
  },
  openGraph: {
    title: 'Compliance Reports - Sentinel Docs',
    description:
      'Generate GDPR, PCI-DSS, and SOC 2 evidence reports from your Sentinel security data, with provenance showing how far the data can be trusted.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/compliance-reports',
    siteName: 'Sentinel',
    type: 'article',
  },
};

export default function ComplianceReports() {
  return (
    <>
      <FAQSchema
        faqs={[
          {
            question: 'What compliance report types does Sentinel support?',
            answer: 'Sentinel generates three evidence reports: GDPR (per-user data access, exports, deletions, unusual access), PCI-DSS (authentication events, security incidents, blocked threats over 90 days), and SOC 2 (monitoring evidence, incident response, access control, anomalies). They collect evidence; they do not assess compliance.',
          },
          {
            question: 'How do I generate a GDPR report in Sentinel?',
            answer: 'Call GET /sentinel/api/reports/gdpr with an optional ?window query parameter (default 720h for 30 days). The per-user section needs Config.UserExtractor to be set, because that is what records user activity.',
          },
          {
            question: 'Can I trust an empty section in a Sentinel report?',
            answer: 'Check the provenance block first. Every report says which storage driver produced it, whether that storage survives a restart, how long data is retained, the oldest stored records, and warnings when the data cannot support the report — so an empty section can be told apart from a clean record.',
          },
          {
            question: 'Can Sentinel compliance reports be exported as JSON?',
            answer: 'Yes. The API returns reports as JSON, and the dashboard has an Export JSON button that downloads sentinel-<type>-report-<date>.json.',
          },
        ]}
      />
      <TechArticleSchema
        title="Compliance Reports - Sentinel Docs"
        description="Generate GDPR, PCI-DSS, and SOC 2 evidence reports from your Sentinel security data, with provenance showing how far the data can be trusted."
        url="https://sentinel-go-sdk.vercel.app/docs/compliance-reports"
      />
      <SpeakableSchema url="https://sentinel-go-sdk.vercel.app/docs/compliance-reports" />

      <h1>Compliance Reports</h1>
      <p>
        Sentinel generates <strong>GDPR</strong>, <strong>PCI-DSS</strong>, and <strong>SOC 2</strong>{' '}
        reports from the security data it records: threat events, audit logs, user activity, and IP
        blocks. Reports are generated on demand through the API or the dashboard and returned as JSON.
      </p>

      <Callout type="warning" title="Evidence, not an assessment">
        These reports collect evidence an auditor will ask for. They do not evaluate compliance — no
        report computes a requirement status or a pass/fail verdict — and they only contain what
        Sentinel has recorded. Read each report's <code>provenance</code> block before relying on it.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  DATA SOURCES                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="data-sources">Where the Data Comes From</h2>
      <p>
        A report section can only be as complete as the component that feeds it. If a feeder isn't
        configured, its section is empty — and an empty section means <em>no data</em>, not a clean
        record.
      </p>

      <table>
        <thead>
          <tr>
            <th>Section</th>
            <th>Recorded by</th>
            <th>Requires</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>GDPR <code>user_data_access</code>, SOC 2 <code>total_users</code></td>
            <td>User activity, one entry per authenticated request</td>
            <td><code>Config.UserExtractor</code> (v2.3.0+)</td>
          </tr>
          <tr>
            <td>GDPR <code>data_deletions</code></td>
            <td><code>DELETE</code> audit entries from the GORM plugin</td>
            <td>Pass your <code>*gorm.DB</code> to <code>Mount</code></td>
          </tr>
          <tr>
            <td>GDPR <code>data_exports</code></td>
            <td><code>READ</code> audit entries</td>
            <td>Your application writing them — the GORM plugin records CREATE, UPDATE, and DELETE only</td>
          </tr>
          <tr>
            <td>GDPR <code>unusual_access</code>, SOC 2 <code>anomaly_events</code></td>
            <td>Anomaly detection</td>
            <td><code>Anomaly.Enabled</code> and <code>UserExtractor</code></td>
          </tr>
          <tr>
            <td>PCI-DSS <code>auth_events</code></td>
            <td>Login audit entries (<code>Resource: "auth"</code>) — logins AuthShield observes on your app, and dashboard logins</td>
            <td><code>AuthShield.Enabled</code> with a <code>LoginRoute</code> for app logins (v2.3.0+)</td>
          </tr>
          <tr>
            <td>PCI-DSS incidents and blocked threats, SOC 2 monitoring evidence</td>
            <td>Threat events from the WAF, rate limiter, AuthShield, and anomaly detection</td>
            <td>The WAF or other detectors enabled</td>
          </tr>
          <tr>
            <td>SOC 2 <code>incident_response</code></td>
            <td>Threats marked resolved in the dashboard</td>
            <td>Operators triaging threats</td>
          </tr>
          <tr>
            <td>SOC 2 <code>access_control.audit_logs</code></td>
            <td>Every audit entry, including dashboard actions (v2.3.0+)</td>
            <td>—</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  PROVENANCE                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="provenance">Provenance and Truncation</h2>
      <p>
        Every report carries a <code>provenance</code> block (v2.3.0+) describing the data behind it:
      </p>

      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>storage_driver</code></td>
            <td><code>sqlite</code>, <code>postgres</code>, or <code>memory</code>.</td>
          </tr>
          <tr>
            <td><code>durable</code></td>
            <td><code>true</code> only for SQLite and Postgres — data that survives a restart.</td>
          </tr>
          <tr>
            <td><code>retention_days</code>, <code>audit_retention_days</code></td>
            <td>How long threat/activity records and audit entries are kept before deletion.</td>
          </tr>
          <tr>
            <td><code>oldest_threat_event</code>, <code>oldest_audit_entry</code></td>
            <td>The earliest records in storage.</td>
          </tr>
          <tr>
            <td><code>warnings</code></td>
            <td>
              Every reason the data may not support the report: in-memory storage, a window longer
              than retention, a window that starts before the oldest stored record, an empty store,
              audit retention under PCI-DSS's 12 months, no <code>UserExtractor</code>, no source of{' '}
              <code>READ</code> entries.
            </td>
          </tr>
        </tbody>
      </table>

      <p>
        List sections are capped (500 to 5,000 rows depending on the section). When a list hits its
        cap, its name appears in the report's <code>truncated</code> array. Summary counts come from
        aggregate queries and stay exact either way.
      </p>

      <Callout type="warning" title="In-memory storage is refused in release mode">
        With <code>Storage.Driver: sentinel.Memory</code> in <code>gin.ReleaseMode</code>, the report
        endpoints return <strong>409</strong> with code <code>EPHEMERAL_STORAGE</code>: that data is
        lost on every restart, so a report would cover only the time since the last deploy while
        reading as a complete record. Pass <code>?acknowledge_ephemeral=true</code> to generate it
        anyway.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  AVAILABLE REPORTS                                                  */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="available-reports">Available Reports</h2>
      <table>
        <thead>
          <tr>
            <th>Report</th>
            <th>Endpoint</th>
            <th>Time Window</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>GDPR</strong></td>
            <td><code>GET /sentinel/api/reports/gdpr</code></td>
            <td><code>?window=</code>, default <code>720h</code></td>
          </tr>
          <tr>
            <td><strong>PCI-DSS</strong></td>
            <td><code>GET /sentinel/api/reports/pci-dss</code></td>
            <td>Fixed 90 days</td>
          </tr>
          <tr>
            <td><strong>SOC 2</strong></td>
            <td><code>GET /sentinel/api/reports/soc2</code></td>
            <td><code>?window=</code>, default <code>720h</code></td>
          </tr>
        </tbody>
      </table>
      <p>
        Every endpoint requires a dashboard token and wraps the report in a{' '}
        <code>{'{ "data": ... }'}</code> envelope. <code>window</code> takes any Go duration
        (<code>168h</code>, <code>336h</code>, <code>2160h</code>); an unparseable value falls back to{' '}
        <code>720h</code>.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  GDPR REPORT                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="gdpr-report">GDPR Report</h2>
      <p>
        How user data was accessed, exported, and deleted in the window, plus anomalous access.
      </p>

      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Contents</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>user_data_access</code></td>
            <td>Per user: <code>user_id</code>, <code>routes_accessed</code> (route patterns), <code>access_count</code>, <code>last_access</code>.</td>
          </tr>
          <tr>
            <td><code>data_exports</code></td>
            <td><code>READ</code> audit entries.</td>
          </tr>
          <tr>
            <td><code>data_deletions</code></td>
            <td><code>DELETE</code> audit entries, with the deleted record's before-state.</td>
          </tr>
          <tr>
            <td><code>unusual_access</code></td>
            <td><code>AnomalyDetected</code> threat events.</td>
          </tr>
          <tr>
            <td><code>summary</code></td>
            <td><code>total_users</code>, <code>total_data_accesses</code>, <code>total_exports</code>, <code>total_deletions</code>, <code>unusual_access_count</code>.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="json"
        filename="GDPR Response (abridged)"
        showLineNumbers={false}
        code={`{
  "data": {
    "generated_at": "2026-09-11T10:00:00Z",
    "window_start": "2026-08-12T10:00:00Z",
    "window_end": "2026-09-11T10:00:00Z",
    "user_data_access": [
      {
        "user_id": "user-abc123",
        "routes_accessed": ["/api/profile", "/api/orders/:id"],
        "access_count": 87,
        "last_access": "2026-09-11T09:45:00Z"
      }
    ],
    "data_exports": [],
    "data_deletions": [ { "action": "DELETE", "resource": "customers", "resource_id": "412", "...": "..." } ],
    "unusual_access": [],
    "summary": {
      "total_users": 42,
      "total_data_accesses": 1580,
      "total_exports": 0,
      "total_deletions": 3,
      "unusual_access_count": 0
    },
    "provenance": {
      "storage_driver": "sqlite",
      "durable": true,
      "retention_days": 90,
      "audit_retention_days": 365,
      "oldest_threat_event": "2026-06-14T08:02:11Z",
      "oldest_audit_entry": "2026-06-14T08:05:40Z",
      "warnings": [
        "data_exports lists READ audit entries, which Sentinel's GORM plugin does not record (it records CREATE, UPDATE, and DELETE): the section stays empty unless your application writes READ entries itself."
      ]
    }
  }
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  PCI-DSS REPORT                                                    */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="pci-dss-report">PCI-DSS Report</h2>
      <p>
        Authentication activity, security incidents, and blocked threats over the last 90 days.
      </p>

      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Contents</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>auth_events</code></td>
            <td><code>total_attempts</code>, <code>success_count</code>, <code>failure_count</code>, <code>failure_rate</code> (percent), from login audit entries.</td>
          </tr>
          <tr>
            <td><code>security_incidents</code></td>
            <td>Every threat event in the window, newest first.</td>
          </tr>
          <tr>
            <td><code>blocked_threats</code></td>
            <td>Threat events Sentinel blocked.</td>
          </tr>
          <tr>
            <td><code>summary</code></td>
            <td><code>total_incidents</code>, <code>critical_incidents</code>, <code>high_incidents</code>, <code>blocked_count</code>, <code>unique_attacker_ips</code>.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Audit retention">
        PCI-DSS 10.5.1 requires 12 months of audit history. <code>Storage.AuditRetentionDays</code>{' '}
        defaults to 365; set lower and the report's provenance says so.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  SOC 2 REPORT                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="soc2-report">SOC 2 Report</h2>
      <p>
        Monitoring, incident-response, and access-control evidence for the window.
      </p>

      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Contents</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>monitoring_evidence</code></td>
            <td><code>total_events_processed</code> (threat events recorded in the window), <code>threat_stats</code> (counts by severity, blocked, unique IPs, top attack types), <code>security_score</code>.</td>
          </tr>
          <tr>
            <td><code>incident_response</code></td>
            <td>Threat events marked resolved.</td>
          </tr>
          <tr>
            <td><code>access_control</code></td>
            <td><code>total_users</code>, <code>audit_logs</code> (every audit entry in the window, including dashboard actions and logins), <code>blocked_ips</code>.</td>
          </tr>
          <tr>
            <td><code>anomaly_events</code></td>
            <td><code>AnomalyDetected</code> threat events.</td>
          </tr>
          <tr>
            <td><code>summary</code></td>
            <td><code>total_threats_detected</code>, <code>total_threats_blocked</code>, <code>total_anomalies</code>, <code>total_audit_entries</code>, <code>active_blocked_ips</code>.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Fixed in v2.2.2">
        Before v2.2.2 the PCI-DSS <code>blocked_threats</code> list filtered on the wrong field, the
        SOC 2 blocked count could never exceed 1, and <code>total_events_processed</code> was a
        meaningless sum. Reports generated by older versions should not be relied on.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD & EXPORT                                                */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard and JSON Export</h2>
      <p>
        The dashboard's Reports page lets you pick a report type and window, generate it, and export
        it with the <strong>Export JSON</strong> button as{' '}
        <code>sentinel-{'<type>'}-report-{'<date>'}.json</code>. From the API, extract the{' '}
        <code>.data</code> field:
      </p>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`TOKEN=$(curl -s -X POST http://localhost:8080/sentinel/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"<your-password>"}' | jq -r .token)

curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=720h" | jq '.data' > gdpr-report.json

curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/reports/pci-dss" | jq '.data.provenance'`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  PROGRAMMATIC                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">Generating Reports in Code</h2>
      <p>
        Reports come from <code>reports.Generator</code>, which queries any <code>storage.Store</code>.
        Tell it about the store with <code>SetSourceInfo</code> so the provenance block can describe
        it; without that, reports warn that durability and retention are unknown.
      </p>

      <CodeBlock
        language="go"
        filename="report.go"
        code={`gen := reports.NewGenerator(store)
gen.SetSourceInfo(reports.SourceInfo{
    StorageDriver:        "postgres",
    RetentionDays:        90,
    AuditRetentionDays:   365,
    UserActivityRecorded: true, // Config.UserExtractor is set
})

report, err := gen.GenerateSOC2(ctx, 30*24*time.Hour)
if err != nil {
    return err
}
for _, w := range report.Provenance.Warnings {
    log.Println("report warning:", w)
}`}
      />

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration#user-extractor">User Extractor</a> -- Record the user activity the GDPR report needs</li>
        <li><a href="/docs/audit-logging">Audit Logging</a> -- The audit entries behind exports, deletions, and logins</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> -- Powers unusual access (GDPR) and anomaly events (SOC 2)</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> -- Records the login attempts in PCI-DSS auth events</li>
        <li><a href="/docs/security-score">Security Score</a> -- Included in SOC 2 monitoring evidence</li>
      </ul>
    </>
  );
}
