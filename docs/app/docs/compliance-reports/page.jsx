import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = { title: 'Compliance Reports - Sentinel Docs' };

export default function ComplianceReports() {
  return (
    <>
      <h1>Compliance Reports</h1>
      <p>
        Sentinel can generate compliance reports for <strong>GDPR</strong>,{' '}
        <strong>PCI-DSS</strong>, and <strong>SOC 2</strong> directly from your security data.
        Each report aggregates threat events, audit logs, user activity, and access control
        records into a structured document that maps to the requirements of its respective
        compliance framework. Reports are generated on demand through the API or the dashboard
        and can be exported as JSON for integration with external compliance tools.
      </p>

      <Callout type="info" title="No Extra Configuration">
        Compliance reports are generated from data that Sentinel already collects. There is no
        separate configuration to enable them. As long as Sentinel is mounted and processing
        traffic, the report endpoints are available.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  AVAILABLE REPORTS                                                  */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="available-reports">Available Reports</h2>
      <p>
        Sentinel supports three compliance report types. Each report queries different subsets of
        stored data and presents metrics aligned with its compliance framework.
      </p>

      <table>
        <thead>
          <tr>
            <th>Report</th>
            <th>Framework</th>
            <th>Time Window</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>GDPR</strong></td>
            <td>General Data Protection Regulation</td>
            <td>Configurable (default 720h)</td>
            <td>User data access, exports, deletions, and unusual access patterns.</td>
          </tr>
          <tr>
            <td><strong>PCI-DSS</strong></td>
            <td>Payment Card Industry Data Security Standard</td>
            <td>Fixed 90 days</td>
            <td>Authentication events, security incidents, blocked threats, and requirements status.</td>
          </tr>
          <tr>
            <td><strong>SOC 2</strong></td>
            <td>Service Organization Control 2</td>
            <td>Configurable (default 720h)</td>
            <td>Monitoring evidence, incident response, access control, and anomalies.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  GDPR REPORT                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="gdpr-report">GDPR Report</h2>
      <p>
        The GDPR report provides visibility into how user data is accessed, exported, and deleted
        within your application. It also surfaces unusual access patterns detected by the anomaly
        detection engine. This helps demonstrate compliance with GDPR articles related to data
        subject rights, lawful processing, and breach notification.
      </p>

      <h3>Metrics</h3>
      <table>
        <thead>
          <tr>
            <th>Metric</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>total_users</code></td>
            <td>Number of unique users with data access activity in the reporting window.</td>
          </tr>
          <tr>
            <td><code>data_access_events</code></td>
            <td>Total number of data access events across all users.</td>
          </tr>
          <tr>
            <td><code>data_export_events</code></td>
            <td>Number of data export (READ) audit log entries.</td>
          </tr>
          <tr>
            <td><code>data_deletion_events</code></td>
            <td>Number of data deletion (DELETE) audit log entries.</td>
          </tr>
          <tr>
            <td><code>unusual_access_patterns</code></td>
            <td>Anomaly-type threat events indicating suspicious data access behavior.</td>
          </tr>
          <tr>
            <td><code>user_data_summary</code></td>
            <td>Per-user breakdown with user ID, activity count, routes accessed, and last access time.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="json"
        filename="GDPR Response"
        showLineNumbers={false}
        code={`{
  "data": {
    "generated_at": "2025-06-15T10:00:00Z",
    "window_start": "2025-05-16T10:00:00Z",
    "window_end": "2025-06-15T10:00:00Z",
    "total_users": 42,
    "data_access_events": 1580,
    "data_export_events": 12,
    "data_deletion_events": 3,
    "unusual_access_patterns": [
      {
        "id": "te-anom-001",
        "timestamp": "2025-06-10T03:22:00Z",
        "ip": "198.51.100.14",
        "threat_types": ["AnomalyDetected"],
        "severity": "Medium"
      }
    ],
    "user_data_summary": [
      {
        "user_id": "user-abc123",
        "activity_count": 87,
        "routes_accessed": ["/api/users", "/api/profile"],
        "last_seen": "2025-06-15T09:45:00Z"
      }
    ]
  }
}`}
      />

      <Callout type="warning" title="Query Parameter">
        The GDPR report accepts a <code>?window</code> query parameter to control the reporting
        period. The default is <code>720h</code> (30 days). Example:{' '}
        <code>GET /sentinel/api/reports/gdpr?window=2160h</code> for 90 days.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  PCI-DSS REPORT                                                    */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="pci-dss-report">PCI-DSS Report</h2>
      <p>
        The PCI-DSS report focuses on authentication security, incident tracking, and threat
        blocking over a fixed 90-day window. It maps to PCI-DSS requirements around access
        control, monitoring, and incident response. The report includes a requirements status map
        that indicates whether each relevant PCI-DSS requirement is compliant, partially met, or
        non-compliant based on your Sentinel configuration and runtime data.
      </p>

      <h3>Metrics</h3>
      <table>
        <thead>
          <tr>
            <th>Metric</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>auth_events_90d</code></td>
            <td>Total authentication attempts in the last 90 days (success + failure).</td>
          </tr>
          <tr>
            <td><code>failed_logins_90d</code></td>
            <td>Number of failed login attempts in the last 90 days.</td>
          </tr>
          <tr>
            <td><code>security_incidents</code></td>
            <td>Total security incidents (threat events) detected in the last 90 days.</td>
          </tr>
          <tr>
            <td><code>blocked_threats</code></td>
            <td>Number of threats that were actively blocked by the WAF or rate limiter.</td>
          </tr>
          <tr>
            <td><code>requirements</code></td>
            <td>Map of PCI-DSS requirement names to their compliance status: <code>compliant</code>, <code>partial</code>, or <code>non-compliant</code>.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="json"
        filename="PCI-DSS Response"
        showLineNumbers={false}
        code={`{
  "data": {
    "generated_at": "2025-06-15T10:00:00Z",
    "auth_events_90d": 12450,
    "failed_logins_90d": 342,
    "security_incidents": 87,
    "blocked_threats": 76,
    "requirements": {
      "Req 1 - Firewall Configuration": "compliant",
      "Req 2 - Default Passwords": "compliant",
      "Req 6 - Secure Systems": "partial",
      "Req 7 - Access Control": "compliant",
      "Req 8 - Authentication": "compliant",
      "Req 10 - Logging & Monitoring": "compliant",
      "Req 11 - Security Testing": "partial",
      "Req 12 - Security Policy": "non-compliant"
    }
  }
}`}
      />

      <Callout type="info" title="Fixed 90-Day Window">
        The PCI-DSS report always covers the last 90 days. There is no <code>?window</code> query
        parameter for this endpoint. This aligns with PCI-DSS requirements for quarterly review
        periods.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  SOC 2 REPORT                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="soc2-report">SOC 2 Report</h2>
      <p>
        The SOC 2 report provides evidence for the Trust Services Criteria: security, availability,
        and confidentiality. It aggregates monitoring evidence, incident response metrics, access
        control data, and anomaly events into a format suitable for SOC 2 Type II audits.
      </p>

      <h3>Sections</h3>

      <h4>Monitoring Evidence</h4>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>total_events</code></td>
            <td>Total number of security events processed during the reporting window.</td>
          </tr>
          <tr>
            <td><code>threats_detected</code></td>
            <td>Number of threats identified by the detection engine.</td>
          </tr>
          <tr>
            <td><code>threats_blocked</code></td>
            <td>Number of threats actively blocked before reaching the application.</td>
          </tr>
        </tbody>
      </table>

      <h4>Incident Response</h4>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>total_incidents</code></td>
            <td>Total number of security incidents recorded.</td>
          </tr>
          <tr>
            <td><code>resolved</code></td>
            <td>Number of incidents that have been resolved.</td>
          </tr>
          <tr>
            <td><code>avg_response_time</code></td>
            <td>Average time to resolve an incident (human-readable duration).</td>
          </tr>
        </tbody>
      </table>

      <h4>Access Control</h4>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>unique_users</code></td>
            <td>Number of unique users with activity in the reporting window.</td>
          </tr>
          <tr>
            <td><code>auth_events</code></td>
            <td>Total authentication events (logins, logouts, token refreshes).</td>
          </tr>
          <tr>
            <td><code>ip_blocks_active</code></td>
            <td>Number of currently active IP blocks.</td>
          </tr>
        </tbody>
      </table>

      <h4>Anomalies</h4>
      <p>
        A list of anomaly-type threat events detected during the reporting window. Each anomaly
        includes the event ID, timestamp, source IP, severity, and threat type details.
      </p>

      <CodeBlock
        language="json"
        filename="SOC 2 Response"
        showLineNumbers={false}
        code={`{
  "data": {
    "generated_at": "2025-06-15T10:00:00Z",
    "window_start": "2025-05-16T10:00:00Z",
    "window_end": "2025-06-15T10:00:00Z",
    "monitoring_evidence": {
      "total_events": 58420,
      "threats_detected": 134,
      "threats_blocked": 121
    },
    "incident_response": {
      "total_incidents": 134,
      "resolved": 128,
      "avg_response_time": "4m32s"
    },
    "access_control": {
      "unique_users": 67,
      "auth_events": 8930,
      "ip_blocks_active": 14
    },
    "anomalies": [
      {
        "id": "te-anom-042",
        "timestamp": "2025-06-12T18:15:00Z",
        "ip": "203.0.113.88",
        "threat_types": ["AnomalyDetected"],
        "severity": "High"
      }
    ]
  }
}`}
      />

      <Callout type="warning" title="Query Parameter">
        The SOC 2 report accepts a <code>?window</code> query parameter to control the reporting
        period. The default is <code>720h</code> (30 days). Example:{' '}
        <code>GET /sentinel/api/reports/soc2?window=2160h</code> for 90 days.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  API ENDPOINTS                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="api-endpoints">API Endpoints</h2>
      <p>
        All report endpoints are authenticated. Include a valid JWT token in the{' '}
        <code>Authorization</code> header. Each endpoint returns the report data in a{' '}
        <code>{"{ \"data\": ... }"}</code> envelope.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Endpoint</th>
            <th>Query Params</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>GET</code></td>
            <td><code>/sentinel/api/reports/gdpr</code></td>
            <td><code>?window=720h</code></td>
            <td>Generate a GDPR compliance report for the specified time window.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/sentinel/api/reports/pci-dss</code></td>
            <td>None (fixed 90 days)</td>
            <td>Generate a PCI-DSS compliance report for the last 90 days.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/sentinel/api/reports/soc2</code></td>
            <td><code>?window=720h</code></td>
            <td>Generate a SOC 2 compliance report for the specified time window.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  TIME WINDOWS                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="time-windows">Time Windows</h2>
      <p>
        GDPR and SOC 2 reports accept a <code>?window</code> query parameter that controls how far
        back the report looks. The value is a Go-style duration string. If omitted, the default is{' '}
        <code>720h</code> (30 days).
      </p>

      <table>
        <thead>
          <tr>
            <th>Value</th>
            <th>Duration</th>
            <th>Use Case</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>168h</code></td>
            <td>7 days</td>
            <td>Weekly reviews and quick checks on recent activity.</td>
          </tr>
          <tr>
            <td><code>720h</code></td>
            <td>30 days</td>
            <td>Standard monthly compliance reporting. <strong>Default.</strong></td>
          </tr>
          <tr>
            <td><code>2160h</code></td>
            <td>90 days</td>
            <td>Quarterly audits, SOC 2 Type II evidence collection.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="success" title="Custom Windows">
        You can pass any valid Go duration, not just the predefined values. For example,{' '}
        <code>?window=336h</code> produces a 14-day report. If the value cannot be parsed, the
        endpoint falls back to the default 720h window.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        The Sentinel dashboard includes a dedicated Reports page that provides a graphical
        interface for generating compliance reports without using the API directly.
      </p>

      <ul>
        <li>
          <strong>Report type selector</strong> -- choose between GDPR, PCI-DSS, and SOC 2 using
          toggle buttons at the top of the page.
        </li>
        <li>
          <strong>Date range picker</strong> -- select the time window from a dropdown. The
          dropdown is hidden for PCI-DSS since it always covers 90 days.
        </li>
        <li>
          <strong>Generate button</strong> -- click to generate the report on demand. A loading
          indicator is shown while the report is being computed.
        </li>
        <li>
          <strong>Structured display</strong> -- the report is rendered with summary statistics in
          a grid layout, followed by detailed sections (requirements status, user data summary,
          anomaly events, etc.) depending on the report type.
        </li>
        <li>
          <strong>JSON export</strong> -- an Export JSON button appears after a report is generated,
          allowing you to download the report data as a JSON file.
        </li>
      </ul>

      <p>
        Access the Reports page at{' '}
        <code>http://localhost:8080/sentinel/ui</code> and navigate to the Reports section.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  JSON EXPORT                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="json-export">JSON Export</h2>
      <p>
        Both the dashboard and the API return reports as JSON. From the dashboard, clicking the{' '}
        <strong>Export JSON</strong> button downloads the report as a file named{' '}
        <code>sentinel-{'<type>'}-report-{'<date>'}.json</code>, where <code>{'<type>'}</code> is
        the report type (gdpr, pci-dss, or soc2) and <code>{'<date>'}</code> is the current date
        in <code>YYYY-MM-DD</code> format.
      </p>

      <CodeBlock
        language="text"
        showLineNumbers={false}
        code={`sentinel-gdpr-report-2025-06-15.json
sentinel-pci-dss-report-2025-06-15.json
sentinel-soc2-report-2025-06-15.json`}
      />

      <p>
        When consuming reports programmatically via the API, pipe the response through{' '}
        <code>jq</code> to extract the <code>.data</code> field and redirect it to a file:
      </p>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=720h" \\
  | jq '.data' > gdpr-report.json`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing</h2>
      <p>
        Use the following <code>curl</code> commands to generate each report type. Replace{' '}
        <code>{'<token>'}</code> with a valid JWT token obtained from the dashboard login endpoint.
      </p>

      <h3>Generate GDPR Report</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# GDPR report for the last 30 days (default)
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=720h" | jq .

# GDPR report for the last 7 days
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=168h" | jq .

# GDPR report for the last 90 days
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=2160h" | jq .`}
      />

      <h3>Generate PCI-DSS Report</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# PCI-DSS report (always 90 days, no window parameter)
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/pci-dss" | jq .`}
      />

      <h3>Generate SOC 2 Report</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# SOC 2 report for the last 30 days (default)
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/soc2?window=720h" | jq .

# SOC 2 report for the last 90 days
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/soc2?window=2160h" | jq .`}
      />

      <Callout type="info" title="Authentication">
        All report endpoints require authentication. Obtain a JWT token by logging into the
        dashboard at <code>POST /sentinel/api/login</code> with your dashboard credentials. Include
        the token as <code>Authorization: Bearer {'<token>'}</code> in every request.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  REPORT GENERATION INTERNALS                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It Works</h2>
      <p>
        Reports are generated on demand by the <code>reports.Generator</code> struct, which queries
        the storage layer for the relevant data. Each report type has a dedicated generator method
        that assembles data from multiple storage queries into a single response.
      </p>

      <ol>
        <li>
          <strong>GDPR</strong> -- queries user activity, READ/DELETE audit logs, and anomaly-type
          threat events to build the user data access summary and unusual access patterns list.
        </li>
        <li>
          <strong>PCI-DSS</strong> -- queries authentication audit logs, all threat events, and
          blocked threats over a fixed 90-day window. Computes failure rates and maps results to
          PCI-DSS requirement categories.
        </li>
        <li>
          <strong>SOC 2</strong> -- queries threat stats, the security score, resolved incidents,
          audit logs, blocked IPs, and anomaly events to build evidence across monitoring, incident
          response, and access control sections.
        </li>
      </ol>

      <CodeBlock
        language="go"
        filename="reports/compliance.go"
        code={`// Generator produces compliance reports from stored Sentinel data.
type Generator struct {
    store storage.Store
}

// NewGenerator creates a new compliance report generator.
func NewGenerator(store storage.Store) *Generator {
    return &Generator{store: store}
}

// GenerateGDPR produces a GDPR compliance report for the given time window.
func (g *Generator) GenerateGDPR(ctx context.Context, window time.Duration) (*GDPRReport, error) {
    // Queries user activity, audit logs (READ/DELETE), and anomaly threats
    // Returns structured report with per-user summaries
}

// GeneratePCIDSS produces a PCI-DSS compliance report for the last 90 days.
func (g *Generator) GeneratePCIDSS(ctx context.Context) (*PCIDSSReport, error) {
    // Fixed 90-day window, no configurable parameter
    // Queries auth audit logs, all threats, and blocked threats
}

// GenerateSOC2 produces a SOC2 compliance report for the given time window.
func (g *Generator) GenerateSOC2(ctx context.Context, window time.Duration) (*SOC2Report, error) {
    // Queries threat stats, security score, resolved incidents,
    // audit logs, blocked IPs, and anomaly events
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/the-dashboard">Dashboard</a> -- Access the Reports page and generate reports from the UI</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> -- Powers the unusual access patterns in GDPR and anomalies in SOC 2 reports</li>
        <li><a href="/docs/waf">WAF</a> -- Threat events from the WAF feed into PCI-DSS and SOC 2 incident data</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> -- Authentication events that populate PCI-DSS auth metrics</li>
        <li><a href="/docs/security-score">Security Score</a> -- The security score is included in SOC 2 monitoring evidence</li>
        <li><a href="/docs/alerting">Alerting</a> -- Configure real-time alerts alongside periodic compliance reporting</li>
      </ul>
    </>
  );
}
