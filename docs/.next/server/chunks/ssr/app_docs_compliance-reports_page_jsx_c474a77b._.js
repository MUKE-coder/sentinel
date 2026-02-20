module.exports=[21153,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Compliance Reports"}),(0,b.jsxs)("p",{children:["Sentinel can generate compliance reports for ",(0,b.jsx)("strong",{children:"GDPR"}),","," ",(0,b.jsx)("strong",{children:"PCI-DSS"}),", and ",(0,b.jsx)("strong",{children:"SOC 2"})," directly from your security data. Each report aggregates threat events, audit logs, user activity, and access control records into a structured document that maps to the requirements of its respective compliance framework. Reports are generated on demand through the API or the dashboard and can be exported as JSON for integration with external compliance tools."]}),(0,b.jsx)(d.default,{type:"info",title:"No Extra Configuration",children:"Compliance reports are generated from data that Sentinel already collects. There is no separate configuration to enable them. As long as Sentinel is mounted and processing traffic, the report endpoints are available."}),(0,b.jsx)("h2",{id:"available-reports",children:"Available Reports"}),(0,b.jsx)("p",{children:"Sentinel supports three compliance report types. Each report queries different subsets of stored data and presents metrics aligned with its compliance framework."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Report"}),(0,b.jsx)("th",{children:"Framework"}),(0,b.jsx)("th",{children:"Time Window"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"GDPR"})}),(0,b.jsx)("td",{children:"General Data Protection Regulation"}),(0,b.jsx)("td",{children:"Configurable (default 720h)"}),(0,b.jsx)("td",{children:"User data access, exports, deletions, and unusual access patterns."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"PCI-DSS"})}),(0,b.jsx)("td",{children:"Payment Card Industry Data Security Standard"}),(0,b.jsx)("td",{children:"Fixed 90 days"}),(0,b.jsx)("td",{children:"Authentication events, security incidents, blocked threats, and requirements status."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"SOC 2"})}),(0,b.jsx)("td",{children:"Service Organization Control 2"}),(0,b.jsx)("td",{children:"Configurable (default 720h)"}),(0,b.jsx)("td",{children:"Monitoring evidence, incident response, access control, and anomalies."})]})]})]}),(0,b.jsx)("h2",{id:"gdpr-report",children:"GDPR Report"}),(0,b.jsx)("p",{children:"The GDPR report provides visibility into how user data is accessed, exported, and deleted within your application. It also surfaces unusual access patterns detected by the anomaly detection engine. This helps demonstrate compliance with GDPR articles related to data subject rights, lawful processing, and breach notification."}),(0,b.jsx)("h3",{children:"Metrics"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Metric"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"total_users"})}),(0,b.jsx)("td",{children:"Number of unique users with data access activity in the reporting window."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"data_access_events"})}),(0,b.jsx)("td",{children:"Total number of data access events across all users."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"data_export_events"})}),(0,b.jsx)("td",{children:"Number of data export (READ) audit log entries."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"data_deletion_events"})}),(0,b.jsx)("td",{children:"Number of data deletion (DELETE) audit log entries."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"unusual_access_patterns"})}),(0,b.jsx)("td",{children:"Anomaly-type threat events indicating suspicious data access behavior."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"user_data_summary"})}),(0,b.jsx)("td",{children:"Per-user breakdown with user ID, activity count, routes accessed, and last access time."})]})]})]}),(0,b.jsx)(c.default,{language:"json",filename:"GDPR Response",showLineNumbers:!1,code:`{
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
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Query Parameter",children:["The GDPR report accepts a ",(0,b.jsx)("code",{children:"?window"})," query parameter to control the reporting period. The default is ",(0,b.jsx)("code",{children:"720h"})," (30 days). Example:"," ",(0,b.jsx)("code",{children:"GET /sentinel/api/reports/gdpr?window=2160h"})," for 90 days."]}),(0,b.jsx)("h2",{id:"pci-dss-report",children:"PCI-DSS Report"}),(0,b.jsx)("p",{children:"The PCI-DSS report focuses on authentication security, incident tracking, and threat blocking over a fixed 90-day window. It maps to PCI-DSS requirements around access control, monitoring, and incident response. The report includes a requirements status map that indicates whether each relevant PCI-DSS requirement is compliant, partially met, or non-compliant based on your Sentinel configuration and runtime data."}),(0,b.jsx)("h3",{children:"Metrics"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Metric"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"auth_events_90d"})}),(0,b.jsx)("td",{children:"Total authentication attempts in the last 90 days (success + failure)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"failed_logins_90d"})}),(0,b.jsx)("td",{children:"Number of failed login attempts in the last 90 days."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"security_incidents"})}),(0,b.jsx)("td",{children:"Total security incidents (threat events) detected in the last 90 days."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"blocked_threats"})}),(0,b.jsx)("td",{children:"Number of threats that were actively blocked by the WAF or rate limiter."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"requirements"})}),(0,b.jsxs)("td",{children:["Map of PCI-DSS requirement names to their compliance status: ",(0,b.jsx)("code",{children:"compliant"}),", ",(0,b.jsx)("code",{children:"partial"}),", or ",(0,b.jsx)("code",{children:"non-compliant"}),"."]})]})]})]}),(0,b.jsx)(c.default,{language:"json",filename:"PCI-DSS Response",showLineNumbers:!1,code:`{
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
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Fixed 90-Day Window",children:["The PCI-DSS report always covers the last 90 days. There is no ",(0,b.jsx)("code",{children:"?window"})," query parameter for this endpoint. This aligns with PCI-DSS requirements for quarterly review periods."]}),(0,b.jsx)("h2",{id:"soc2-report",children:"SOC 2 Report"}),(0,b.jsx)("p",{children:"The SOC 2 report provides evidence for the Trust Services Criteria: security, availability, and confidentiality. It aggregates monitoring evidence, incident response metrics, access control data, and anomaly events into a format suitable for SOC 2 Type II audits."}),(0,b.jsx)("h3",{children:"Sections"}),(0,b.jsx)("h4",{children:"Monitoring Evidence"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"total_events"})}),(0,b.jsx)("td",{children:"Total number of security events processed during the reporting window."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"threats_detected"})}),(0,b.jsx)("td",{children:"Number of threats identified by the detection engine."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"threats_blocked"})}),(0,b.jsx)("td",{children:"Number of threats actively blocked before reaching the application."})]})]})]}),(0,b.jsx)("h4",{children:"Incident Response"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"total_incidents"})}),(0,b.jsx)("td",{children:"Total number of security incidents recorded."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"resolved"})}),(0,b.jsx)("td",{children:"Number of incidents that have been resolved."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"avg_response_time"})}),(0,b.jsx)("td",{children:"Average time to resolve an incident (human-readable duration)."})]})]})]}),(0,b.jsx)("h4",{children:"Access Control"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"unique_users"})}),(0,b.jsx)("td",{children:"Number of unique users with activity in the reporting window."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"auth_events"})}),(0,b.jsx)("td",{children:"Total authentication events (logins, logouts, token refreshes)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ip_blocks_active"})}),(0,b.jsx)("td",{children:"Number of currently active IP blocks."})]})]})]}),(0,b.jsx)("h4",{children:"Anomalies"}),(0,b.jsx)("p",{children:"A list of anomaly-type threat events detected during the reporting window. Each anomaly includes the event ID, timestamp, source IP, severity, and threat type details."}),(0,b.jsx)(c.default,{language:"json",filename:"SOC 2 Response",showLineNumbers:!1,code:`{
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
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Query Parameter",children:["The SOC 2 report accepts a ",(0,b.jsx)("code",{children:"?window"})," query parameter to control the reporting period. The default is ",(0,b.jsx)("code",{children:"720h"})," (30 days). Example:"," ",(0,b.jsx)("code",{children:"GET /sentinel/api/reports/soc2?window=2160h"})," for 90 days."]}),(0,b.jsx)("h2",{id:"api-endpoints",children:"API Endpoints"}),(0,b.jsxs)("p",{children:["All report endpoints are authenticated. Include a valid JWT token in the"," ",(0,b.jsx)("code",{children:"Authorization"})," header. Each endpoint returns the report data in a"," ",(0,b.jsx)("code",{children:'{ "data": ... }'})," envelope."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Method"}),(0,b.jsx)("th",{children:"Endpoint"}),(0,b.jsx)("th",{children:"Query Params"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"/sentinel/api/reports/gdpr"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"?window=720h"})}),(0,b.jsx)("td",{children:"Generate a GDPR compliance report for the specified time window."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"/sentinel/api/reports/pci-dss"})}),(0,b.jsx)("td",{children:"None (fixed 90 days)"}),(0,b.jsx)("td",{children:"Generate a PCI-DSS compliance report for the last 90 days."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"/sentinel/api/reports/soc2"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"?window=720h"})}),(0,b.jsx)("td",{children:"Generate a SOC 2 compliance report for the specified time window."})]})]})]}),(0,b.jsx)("h2",{id:"time-windows",children:"Time Windows"}),(0,b.jsxs)("p",{children:["GDPR and SOC 2 reports accept a ",(0,b.jsx)("code",{children:"?window"})," query parameter that controls how far back the report looks. The value is a Go-style duration string. If omitted, the default is"," ",(0,b.jsx)("code",{children:"720h"})," (30 days)."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Value"}),(0,b.jsx)("th",{children:"Duration"}),(0,b.jsx)("th",{children:"Use Case"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"168h"})}),(0,b.jsx)("td",{children:"7 days"}),(0,b.jsx)("td",{children:"Weekly reviews and quick checks on recent activity."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"720h"})}),(0,b.jsx)("td",{children:"30 days"}),(0,b.jsxs)("td",{children:["Standard monthly compliance reporting. ",(0,b.jsx)("strong",{children:"Default."})]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"2160h"})}),(0,b.jsx)("td",{children:"90 days"}),(0,b.jsx)("td",{children:"Quarterly audits, SOC 2 Type II evidence collection."})]})]})]}),(0,b.jsxs)(d.default,{type:"success",title:"Custom Windows",children:["You can pass any valid Go duration, not just the predefined values. For example,"," ",(0,b.jsx)("code",{children:"?window=336h"})," produces a 14-day report. If the value cannot be parsed, the endpoint falls back to the default 720h window."]}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsx)("p",{children:"The Sentinel dashboard includes a dedicated Reports page that provides a graphical interface for generating compliance reports without using the API directly."}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Report type selector"})," -- choose between GDPR, PCI-DSS, and SOC 2 using toggle buttons at the top of the page."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Date range picker"})," -- select the time window from a dropdown. The dropdown is hidden for PCI-DSS since it always covers 90 days."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Generate button"})," -- click to generate the report on demand. A loading indicator is shown while the report is being computed."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Structured display"})," -- the report is rendered with summary statistics in a grid layout, followed by detailed sections (requirements status, user data summary, anomaly events, etc.) depending on the report type."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"JSON export"})," -- an Export JSON button appears after a report is generated, allowing you to download the report data as a JSON file."]})]}),(0,b.jsxs)("p",{children:["Access the Reports page at"," ",(0,b.jsx)("code",{children:"http://localhost:8080/sentinel/ui"})," and navigate to the Reports section."]}),(0,b.jsx)("h2",{id:"json-export",children:"JSON Export"}),(0,b.jsxs)("p",{children:["Both the dashboard and the API return reports as JSON. From the dashboard, clicking the"," ",(0,b.jsx)("strong",{children:"Export JSON"})," button downloads the report as a file named"," ",(0,b.jsxs)("code",{children:["sentinel-","<type>","-report-","<date>",".json"]}),", where ",(0,b.jsx)("code",{children:"<type>"})," is the report type (gdpr, pci-dss, or soc2) and ",(0,b.jsx)("code",{children:"<date>"})," is the current date in ",(0,b.jsx)("code",{children:"YYYY-MM-DD"})," format."]}),(0,b.jsx)(c.default,{language:"text",showLineNumbers:!1,code:`sentinel-gdpr-report-2025-06-15.json
sentinel-pci-dss-report-2025-06-15.json
sentinel-soc2-report-2025-06-15.json`}),(0,b.jsxs)("p",{children:["When consuming reports programmatically via the API, pipe the response through"," ",(0,b.jsx)("code",{children:"jq"})," to extract the ",(0,b.jsx)("code",{children:".data"})," field and redirect it to a file:"]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=720h" \\
  | jq '.data' > gdpr-report.json`}),(0,b.jsx)("h2",{id:"testing",children:"Testing"}),(0,b.jsxs)("p",{children:["Use the following ",(0,b.jsx)("code",{children:"curl"})," commands to generate each report type. Replace"," ",(0,b.jsx)("code",{children:"<token>"})," with a valid JWT token obtained from the dashboard login endpoint."]}),(0,b.jsx)("h3",{children:"Generate GDPR Report"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# GDPR report for the last 30 days (default)
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=720h" | jq .

# GDPR report for the last 7 days
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=168h" | jq .

# GDPR report for the last 90 days
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/gdpr?window=2160h" | jq .`}),(0,b.jsx)("h3",{children:"Generate PCI-DSS Report"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# PCI-DSS report (always 90 days, no window parameter)
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/pci-dss" | jq .`}),(0,b.jsx)("h3",{children:"Generate SOC 2 Report"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# SOC 2 report for the last 30 days (default)
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/soc2?window=720h" | jq .

# SOC 2 report for the last 90 days
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/reports/soc2?window=2160h" | jq .`}),(0,b.jsxs)(d.default,{type:"info",title:"Authentication",children:["All report endpoints require authentication. Obtain a JWT token by logging into the dashboard at ",(0,b.jsx)("code",{children:"POST /sentinel/api/login"})," with your dashboard credentials. Include the token as ",(0,b.jsxs)("code",{children:["Authorization: Bearer ","<token>"]})," in every request."]}),(0,b.jsx)("h2",{id:"how-it-works",children:"How It Works"}),(0,b.jsxs)("p",{children:["Reports are generated on demand by the ",(0,b.jsx)("code",{children:"reports.Generator"})," struct, which queries the storage layer for the relevant data. Each report type has a dedicated generator method that assembles data from multiple storage queries into a single response."]}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"GDPR"})," -- queries user activity, READ/DELETE audit logs, and anomaly-type threat events to build the user data access summary and unusual access patterns list."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"PCI-DSS"})," -- queries authentication audit logs, all threat events, and blocked threats over a fixed 90-day window. Computes failure rates and maps results to PCI-DSS requirement categories."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"SOC 2"})," -- queries threat stats, the security score, resolved incidents, audit logs, blocked IPs, and anomaly events to build evidence across monitoring, incident response, and access control sections."]})]}),(0,b.jsx)(c.default,{language:"go",filename:"reports/compliance.go",code:`// Generator produces compliance reports from stored Sentinel data.
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
}`}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," -- Access the Reports page and generate reports from the UI"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/anomaly-detection",children:"Anomaly Detection"})," -- Powers the unusual access patterns in GDPR and anomalies in SOC 2 reports"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF"})," -- Threat events from the WAF feed into PCI-DSS and SOC 2 incident data"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," -- Authentication events that populate PCI-DSS auth metrics"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/security-score",children:"Security Score"})," -- The security score is included in SOC 2 monitoring evidence"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/alerting",children:"Alerting"})," -- Configure real-time alerts alongside periodic compliance reporting"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Compliance Reports - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_compliance-reports_page_jsx_c474a77b._.js.map