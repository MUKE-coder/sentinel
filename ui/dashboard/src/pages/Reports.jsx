import { useState } from 'react';
import { useAPI } from '../hooks/useAPI';

const REPORT_TYPES = [
  { id: 'gdpr', label: 'GDPR', description: 'Evidence of how user data was accessed, exported, and deleted' },
  { id: 'pci-dss', label: 'PCI-DSS', description: 'Authentication events, incidents, and blocked threats over the last 90 days' },
  { id: 'soc2', label: 'SOC 2', description: 'Monitoring, incident-response, and access-control evidence' },
];

const WINDOWS = [
  { value: '168h', label: 'Last 7 Days' },
  { value: '720h', label: 'Last 30 Days' },
  { value: '2160h', label: 'Last 90 Days' },
];

// Rows shown per list; the JSON export always has everything the API returned.
const LIST_LIMIT = 50;

export default function Reports() {
  const { apiFetch } = useAPI();
  const [selectedType, setSelectedType] = useState('gdpr');
  const [reportWindow, setReportWindow] = useState('720h');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [ephemeral, setEphemeral] = useState(false);

  const generate = async (acknowledgeEphemeral = false) => {
    setLoading(true);
    setError('');
    setEphemeral(false);
    setReport(null);
    try {
      const params = new URLSearchParams();
      if (selectedType !== 'pci-dss') params.set('window', reportWindow);
      if (acknowledgeEphemeral) params.set('acknowledge_ephemeral', 'true');
      const query = params.toString();
      const res = await apiFetch(`/reports/${selectedType}${query ? `?${query}` : ''}`);
      setReport({ type: selectedType, data: res.data });
    } catch (err) {
      setError(err.message || 'Failed to generate report');
      setEphemeral(err.code === 'EPHEMERAL_STORAGE');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-${report.type}-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">Compliance Reports</h2>

      {/* Report Controls */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <div className="flex items-end gap-4">
          <div className="flex-1">
            <label className="text-[#8892a0] text-xs uppercase tracking-wider block mb-2">Report Type</label>
            <div className="flex gap-2">
              {REPORT_TYPES.map((type) => (
                <button
                  key={type.id}
                  onClick={() => { setSelectedType(type.id); setReport(null); setError(''); setEphemeral(false); }}
                  className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
                    selectedType === type.id
                      ? 'bg-[#00d4ff] text-[#0a0f1e]'
                      : 'bg-[#0a0f1e] border border-[#1e2d4a] text-[#8892a0] hover:text-[#e0e0e0]'
                  }`}
                >
                  {type.label}
                </button>
              ))}
            </div>
          </div>
          {selectedType !== 'pci-dss' && (
            <div>
              <label className="text-[#8892a0] text-xs uppercase tracking-wider block mb-2">Time Window</label>
              <select
                value={reportWindow}
                onChange={(e) => setReportWindow(e.target.value)}
                className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
              >
                {WINDOWS.map((w) => (
                  <option key={w.value} value={w.value}>{w.label}</option>
                ))}
              </select>
            </div>
          )}
          <button
            onClick={() => generate(false)}
            disabled={loading}
            className="px-6 py-2 bg-[#00d4ff] text-[#0a0f1e] rounded text-sm font-medium hover:bg-[#00bde0] disabled:opacity-50"
          >
            {loading ? 'Generating...' : 'Generate Report'}
          </button>
          {report && (
            <button
              onClick={handleExport}
              className="px-4 py-2 bg-[#1e2d4a] text-[#00d4ff] rounded text-sm font-medium hover:bg-[#2a3d5a]"
            >
              Export JSON
            </button>
          )}
        </div>
        <p className="text-[#8892a0] text-xs mt-2">
          {REPORT_TYPES.find(t => t.id === selectedType)?.description}. Reports collect evidence
          from what Sentinel has recorded; they do not assess compliance.
        </p>
        {error && (
          <div className="mt-3 bg-[#0a0f1e] border border-[#ff2d55]/40 rounded px-3 py-2">
            <p className="text-[#ff2d55] text-xs">{error}</p>
            {ephemeral && (
              <button
                onClick={() => generate(true)}
                disabled={loading}
                className="mt-2 px-3 py-1 bg-[#1e2d4a] text-[#ff6b35] rounded text-xs font-medium hover:bg-[#2a3d5a] disabled:opacity-50"
              >
                Generate anyway (covers only the time since the last restart)
              </button>
            )}
          </div>
        )}
      </div>

      {/* Report Display */}
      {report?.data && (
        <div className="space-y-4">
          {report.type === 'gdpr' && <GDPRReport data={report.data} />}
          {report.type === 'pci-dss' && <PCIDSSReport data={report.data} />}
          {report.type === 'soc2' && <SOC2Report data={report.data} />}
          <Provenance data={report.data} />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
//  Shared pieces
// ---------------------------------------------------------------------------

function fmtTime(t) {
  return t ? new Date(t).toLocaleString() : '—';
}

function ReportSection({ title, children }) {
  return (
    <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
      <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">{title}</h3>
      {children}
    </div>
  );
}

function ReportStat({ label, value, color = '#e0e0e0' }) {
  return (
    <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3">
      <div className="text-[#8892a0] text-xs">{label}</div>
      <div className="text-lg font-bold mt-1" style={{ color }}>{value ?? 0}</div>
    </div>
  );
}

function StatGrid({ children }) {
  return <div className="grid grid-cols-5 gap-3">{children}</div>;
}

function ReportHeader({ title, data, windowLabel }) {
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-1 mb-4 text-sm">
      <span className="text-[#e0e0e0] font-medium">{title}</span>
      <span><span className="text-[#8892a0]">Generated: </span><span className="text-[#e0e0e0]">{fmtTime(data.generated_at)}</span></span>
      <span>
        <span className="text-[#8892a0]">Window: </span>
        <span className="text-[#e0e0e0]">
          {windowLabel || `${fmtTime(data.window_start)} – ${fmtTime(data.window_end)}`}
        </span>
      </span>
    </div>
  );
}

// ListTable renders up to LIST_LIMIT rows; columns are [label, row => cell].
function ListTable({ rows, columns, empty = 'None recorded in this window.' }) {
  if (!rows || rows.length === 0) {
    return <p className="text-[#8892a0] text-xs">{empty}</p>;
  }
  const shown = rows.slice(0, LIST_LIMIT);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-[#8892a0] text-xs uppercase border-b border-[#1e2d4a]">
            {columns.map(([label]) => <th key={label} className="text-left py-2 px-2">{label}</th>)}
          </tr>
        </thead>
        <tbody>
          {shown.map((row, i) => (
            <tr key={row.id || i} className="border-b border-[#1e2d4a]">
              {columns.map(([label, cell]) => (
                <td key={label} className="py-2 px-2 text-[#e0e0e0] text-xs">{cell(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > shown.length && (
        <p className="text-[#8892a0] text-xs mt-2">
          Showing {shown.length} of {rows.length}. Export JSON for the full list.
        </p>
      )}
    </div>
  );
}

const threatColumns = [
  ['Time', (t) => fmtTime(t.timestamp)],
  ['Source IP', (t) => <span className="font-mono text-[#00d4ff]">{t.ip || '—'}</span>],
  ['Request', (t) => `${t.method || ''} ${t.path || ''}`.trim() || '—'],
  ['Type', (t) => (t.threat_types || []).join(', ')],
  ['Severity', (t) => t.severity],
  ['Blocked', (t) => (t.blocked ? 'Yes' : 'No')],
];

const auditColumns = [
  ['Time', (a) => fmtTime(a.timestamp)],
  ['User', (a) => a.user_id || '—'],
  ['Action', (a) => a.action],
  ['Resource', (a) => `${a.resource || ''}${a.resource_id ? ` / ${a.resource_id}` : ''}`],
  ['Outcome', (a) => (a.success ? 'Success' : <span className="text-[#ff2d55]">{a.error || 'Failed'}</span>)],
];

// Provenance shows where the report's data came from and every reason it may
// fall short of a complete record — an empty section must not read as clean.
function Provenance({ data }) {
  const p = data.provenance;
  if (!p) return null;
  const truncated = data.truncated || [];
  const oldest = [p.oldest_threat_event, p.oldest_audit_entry]
    .filter(Boolean)
    .sort((a, b) => new Date(a) - new Date(b))[0];

  return (
    <ReportSection title="Data Provenance">
      <div className="grid grid-cols-4 gap-3 mb-3">
        <ReportStat label="Storage" value={p.storage_driver || 'unknown'} color="#00d4ff" />
        <ReportStat
          label="Survives Restart"
          value={p.durable ? 'Yes' : 'No'}
          color={p.durable ? '#00ff88' : '#ff2d55'}
        />
        <ReportStat
          label="Retention (events / audit)"
          value={`${p.retention_days ?? '?'}d / ${p.audit_retention_days ?? '?'}d`}
        />
        <ReportStat label="Oldest Stored Record" value={oldest ? new Date(oldest).toLocaleDateString() : 'none'} />
      </div>
      {p.warnings?.length > 0 && (
        <ul className="space-y-1">
          {p.warnings.map((w, i) => (
            <li key={i} className="bg-[#0a0f1e] border border-[#ff6b35]/40 rounded px-3 py-2 text-xs text-[#ff6b35]">
              {w}
            </li>
          ))}
        </ul>
      )}
      {truncated.length > 0 && (
        <p className="text-[#ff6b35] text-xs mt-2">
          Partial lists (row cap reached): {truncated.join(', ')}. Summary counts are exact; export
          JSON for everything returned.
        </p>
      )}
    </ReportSection>
  );
}

// ---------------------------------------------------------------------------
//  GDPR
// ---------------------------------------------------------------------------

function GDPRReport({ data }) {
  const s = data.summary || {};
  return (
    <>
      <ReportSection title="GDPR Report">
        <ReportHeader title="GDPR" data={data} />
        <StatGrid>
          <ReportStat label="Users" value={s.total_users} color="#00d4ff" />
          <ReportStat label="Data Accesses" value={s.total_data_accesses} />
          <ReportStat label="Exports (READ)" value={s.total_exports} />
          <ReportStat label="Deletions" value={s.total_deletions} color="#ff6b35" />
          <ReportStat label="Unusual Access" value={s.unusual_access_count} color="#ff2d55" />
        </StatGrid>
      </ReportSection>

      <ReportSection title="User Data Access">
        <ListTable
          rows={data.user_data_access}
          empty="No user activity recorded in this window. Per-user activity requires Config.UserExtractor."
          columns={[
            ['User', (u) => <span className="font-mono text-[#00d4ff]">{u.user_id}</span>],
            ['Accesses', (u) => u.access_count],
            ['Routes', (u) => (u.routes_accessed || []).slice(0, 6).join(', ') + ((u.routes_accessed || []).length > 6 ? ', …' : '')],
            ['Last Access', (u) => fmtTime(u.last_access)],
          ]}
        />
      </ReportSection>

      <ReportSection title="Data Deletions">
        <ListTable rows={data.data_deletions} columns={auditColumns} />
      </ReportSection>

      <ReportSection title="Data Exports">
        <ListTable rows={data.data_exports} columns={auditColumns} />
      </ReportSection>

      <ReportSection title="Unusual Access">
        <ListTable
          rows={data.unusual_access}
          columns={[
            ['Time', (t) => fmtTime(t.timestamp)],
            ['User', (t) => t.user_id || '—'],
            ['Source IP', (t) => <span className="font-mono text-[#00d4ff]">{t.ip || '—'}</span>],
            ['Request', (t) => `${t.method || ''} ${t.path || ''}`.trim() || '—'],
            ['Severity', (t) => t.severity],
          ]}
        />
      </ReportSection>
    </>
  );
}

// ---------------------------------------------------------------------------
//  PCI-DSS
// ---------------------------------------------------------------------------

function PCIDSSReport({ data }) {
  const s = data.summary || {};
  const auth = data.auth_events || {};
  return (
    <>
      <ReportSection title="PCI-DSS Report">
        <ReportHeader title="PCI-DSS" data={data} windowLabel="Last 90 days" />
        <StatGrid>
          <ReportStat label="Security Incidents" value={s.total_incidents} color="#ff2d55" />
          <ReportStat label="Critical" value={s.critical_incidents} color="#ff2d55" />
          <ReportStat label="High" value={s.high_incidents} color="#ff6b35" />
          <ReportStat label="Blocked" value={s.blocked_count} color="#00ff88" />
          <ReportStat label="Attacker IPs" value={s.unique_attacker_ips} color="#00d4ff" />
        </StatGrid>
      </ReportSection>

      <ReportSection title="Authentication Events">
        <div className="grid grid-cols-4 gap-3">
          <ReportStat label="Attempts" value={auth.total_attempts} color="#00d4ff" />
          <ReportStat label="Successful" value={auth.success_count} color="#00ff88" />
          <ReportStat label="Failed" value={auth.failure_count} color="#ff6b35" />
          <ReportStat label="Failure Rate" value={`${(auth.failure_rate ?? 0).toFixed(1)}%`} />
        </div>
        {!auth.total_attempts && (
          <p className="text-[#8892a0] text-xs mt-2">
            No login attempts recorded. App logins are recorded when AuthShield is enabled with a
            LoginRoute; dashboard logins are always recorded.
          </p>
        )}
      </ReportSection>

      <ReportSection title="Blocked Threats">
        <ListTable rows={data.blocked_threats} columns={threatColumns} />
      </ReportSection>

      <ReportSection title="Security Incidents">
        <ListTable rows={data.security_incidents} columns={threatColumns} />
      </ReportSection>
    </>
  );
}

// ---------------------------------------------------------------------------
//  SOC 2
// ---------------------------------------------------------------------------

function SOC2Report({ data }) {
  const s = data.summary || {};
  const monitoring = data.monitoring_evidence || {};
  const stats = monitoring.threat_stats || {};
  const score = monitoring.security_score;
  const access = data.access_control || {};
  return (
    <>
      <ReportSection title="SOC 2 Report">
        <ReportHeader title="SOC 2" data={data} />
        <StatGrid>
          <ReportStat label="Threats Detected" value={s.total_threats_detected} color="#ff6b35" />
          <ReportStat label="Threats Blocked" value={s.total_threats_blocked} color="#00ff88" />
          <ReportStat label="Anomalies" value={s.total_anomalies} color="#ff2d55" />
          <ReportStat label="Audit Entries" value={s.total_audit_entries} color="#00d4ff" />
          <ReportStat label="Active IP Blocks" value={s.active_blocked_ips} />
        </StatGrid>
      </ReportSection>

      <ReportSection title="Monitoring Evidence">
        <div className="grid grid-cols-6 gap-3">
          <ReportStat label="Threat Events Recorded" value={monitoring.total_events_processed} color="#00d4ff" />
          <ReportStat label="Security Score" value={score ? `${score.overall} (${score.grade})` : '—'} color="#00ff88" />
          <ReportStat label="Critical" value={stats.critical_count} color="#ff2d55" />
          <ReportStat label="High" value={stats.high_count} color="#ff6b35" />
          <ReportStat label="Medium" value={stats.medium_count} />
          <ReportStat label="Low" value={stats.low_count} />
        </div>
      </ReportSection>

      <ReportSection title={`Incident Response — Resolved Threats (${(data.incident_response || []).length})`}>
        <ListTable rows={data.incident_response} columns={threatColumns} empty="No threats were marked resolved in this window." />
      </ReportSection>

      <ReportSection title={`Access Control — ${access.total_users ?? 0} users`}>
        <h4 className="text-xs text-[#8892a0] uppercase tracking-wider mb-2">Audit Log</h4>
        <ListTable rows={access.audit_logs} columns={auditColumns} />
        <h4 className="text-xs text-[#8892a0] uppercase tracking-wider mt-4 mb-2">Blocked IPs</h4>
        <ListTable
          rows={access.blocked_ips}
          empty="No IPs are blocked."
          columns={[
            ['IP / CIDR', (b) => <span className="font-mono text-[#00d4ff]">{b.ip}</span>],
            ['Reason', (b) => b.reason || '—'],
            ['Blocked', (b) => fmtTime(b.blocked_at)],
            ['Expires', (b) => (b.expires_at ? fmtTime(b.expires_at) : 'Never')],
          ]}
        />
      </ReportSection>

      <ReportSection title="Anomaly Events">
        <ListTable rows={data.anomaly_events} columns={threatColumns} />
      </ReportSection>
    </>
  );
}
