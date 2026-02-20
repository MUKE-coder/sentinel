import { useState } from 'react';
import { useAPI } from '../hooks/useAPI';

const REPORT_TYPES = [
  { id: 'gdpr', label: 'GDPR', description: 'General Data Protection Regulation compliance report' },
  { id: 'pci-dss', label: 'PCI-DSS', description: 'Payment Card Industry Data Security Standard report' },
  { id: 'soc2', label: 'SOC 2', description: 'Service Organization Control 2 compliance report' },
];

const WINDOWS = [
  { value: '168h', label: 'Last 7 Days' },
  { value: '720h', label: 'Last 30 Days' },
  { value: '2160h', label: 'Last 90 Days' },
];

export default function Reports() {
  const { apiFetch } = useAPI();
  const [selectedType, setSelectedType] = useState('gdpr');
  const [window, setWindow] = useState('720h');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    setReport(null);
    try {
      const url = selectedType === 'pci-dss'
        ? '/reports/pci-dss'
        : `/reports/${selectedType}?window=${window}`;
      const res = await apiFetch(url);
      setReport({ type: selectedType, data: res.data });
    } catch (err) {
      setError(err.message || 'Failed to generate report');
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
                  onClick={() => { setSelectedType(type.id); setReport(null); }}
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
                value={window}
                onChange={(e) => setWindow(e.target.value)}
                className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
              >
                {WINDOWS.map((w) => (
                  <option key={w.value} value={w.value}>{w.label}</option>
                ))}
              </select>
            </div>
          )}
          <button
            onClick={handleGenerate}
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
          {REPORT_TYPES.find(t => t.id === selectedType)?.description}
        </p>
        {error && <p className="text-[#ff2d55] text-xs mt-2">{error}</p>}
      </div>

      {/* Report Display */}
      {report && (
        <div className="space-y-4">
          {report.type === 'gdpr' && <GDPRReport data={report.data} />}
          {report.type === 'pci-dss' && <PCIDSSReport data={report.data} />}
          {report.type === 'soc2' && <SOC2Report data={report.data} />}
        </div>
      )}
    </div>
  );
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

function GDPRReport({ data }) {
  if (!data) return null;
  return (
    <>
      <ReportSection title="GDPR Compliance Report">
        <div className="flex items-center gap-3 mb-4">
          <span className="text-[#8892a0] text-sm">Generated:</span>
          <span className="text-[#e0e0e0] text-sm">{new Date(data.generated_at).toLocaleString()}</span>
          <span className="text-[#8892a0] text-sm ml-4">Window:</span>
          <span className="text-[#e0e0e0] text-sm">{data.window}</span>
        </div>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <ReportStat label="Total Users" value={data.total_users} color="#00d4ff" />
          <ReportStat label="Data Accesses" value={data.data_access_events} />
          <ReportStat label="Data Exports" value={data.data_export_events} />
          <ReportStat label="Data Deletions" value={data.data_deletion_events} color="#ff6b35" />
        </div>
      </ReportSection>

      {data.unusual_access_patterns?.length > 0 && (
        <ReportSection title="Unusual Access Patterns">
          <div className="space-y-1">
            {data.unusual_access_patterns.map((p, i) => (
              <div key={i} className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-xs text-[#ff6b35]">
                {typeof p === 'string' ? p : JSON.stringify(p)}
              </div>
            ))}
          </div>
        </ReportSection>
      )}

      {data.user_data_summary?.length > 0 && (
        <ReportSection title="User Data Summary">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[#8892a0] text-xs uppercase border-b border-[#1e2d4a]">
                  <th className="text-left py-2 px-2">User ID</th>
                  <th className="text-left py-2 px-2">Activity Count</th>
                  <th className="text-left py-2 px-2">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {data.user_data_summary.map((u, i) => (
                  <tr key={i} className="border-b border-[#1e2d4a]">
                    <td className="py-2 px-2 text-[#00d4ff] font-mono text-xs">{u.user_id}</td>
                    <td className="py-2 px-2 text-[#e0e0e0]">{u.activity_count}</td>
                    <td className="py-2 px-2 text-[#8892a0] text-xs">{u.last_seen ? new Date(u.last_seen).toLocaleString() : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ReportSection>
      )}
    </>
  );
}

function PCIDSSReport({ data }) {
  if (!data) return null;
  return (
    <>
      <ReportSection title="PCI-DSS Compliance Report">
        <div className="flex items-center gap-3 mb-4">
          <span className="text-[#8892a0] text-sm">Generated:</span>
          <span className="text-[#e0e0e0] text-sm">{new Date(data.generated_at).toLocaleString()}</span>
        </div>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <ReportStat label="Auth Events (90d)" value={data.auth_events_90d} color="#00d4ff" />
          <ReportStat label="Failed Logins" value={data.failed_logins_90d} color="#ff6b35" />
          <ReportStat label="Security Incidents" value={data.security_incidents} color="#ff2d55" />
          <ReportStat label="Blocked Threats" value={data.blocked_threats} color="#00ff88" />
        </div>
      </ReportSection>

      {data.requirements && (
        <ReportSection title="PCI-DSS Requirements Status">
          <div className="space-y-2">
            {Object.entries(data.requirements).map(([req, status], i) => (
              <div key={i} className="flex items-center justify-between bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm">
                <span className="text-[#e0e0e0]">{req}</span>
                <span className={status === 'compliant' ? 'text-[#00ff88] text-xs font-medium' : status === 'partial' ? 'text-[#ff6b35] text-xs font-medium' : 'text-[#ff2d55] text-xs font-medium'}>
                  {typeof status === 'string' ? status.toUpperCase() : JSON.stringify(status)}
                </span>
              </div>
            ))}
          </div>
        </ReportSection>
      )}
    </>
  );
}

function SOC2Report({ data }) {
  if (!data) return null;
  return (
    <>
      <ReportSection title="SOC 2 Compliance Report">
        <div className="flex items-center gap-3 mb-4">
          <span className="text-[#8892a0] text-sm">Generated:</span>
          <span className="text-[#e0e0e0] text-sm">{new Date(data.generated_at).toLocaleString()}</span>
          <span className="text-[#8892a0] text-sm ml-4">Window:</span>
          <span className="text-[#e0e0e0] text-sm">{data.window}</span>
        </div>
      </ReportSection>

      {data.monitoring_evidence && (
        <ReportSection title="Monitoring Evidence">
          <div className="grid grid-cols-3 gap-3">
            <ReportStat label="Total Events Monitored" value={data.monitoring_evidence.total_events} color="#00d4ff" />
            <ReportStat label="Threats Detected" value={data.monitoring_evidence.threats_detected} color="#ff6b35" />
            <ReportStat label="Threats Blocked" value={data.monitoring_evidence.threats_blocked} color="#00ff88" />
          </div>
        </ReportSection>
      )}

      {data.incident_response && (
        <ReportSection title="Incident Response">
          <div className="grid grid-cols-3 gap-3">
            <ReportStat label="Total Incidents" value={data.incident_response.total_incidents} />
            <ReportStat label="Resolved" value={data.incident_response.resolved} color="#00ff88" />
            <ReportStat label="Avg Response Time" value={data.incident_response.avg_response_time || 'N/A'} color="#00d4ff" />
          </div>
        </ReportSection>
      )}

      {data.access_control && (
        <ReportSection title="Access Control">
          <div className="grid grid-cols-3 gap-3">
            <ReportStat label="Unique Users" value={data.access_control.unique_users} color="#00d4ff" />
            <ReportStat label="Auth Events" value={data.access_control.auth_events} />
            <ReportStat label="IP Blocks Active" value={data.access_control.ip_blocks_active} color="#ff6b35" />
          </div>
        </ReportSection>
      )}

      {data.anomalies?.length > 0 && (
        <ReportSection title="Detected Anomalies">
          <div className="space-y-1">
            {data.anomalies.map((a, i) => (
              <div key={i} className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-xs text-[#ff6b35]">
                {typeof a === 'string' ? a : JSON.stringify(a)}
              </div>
            ))}
          </div>
        </ReportSection>
      )}
    </>
  );
}
