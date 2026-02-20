import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import DataTable from '../components/DataTable';
import SeverityBadge from '../components/SeverityBadge';

export default function Alerts() {
  const { apiFetch } = useAPI();
  const [config, setConfig] = useState(null);
  const [history, setHistory] = useState([]);
  const [testResult, setTestResult] = useState(null);

  const loadData = useCallback(async () => {
    try {
      const [cfgRes, histRes] = await Promise.all([
        apiFetch('/alerts/config'),
        apiFetch('/alerts/history'),
      ]);
      setConfig(cfgRes.data);
      setHistory(histRes.data || []);
    } catch {
      // ignore
    }
  }, [apiFetch]);

  useEffect(() => { loadData(); }, [loadData]);

  const handleTest = async () => {
    try {
      const res = await apiFetch('/alerts/test', { method: 'POST' });
      setTestResult(res.message || 'Test sent');
      setTimeout(() => setTestResult(null), 3000);
      loadData();
    } catch (e) {
      setTestResult('Test failed: ' + e.message);
    }
  };

  const handleUpdateSeverity = async (severity) => {
    try {
      await apiFetch('/alerts/config', {
        method: 'PUT',
        body: JSON.stringify({ min_severity: severity }),
      });
      loadData();
    } catch {
      // ignore
    }
  };

  const historyColumns = [
    {
      key: 'timestamp',
      label: 'Time',
      render: (v) => new Date(v).toLocaleString(),
    },
    { key: 'channel', label: 'Channel' },
    {
      key: 'severity',
      label: 'Severity',
      render: (v) => <SeverityBadge severity={v} />,
    },
    { key: 'threat_type', label: 'Type' },
    { key: 'ip', label: 'IP' },
    {
      key: 'success',
      label: 'Status',
      render: (v) => (
        <span className={v ? 'text-[#00ff88]' : 'text-[#ff2d55]'}>
          {v ? 'Sent' : 'Failed'}
        </span>
      ),
    },
    { key: 'error', label: 'Error', render: (v) => v || '—' },
  ];

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">Alert Configuration</h2>

      {/* Channel status cards */}
      <div className="grid grid-cols-3 gap-4">
        {/* Slack */}
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-[#e0e0e0]">Slack</h3>
            <span className={`text-xs px-2 py-0.5 rounded ${
              config?.slack?.enabled
                ? 'bg-[#00ff8820] text-[#00ff88] border border-[#00ff8840]'
                : 'bg-[#ff2d5520] text-[#ff2d55] border border-[#ff2d5540]'
            }`}>
              {config?.slack?.enabled ? 'Active' : 'Not configured'}
            </span>
          </div>
          {config?.slack?.webhook_url && (
            <p className="text-xs text-[#8892a0] font-mono truncate">{config.slack.webhook_url}</p>
          )}
        </div>

        {/* Email */}
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-[#e0e0e0]">Email</h3>
            <span className={`text-xs px-2 py-0.5 rounded ${
              config?.email?.enabled
                ? 'bg-[#00ff8820] text-[#00ff88] border border-[#00ff8840]'
                : 'bg-[#ff2d5520] text-[#ff2d55] border border-[#ff2d5540]'
            }`}>
              {config?.email?.enabled ? 'Active' : 'Not configured'}
            </span>
          </div>
          {config?.email?.recipients?.length > 0 && (
            <p className="text-xs text-[#8892a0]">{config.email.recipients.join(', ')}</p>
          )}
        </div>

        {/* Webhook */}
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-[#e0e0e0]">Webhook</h3>
            <span className={`text-xs px-2 py-0.5 rounded ${
              config?.webhook?.enabled
                ? 'bg-[#00ff8820] text-[#00ff88] border border-[#00ff8840]'
                : 'bg-[#ff2d5520] text-[#ff2d55] border border-[#ff2d5540]'
            }`}>
              {config?.webhook?.enabled ? 'Active' : 'Not configured'}
            </span>
          </div>
          {config?.webhook?.url && (
            <p className="text-xs text-[#8892a0] font-mono truncate">{config.webhook.url}</p>
          )}
        </div>
      </div>

      {/* Severity threshold */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <h3 className="text-sm font-medium text-[#e0e0e0] mb-3">Minimum Severity for Alerts</h3>
        <div className="flex gap-2">
          {['Low', 'Medium', 'High', 'Critical'].map((sev) => (
            <button
              key={sev}
              onClick={() => handleUpdateSeverity(sev)}
              className={`px-4 py-1.5 rounded text-xs font-medium transition-colors ${
                config?.min_severity === sev
                  ? 'bg-[#00d4ff] text-[#0a0f1e]'
                  : 'bg-[#0a0f1e] text-[#8892a0] border border-[#1e2d4a] hover:text-[#e0e0e0]'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Test button */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleTest}
          className="px-4 py-2 bg-[#00d4ff] text-[#0a0f1e] rounded text-sm font-medium hover:bg-[#00b8d9]"
        >
          Send Test Alert
        </button>
        {testResult && (
          <span className="text-sm text-[#00ff88]">{testResult}</span>
        )}
      </div>

      {/* Alert history */}
      <div>
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Alert History</h3>
        <DataTable columns={historyColumns} data={history} emptyText="No alerts sent yet" />
      </div>
    </div>
  );
}
