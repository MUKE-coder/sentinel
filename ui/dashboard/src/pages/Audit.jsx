import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import DataTable from '../components/DataTable';
import Pagination from '../components/Pagination';
import Modal from '../components/Modal';

const ACTION_COLORS = {
  CREATE: '#00ff88',
  UPDATE: '#00d4ff',
  DELETE: '#ff2d55',
  READ: '#8892a0',
};

export default function Audit() {
  const { apiFetch } = useAPI();
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ action: '', resource: '', user_id: '' });
  const [selected, setSelected] = useState(null);
  const pageSize = 20;

  const loadLogs = useCallback(async () => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (filters.action) params.set('action', filters.action);
    if (filters.resource) params.set('resource', filters.resource);
    if (filters.user_id) params.set('user_id', filters.user_id);

    try {
      const res = await apiFetch(`/audit-logs?${params}`);
      setLogs(res.data || []);
      setTotal(res.meta?.total || 0);
    } catch {
      // ignore
    }
  }, [apiFetch, page, filters]);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-logs-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const columns = [
    {
      key: 'timestamp',
      label: 'Time',
      render: (v) => new Date(v).toLocaleString(),
    },
    { key: 'user_id', label: 'User', render: (v) => v || '—' },
    {
      key: 'action',
      label: 'Action',
      render: (v) => (
        <span style={{ color: ACTION_COLORS[v] || '#e0e0e0' }} className="font-medium">
          {v}
        </span>
      ),
    },
    { key: 'resource', label: 'Resource' },
    { key: 'resource_id', label: 'Resource ID', render: (v) => v ? v.slice(0, 8) + '...' : '—' },
    {
      key: 'success',
      label: 'Status',
      render: (v) => (
        <span className={v ? 'text-[#00ff88]' : 'text-[#ff2d55]'}>
          {v ? 'Success' : 'Failed'}
        </span>
      ),
    },
    { key: 'ip', label: 'IP', render: (v) => v || '—' },
  ];

  // Compute diff between before and after
  const computeDiff = (before, after) => {
    if (!before && !after) return [];
    const allKeys = new Set([
      ...Object.keys(before || {}),
      ...Object.keys(after || {}),
    ]);
    const diffs = [];
    for (const key of allKeys) {
      const bVal = before?.[key];
      const aVal = after?.[key];
      const bStr = JSON.stringify(bVal);
      const aStr = JSON.stringify(aVal);
      if (bStr !== aStr) {
        diffs.push({ key, before: bVal, after: aVal });
      }
    }
    return diffs;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-[#e0e0e0]">Audit Logs</h2>
        <button
          onClick={handleExport}
          disabled={logs.length === 0}
          className="px-4 py-1.5 bg-[#1e2d4a] text-[#00d4ff] rounded text-xs font-medium hover:bg-[#2a3d5a] disabled:opacity-50"
        >
          Export JSON
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <select
          value={filters.action}
          onChange={(e) => { setFilters({ ...filters, action: e.target.value }); setPage(1); }}
          className="bg-[#0d1526] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
        >
          <option value="">All Actions</option>
          <option value="CREATE">CREATE</option>
          <option value="UPDATE">UPDATE</option>
          <option value="DELETE">DELETE</option>
          <option value="READ">READ</option>
        </select>
        <input
          placeholder="Filter by resource..."
          value={filters.resource}
          onChange={(e) => { setFilters({ ...filters, resource: e.target.value }); setPage(1); }}
          className="bg-[#0d1526] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none w-48"
        />
        <input
          placeholder="Filter by user ID..."
          value={filters.user_id}
          onChange={(e) => { setFilters({ ...filters, user_id: e.target.value }); setPage(1); }}
          className="bg-[#0d1526] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none w-48"
        />
      </div>

      <DataTable columns={columns} data={logs} onRowClick={setSelected} emptyText="No audit logs recorded" />
      <Pagination page={page} pageSize={pageSize} total={total} onChange={setPage} />

      {/* Detail modal with diff view */}
      <Modal isOpen={!!selected} onClose={() => setSelected(null)} title="Audit Log Detail">
        {selected && (
          <div className="space-y-4 text-sm">
            {/* Header info */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[#8892a0] text-xs">Action</p>
                <p style={{ color: ACTION_COLORS[selected.action] || '#e0e0e0' }} className="font-bold text-lg">
                  {selected.action}
                </p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Resource</p>
                <p className="text-[#e0e0e0] font-mono">{selected.resource}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Resource ID</p>
                <p className="text-[#e0e0e0] font-mono text-xs break-all">{selected.resource_id || '—'}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Timestamp</p>
                <p className="text-[#e0e0e0]">{new Date(selected.timestamp).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">User</p>
                <p className="text-[#e0e0e0]">{selected.user_id || '—'}{selected.user_email ? ` (${selected.user_email})` : ''}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">IP Address</p>
                <p className="text-[#e0e0e0]">{selected.ip || '—'}</p>
              </div>
              {selected.request_id && (
                <div>
                  <p className="text-[#8892a0] text-xs">Request ID</p>
                  <p className="text-[#e0e0e0] font-mono text-xs">{selected.request_id}</p>
                </div>
              )}
              {selected.error && (
                <div>
                  <p className="text-[#8892a0] text-xs">Error</p>
                  <p className="text-[#ff2d55]">{selected.error}</p>
                </div>
              )}
            </div>

            {/* Diff view */}
            {(selected.before || selected.after) && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Changes</p>
                <div className="space-y-1">
                  {computeDiff(selected.before, selected.after).map((d) => (
                    <div key={d.key} className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-xs font-mono">
                      <span className="text-[#00d4ff]">{d.key}</span>
                      {d.before !== undefined && (
                        <div className="mt-1">
                          <span className="text-[#ff2d55]">- </span>
                          <span className="text-[#ff2d55] opacity-70">{JSON.stringify(d.before)}</span>
                        </div>
                      )}
                      {d.after !== undefined && (
                        <div className="mt-0.5">
                          <span className="text-[#00ff88]">+ </span>
                          <span className="text-[#00ff88] opacity-70">{JSON.stringify(d.after)}</span>
                        </div>
                      )}
                    </div>
                  ))}
                  {computeDiff(selected.before, selected.after).length === 0 && (
                    <p className="text-[#8892a0] text-xs">No field differences detected</p>
                  )}
                </div>
              </div>
            )}

            {/* Raw before/after JSON */}
            {selected.action === 'CREATE' && selected.after && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Created Record</p>
                <pre className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3 text-xs text-[#e0e0e0] overflow-x-auto max-h-60">
                  {JSON.stringify(selected.after, null, 2)}
                </pre>
              </div>
            )}

            {selected.action === 'DELETE' && selected.before && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Deleted Record</p>
                <pre className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3 text-xs text-[#ff2d55] opacity-70 overflow-x-auto max-h-60">
                  {JSON.stringify(selected.before, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
