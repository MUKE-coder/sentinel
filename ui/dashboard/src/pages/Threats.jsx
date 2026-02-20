import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import { useWebSocket } from '../hooks/useWebSocket';
import DataTable from '../components/DataTable';
import SeverityBadge from '../components/SeverityBadge';
import Pagination from '../components/Pagination';
import Modal from '../components/Modal';

export default function Threats() {
  const { apiFetch } = useAPI();
  const { lastMessage } = useWebSocket('threats');
  const [threats, setThreats] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ severity: '', type: '', ip: '' });
  const [selected, setSelected] = useState(null);
  const [actorSummary, setActorSummary] = useState(null);
  const pageSize = 20;

  const loadThreats = useCallback(async () => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
      sort_by: 'timestamp',
      sort_order: 'desc',
    });
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.type) params.set('type', filters.type);
    if (filters.ip) params.set('ip', filters.ip);

    try {
      const res = await apiFetch(`/threats?${params}`);
      setThreats(res.data || []);
      setTotal(res.meta?.total || 0);
    } catch {
      // ignore
    }
  }, [apiFetch, page, filters]);

  useEffect(() => { loadThreats(); }, [loadThreats]);
  useEffect(() => {
    if (lastMessage?.type === 'threat') loadThreats();
  }, [lastMessage]);

  // Load actor profile when selecting a threat
  const handleSelect = async (threat) => {
    setSelected(threat);
    setActorSummary(null);
    if (threat.ip) {
      try {
        const res = await apiFetch(`/actors/${threat.ip}`);
        setActorSummary(res.data);
      } catch {
        // actor may not exist
      }
    }
  };

  const handleResolve = async (id) => {
    await apiFetch(`/threats/${id}/resolve`, { method: 'POST' });
    loadThreats();
    setSelected(null);
  };

  const handleFalsePositive = async (id) => {
    await apiFetch(`/threats/${id}/false-positive`, { method: 'POST' });
    loadThreats();
    setSelected(null);
  };

  const handleBlockIP = async (ip) => {
    await apiFetch('/ip/block', {
      method: 'POST',
      body: JSON.stringify({ ip, reason: 'Blocked from threats page' }),
    });
  };

  const columns = [
    { key: 'ip', label: 'IP Address' },
    { key: 'method', label: 'Method' },
    { key: 'path', label: 'Route' },
    {
      key: 'threat_types',
      label: 'Type',
      render: (v) => (v || []).join(', '),
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (v) => <SeverityBadge severity={v} />,
    },
    { key: 'confidence', label: 'Conf', render: (v) => `${v}%` },
    {
      key: 'timestamp',
      label: 'Time',
      render: (v) => new Date(v).toLocaleString(),
    },
    {
      key: 'resolved',
      label: 'Status',
      render: (v, row) =>
        row.false_positive ? (
          <span className="text-[#8892a0]">False +</span>
        ) : v ? (
          <span className="text-[#00ff88]">Resolved</span>
        ) : (
          <span className="text-[#ff6b35]">Active</span>
        ),
    },
  ];

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">Threats</h2>

      {/* Filters */}
      <div className="flex gap-3">
        <select
          value={filters.severity}
          onChange={(e) => { setFilters({ ...filters, severity: e.target.value }); setPage(1); }}
          className="bg-[#0d1526] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <input
          placeholder="Filter by IP..."
          value={filters.ip}
          onChange={(e) => { setFilters({ ...filters, ip: e.target.value }); setPage(1); }}
          className="bg-[#0d1526] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none w-48"
        />
        <input
          placeholder="Filter by type..."
          value={filters.type}
          onChange={(e) => { setFilters({ ...filters, type: e.target.value }); setPage(1); }}
          className="bg-[#0d1526] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none w-48"
        />
      </div>

      <DataTable columns={columns} data={threats} onRowClick={handleSelect} />
      <Pagination page={page} pageSize={pageSize} total={total} onChange={setPage} />

      {/* Detail modal — Full Request Replay */}
      <Modal isOpen={!!selected} onClose={() => setSelected(null)} title="Threat Detail — Request Replay">
        {selected && (
          <div className="space-y-4 text-sm">
            {/* Header info */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[#8892a0] text-xs">IP Address</p>
                <p className="text-[#e0e0e0]">{selected.ip}{selected.country ? ` (${selected.country})` : ''}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Severity</p>
                <SeverityBadge severity={selected.severity} />
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Timestamp</p>
                <p className="text-[#e0e0e0]">{new Date(selected.timestamp).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Blocked</p>
                <span className={selected.blocked ? 'text-[#00ff88]' : 'text-[#ff6b35]'}>
                  {selected.blocked ? 'Yes' : 'No'}
                </span>
              </div>
            </div>

            {/* Full request details */}
            <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3 font-mono text-xs">
              <p className="text-[#00d4ff] font-bold">{selected.method} {selected.path}</p>
              {selected.query_params && (
                <p className="text-[#ffb020] mt-1 break-all">?{selected.query_params}</p>
              )}
              <div className="mt-2 border-t border-[#1e2d4a] pt-2 space-y-1">
                <p className="text-[#8892a0]">User-Agent: <span className="text-[#e0e0e0]">{selected.user_agent || '—'}</span></p>
                <p className="text-[#8892a0]">Referer: <span className="text-[#e0e0e0]">{selected.referer || '—'}</span></p>
                {selected.headers && Object.keys(selected.headers).length > 0 && (
                  <>
                    <p className="text-[#8892a0] mt-1">Headers:</p>
                    {Object.entries(selected.headers).map(([k, v]) => (
                      <p key={k} className="text-[#e0e0e0] pl-2">{k}: {Array.isArray(v) ? v.join(', ') : v}</p>
                    ))}
                  </>
                )}
              </div>
              {selected.body_snippet && (
                <div className="mt-2 border-t border-[#1e2d4a] pt-2">
                  <p className="text-[#8892a0]">Body:</p>
                  <p className="text-[#e0e0e0] break-all mt-1">{selected.body_snippet}</p>
                </div>
              )}
            </div>

            {/* Evidence with highlighted matches */}
            {selected.evidence?.length > 0 && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Evidence (matched patterns)</p>
                <div className="space-y-2">
                  {selected.evidence.map((e, i) => (
                    <div key={i} className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3">
                      <p className="text-[#00d4ff] text-xs font-medium">{e.pattern}</p>
                      <p className="text-[#ff2d55] text-xs mt-1 font-mono break-all bg-[#ff2d5510] px-1 rounded">{e.matched}</p>
                      <p className="text-[#8892a0] text-xs mt-1">Location: {e.location}{e.parameter ? ` (${e.parameter})` : ''}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actor profile summary */}
            {actorSummary && (
              <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3">
                <p className="text-[#8892a0] text-xs mb-2">Actor Profile</p>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div>
                    <span className="text-[#8892a0]">Risk: </span>
                    <span className="text-[#ff6b35] font-bold">{actorSummary.risk_score}</span>
                  </div>
                  <div>
                    <span className="text-[#8892a0]">Total Attacks: </span>
                    <span className="text-[#e0e0e0]">{actorSummary.threat_count}</span>
                  </div>
                  <div>
                    <span className="text-[#8892a0]">Status: </span>
                    <span className="text-[#e0e0e0]">{actorSummary.status}</span>
                  </div>
                </div>
              </div>
            )}

            <div className="flex gap-2 pt-2 border-t border-[#1e2d4a]">
              {!selected.resolved && (
                <button
                  onClick={() => handleResolve(selected.id)}
                  className="px-4 py-1.5 bg-[#00ff88] text-[#0a0f1e] rounded text-xs font-medium hover:bg-[#00e077]"
                >
                  Resolve
                </button>
              )}
              {!selected.false_positive && (
                <button
                  onClick={() => handleFalsePositive(selected.id)}
                  className="px-4 py-1.5 bg-[#1e2d4a] text-[#8892a0] rounded text-xs font-medium hover:text-[#e0e0e0]"
                >
                  False Positive
                </button>
              )}
              <button
                onClick={() => handleBlockIP(selected.ip)}
                className="px-4 py-1.5 bg-[#ff2d55] text-white rounded text-xs font-medium hover:bg-[#e0264d]"
              >
                Block IP
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
