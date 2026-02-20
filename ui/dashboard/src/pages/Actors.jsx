import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import DataTable from '../components/DataTable';
import SeverityBadge from '../components/SeverityBadge';
import Pagination from '../components/Pagination';
import Modal from '../components/Modal';

export default function Actors() {
  const { apiFetch } = useAPI();
  const [actors, setActors] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [reputation, setReputation] = useState(null);
  const pageSize = 20;

  const loadActors = useCallback(async () => {
    try {
      const res = await apiFetch(`/actors?page=${page}&page_size=${pageSize}`);
      setActors(res.data || []);
      setTotal(res.meta?.total || 0);
    } catch {
      // ignore
    }
  }, [apiFetch, page]);

  useEffect(() => { loadActors(); }, [loadActors]);

  const handleSelect = async (actor) => {
    setSelected(actor);
    setTimeline([]);
    setReputation(null);

    // Load attack timeline and reputation in parallel
    const timelineReq = apiFetch(`/actors/${actor.ip}/requests?limit=20`)
      .then((res) => setTimeline(res.data || []))
      .catch(() => {});

    const repReq = apiFetch(`/ip/reputation/${actor.ip}`)
      .then((res) => setReputation(res.data))
      .catch(() => {});

    await Promise.all([timelineReq, repReq]);
  };

  const handleBlock = async (ip) => {
    await apiFetch(`/actors/${ip}/block`, { method: 'POST' });
    loadActors();
    setSelected(null);
  };

  const statusColor = (s) => {
    switch (s) {
      case 'Blocked': return '#ff2d55';
      case 'Whitelisted': return '#00ff88';
      default: return '#ff6b35';
    }
  };

  const riskColor = (r) => {
    if (r >= 80) return '#ff2d55';
    if (r >= 50) return '#ff6b35';
    if (r >= 20) return '#ffb020';
    return '#00d4ff';
  };

  const columns = [
    { key: 'ip', label: 'IP Address' },
    { key: 'country', label: 'Country', render: (v) => v || '—' },
    {
      key: 'risk_score',
      label: 'Risk',
      render: (v) => <span style={{ color: riskColor(v) }}>{v}</span>,
    },
    {
      key: 'attack_types',
      label: 'Attack Types',
      render: (v) => (v || []).slice(0, 3).join(', ') || '—',
    },
    { key: 'threat_count', label: 'Threats' },
    {
      key: 'status',
      label: 'Status',
      render: (v) => <span style={{ color: statusColor(v) }}>{v}</span>,
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (v) => v ? new Date(v).toLocaleString() : '—',
    },
  ];

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">Threat Actors</h2>

      <DataTable columns={columns} data={actors} onRowClick={handleSelect} emptyText="No threat actors detected" />
      <Pagination page={page} pageSize={pageSize} total={total} onChange={setPage} />

      <Modal isOpen={!!selected} onClose={() => setSelected(null)} title="Actor Profile">
        {selected && (
          <div className="space-y-4 text-sm">
            {/* Header info */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[#8892a0] text-xs">IP Address</p>
                <p className="text-[#e0e0e0] text-lg font-mono">{selected.ip}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Risk Score</p>
                <p className="text-2xl font-bold" style={{ color: riskColor(selected.risk_score) }}>
                  {selected.risk_score}
                </p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Country</p>
                <p className="text-[#e0e0e0]">{selected.country || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">ISP</p>
                <p className="text-[#e0e0e0]">{selected.isp || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Total Requests</p>
                <p className="text-[#e0e0e0]">{selected.total_requests}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Threat Count</p>
                <p className="text-[#ff6b35]">{selected.threat_count}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">First Seen</p>
                <p className="text-[#e0e0e0]">{new Date(selected.first_seen).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Last Seen</p>
                <p className="text-[#e0e0e0]">{new Date(selected.last_seen).toLocaleString()}</p>
              </div>
            </div>

            {/* AbuseIPDB reputation */}
            {reputation && (
              <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3">
                <p className="text-[#8892a0] text-xs mb-2">IP Reputation (AbuseIPDB)</p>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div>
                    <span className="text-[#8892a0]">Abuse Score: </span>
                    <span className={reputation.abuse_score >= 50 ? 'text-[#ff2d55] font-bold' : 'text-[#e0e0e0]'}>
                      {reputation.abuse_score}%
                    </span>
                  </div>
                  <div>
                    <span className="text-[#8892a0]">Reports: </span>
                    <span className="text-[#e0e0e0]">{reputation.total_reports}</span>
                  </div>
                  <div>
                    <span className="text-[#8892a0]">ISP: </span>
                    <span className="text-[#e0e0e0]">{reputation.isp || '—'}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Attack types */}
            {selected.attack_types?.length > 0 && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Attack Types</p>
                <div className="flex gap-2 flex-wrap">
                  {selected.attack_types.map((t) => (
                    <span key={t} className="px-2 py-1 bg-[#0a0f1e] border border-[#1e2d4a] rounded text-xs text-[#00d4ff]">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Targeted routes */}
            {selected.targeted_routes?.length > 0 && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Targeted Routes</p>
                <div className="flex gap-2 flex-wrap">
                  {selected.targeted_routes.map((r) => (
                    <span key={r} className="px-2 py-1 bg-[#0a0f1e] border border-[#1e2d4a] rounded text-xs text-[#e0e0e0] font-mono">
                      {r}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Attack timeline */}
            {timeline.length > 0 && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Attack Timeline (Recent)</p>
                <div className="space-y-1 max-h-60 overflow-y-auto">
                  {timeline.map((req, i) => (
                    <div key={i} className="flex items-center gap-3 bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-xs">
                      <span className="text-[#8892a0] shrink-0 w-36">
                        {new Date(req.timestamp).toLocaleString()}
                      </span>
                      <span className="text-[#00d4ff] font-mono shrink-0 w-12">{req.method}</span>
                      <span className="text-[#e0e0e0] font-mono truncate flex-1">{req.path}</span>
                      <SeverityBadge severity={req.severity} />
                      <span className={req.blocked ? 'text-[#00ff88]' : 'text-[#ff6b35]'}>
                        {req.blocked ? 'Blocked' : 'Logged'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            {selected.status !== 'Blocked' && (
              <div className="pt-2 border-t border-[#1e2d4a]">
                <button
                  onClick={() => handleBlock(selected.ip)}
                  className="px-4 py-1.5 bg-[#ff2d55] text-white rounded text-xs font-medium hover:bg-[#e0264d]"
                >
                  Block Actor
                </button>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
