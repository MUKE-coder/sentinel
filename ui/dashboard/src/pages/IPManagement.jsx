import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import DataTable from '../components/DataTable';

export default function IPManagement() {
  const { apiFetch } = useAPI();
  const [blocked, setBlocked] = useState([]);
  const [newIP, setNewIP] = useState('');
  const [newReason, setNewReason] = useState('');
  const [error, setError] = useState('');

  const loadBlocked = useCallback(async () => {
    try {
      const res = await apiFetch('/ip/blocked');
      setBlocked(res.data || []);
    } catch {
      // ignore
    }
  }, [apiFetch]);

  useEffect(() => { loadBlocked(); }, [loadBlocked]);

  const handleBlock = async (e) => {
    e.preventDefault();
    setError('');
    if (!newIP.trim()) { setError('IP address is required'); return; }
    try {
      await apiFetch('/ip/block', {
        method: 'POST',
        body: JSON.stringify({ ip: newIP.trim(), reason: newReason.trim() || 'Manually blocked' }),
      });
      setNewIP('');
      setNewReason('');
      loadBlocked();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleUnblock = async (ip) => {
    // Replace / with _ for CIDR in URL
    const urlIP = ip.replace(/\//g, '_');
    await apiFetch(`/ip/block/${urlIP}`, { method: 'DELETE' });
    loadBlocked();
  };

  const columns = [
    { key: 'ip', label: 'IP Address', render: (v, row) => (
      <span className="font-mono">{v}{row.cidr ? ' (CIDR)' : ''}</span>
    )},
    { key: 'reason', label: 'Reason' },
    {
      key: 'blocked_at',
      label: 'Blocked At',
      render: (v) => new Date(v).toLocaleString(),
    },
    {
      key: 'expires_at',
      label: 'Expires',
      render: (v) => v ? new Date(v).toLocaleString() : 'Never',
    },
    {
      key: 'ip',
      label: 'Actions',
      render: (v) => (
        <button
          onClick={(e) => { e.stopPropagation(); handleUnblock(v); }}
          className="px-3 py-1 bg-[#1e2d4a] text-[#8892a0] rounded text-xs hover:text-[#00ff88] hover:border-[#00ff88] transition-colors"
        >
          Unblock
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">IP Management</h2>

      {/* Add block form */}
      <form onSubmit={handleBlock} className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Block IP / CIDR</h3>
        {error && (
          <div className="bg-[#ff2d5520] border border-[#ff2d5540] text-[#ff2d55] px-3 py-2 rounded text-sm mb-3">
            {error}
          </div>
        )}
        <div className="flex gap-3">
          <input
            placeholder="IP or CIDR (e.g. 192.168.1.0/24)"
            value={newIP}
            onChange={(e) => setNewIP(e.target.value)}
            className="flex-1 bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none font-mono"
          />
          <input
            placeholder="Reason"
            value={newReason}
            onChange={(e) => setNewReason(e.target.value)}
            className="flex-1 bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-[#ff2d55] text-white rounded text-sm font-medium hover:bg-[#e0264d] transition-colors"
          >
            Block
          </button>
        </div>
      </form>

      {/* Blocked IPs table */}
      <DataTable columns={columns} data={blocked} emptyText="No blocked IPs" />
    </div>
  );
}
