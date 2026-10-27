import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import DataTable from '../components/DataTable';

const HOUR = 60 * 60 * 1000;

// How long a dashboard block lasts. The API applies 24 hours when no expiry
// is sent; "permanent" must be asked for explicitly.
const DURATIONS = [
  { value: '1h', label: '1 hour', ms: HOUR },
  { value: '24h', label: '24 hours', ms: 24 * HOUR },
  { value: '7d', label: '7 days', ms: 7 * 24 * HOUR },
  { value: '30d', label: '30 days', ms: 30 * 24 * HOUR },
  { value: 'permanent', label: 'Permanent' },
];

export default function IPManagement() {
  const { apiFetch } = useAPI();
  const [blocked, setBlocked] = useState([]);
  const [newIP, setNewIP] = useState('');
  const [newReason, setNewReason] = useState('');
  const [duration, setDuration] = useState('24h');
  const [error, setError] = useState('');
  // Repeat-offender sweep: preview first, then block what the preview showed.
  const [sweepThreats, setSweepThreats] = useState(5);
  const [sweepPreview, setSweepPreview] = useState(null);
  const [sweepBusy, setSweepBusy] = useState(false);
  const [sweepResult, setSweepResult] = useState('');

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
    const d = DURATIONS.find((x) => x.value === duration);
    const lifetime = d.ms
      ? { expiry: new Date(Date.now() + d.ms).toISOString() }
      : { permanent: true };
    try {
      await apiFetch('/ip/block', {
        method: 'POST',
        body: JSON.stringify({ ip: newIP.trim(), reason: newReason.trim() || 'Manually blocked', ...lifetime }),
      });
      setNewIP('');
      setNewReason('');
      loadBlocked();
    } catch (err) {
      setError(err.message);
    }
  };

  // A scan comes from dozens of addresses; blocking them one at a time is
  // how a threat log with thousands of rows gets ignored instead of acted
  // on. The preview always runs first, so nothing is blocked unseen.
  const runSweep = async (dryRun) => {
    setSweepBusy(true);
    setError('');
    setSweepResult('');
    try {
      const res = await apiFetch('/ip/block-offenders', {
        method: 'POST',
        body: JSON.stringify({
          min_threats: Number(sweepThreats) || 5,
          since: '168h',
          duration: duration === 'permanent' ? undefined : duration,
          permanent: duration === 'permanent',
          reason: `Bulk block: ${sweepThreats}+ threats in the last 7 days`,
          dry_run: dryRun,
        }),
      });
      const data = res.data || {};
      if (dryRun) {
        setSweepPreview(data);
      } else {
        setSweepPreview(null);
        setSweepResult(`Blocked ${data.blocked} of ${data.matched} matching addresses.`);
        loadBlocked();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setSweepBusy(false);
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
        <div className="flex flex-wrap gap-3">
          <input
            placeholder="IP or CIDR (e.g. 192.168.1.0/24)"
            value={newIP}
            onChange={(e) => setNewIP(e.target.value)}
            className="flex-1 min-w-[12rem] bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none font-mono"
          />
          <input
            placeholder="Reason"
            value={newReason}
            onChange={(e) => setNewReason(e.target.value)}
            className="flex-1 min-w-[12rem] bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          />
          <select
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            aria-label="Block duration"
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          >
            {DURATIONS.map((d) => <option key={d.value} value={d.value}>{d.label}</option>)}
          </select>
          <button
            type="submit"
            className="px-4 py-2 bg-[#ff2d55] text-white rounded text-sm font-medium hover:bg-[#e0264d] transition-colors"
          >
            Block
          </button>
        </div>
        {duration === 'permanent' && (
          <p className="text-[#ffaa00] text-xs mt-2">
            A permanent block never lifts on its own. Addresses get reassigned, so prefer an expiry
            unless you're sure.
          </p>
        )}
      </form>

      {/* Repeat offenders */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-1">Block repeat offenders</h3>
        <p className="text-xs text-[#8892a0] mb-3">
          Blocks every address seen in the last 7 days with at least this many detected threats,
          using the duration selected above. Whitelisted and already-blocked addresses are skipped.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-sm text-[#8892a0]">
            Minimum threats
            <input
              type="number"
              min="1"
              value={sweepThreats}
              onChange={(e) => { setSweepThreats(e.target.value); setSweepPreview(null); }}
              className="ml-2 w-20 bg-[#0a0f1e] border border-[#1e2d4a] rounded px-2 py-1 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
            />
          </label>
          <button
            type="button"
            disabled={sweepBusy}
            onClick={() => runSweep(true)}
            className="px-4 py-2 border border-[#1e2d4a] text-[#e0e0e0] rounded text-sm font-medium hover:border-[#00d4ff] transition-colors disabled:opacity-50"
          >
            {sweepBusy ? 'Working…' : 'Preview'}
          </button>
          {sweepPreview && sweepPreview.matched > 0 && (
            <button
              type="button"
              disabled={sweepBusy}
              onClick={() => runSweep(false)}
              className="px-4 py-2 bg-[#ff2d55] text-white rounded text-sm font-medium hover:bg-[#e0264d] transition-colors disabled:opacity-50"
            >
              Block {sweepPreview.matched} address{sweepPreview.matched === 1 ? '' : 'es'}
            </button>
          )}
        </div>

        {sweepPreview && (
          <div className="mt-3 text-sm">
            {sweepPreview.matched === 0 ? (
              <p className="text-[#8892a0]">No address matches those criteria.</p>
            ) : (
              <>
                <p className="text-[#e0e0e0]">
                  {sweepPreview.matched} address{sweepPreview.matched === 1 ? '' : 'es'} would be blocked
                  {sweepPreview.truncated ? ' (capped at 1000 — run again afterwards)' : ''}:
                </p>
                <p className="mt-1 font-mono text-xs text-[#8892a0] break-all">
                  {sweepPreview.ips.slice(0, 20).join(', ')}
                  {sweepPreview.ips.length > 20 ? ` … and ${sweepPreview.ips.length - 20} more` : ''}
                </p>
              </>
            )}
          </div>
        )}
        {sweepResult && <p className="mt-3 text-sm text-[#00d4ff]">{sweepResult}</p>}
      </div>

      {/* Blocked IPs table */}
      <DataTable columns={columns} data={blocked} emptyText="No blocked IPs" />
    </div>
  );
}
