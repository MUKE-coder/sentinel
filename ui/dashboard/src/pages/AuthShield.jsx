import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import DataTable from '../components/DataTable';
import StatCard from '../components/StatCard';

// AuthShield surfaces the live state of brute-force protection:
// who's currently locked, who's in the CAPTCHA tier, and who's accumulating
// failures but not yet at threshold.
export default function AuthShield() {
  const { apiFetch } = useAPI();
  const [snapshot, setSnapshot] = useState({ enabled: false, captcha_provider: '', entries: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const res = await apiFetch('/auth-shield/status');
      setSnapshot(res.data || { enabled: false, captcha_provider: '', entries: [] });
      setError('');
    } catch (e) {
      setError(e?.message || 'Failed to load AuthShield state');
    } finally {
      setLoading(false);
    }
  }, [apiFetch]);

  // Auto-refresh every 10s — this view's value is being current.
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  if (!snapshot.enabled && !loading) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-semibold text-[#e0e0e0]">Auth Shield</h2>
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-6 text-center text-[#8892a0]">
          AuthShield is disabled. Enable it via{' '}
          <code className="text-[#00d4ff]">AuthShieldConfig.Enabled = true</code> in your Sentinel config.
        </div>
      </div>
    );
  }

  const entries = snapshot.entries || [];
  const locked = entries.filter((e) => e.locked).length;
  const captcha = entries.filter((e) => e.captcha_required && !e.locked).length;
  const warming = entries.filter((e) => !e.locked && !e.captcha_required).length;

  const columns = [
    {
      key: 'state',
      label: 'State',
      render: (_, row) => {
        if (row.locked) return <span className="px-2 py-0.5 rounded text-xs bg-[#ff2d55]/20 text-[#ff2d55]">Locked</span>;
        if (row.captcha_required) return <span className="px-2 py-0.5 rounded text-xs bg-[#ff6b35]/20 text-[#ff6b35]">CAPTCHA</span>;
        return <span className="px-2 py-0.5 rounded text-xs bg-[#1e2d4a] text-[#8892a0]">Warming</span>;
      },
    },
    { key: 'ip', label: 'IP', render: (v) => <span className="font-mono">{v}</span> },
    { key: 'failed_attempts', label: 'Failed Attempts', render: (v) => <span className="text-[#e0e0e0] font-bold">{v}</span> },
    {
      key: 'lock_until',
      label: 'Lock Expires',
      render: (v, row) =>
        row.locked && v ? new Date(v).toLocaleString() : <span className="text-[#8892a0]">—</span>,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h2 className="text-xl font-semibold text-[#e0e0e0]">Auth Shield</h2>
        <p className="text-xs text-[#8892a0]">
          CAPTCHA provider:{' '}
          <span className="text-[#00d4ff]">{snapshot.captcha_provider || 'not configured'}</span>
        </p>
      </div>

      {error && (
        <div className="bg-[#ff2d55]/10 border border-[#ff2d55]/30 rounded p-3 text-sm text-[#ff2d55]">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <StatCard label="Locked IPs" value={locked} color="#ff2d55" />
        <StatCard label="CAPTCHA Tier" value={captcha} color="#ff6b35" subtitle={snapshot.captcha_provider ? '' : 'No provider configured — IPs jump straight to lockout'} />
        <StatCard label="Warming IPs" value={warming} color="#00d4ff" subtitle="Accumulating failures" />
      </div>

      <DataTable
        columns={columns}
        data={entries}
        emptyText={loading ? 'Loading…' : 'No tracked IPs — no recent failed logins'}
      />

      {!snapshot.captcha_provider && entries.length > 0 && (
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded p-3 text-xs text-[#8892a0]">
          <strong className="text-[#ff6b35]">Tip:</strong> Configure a CAPTCHA provider
          (hCaptcha, Turnstile, reCAPTCHA, or self-hosted) to add a friction tier between
          warming and lockout. Most credential-stuffing traffic can't solve a CAPTCHA, so
          real users hit a small inconvenience while bots are effectively blocked.
        </div>
      )}
    </div>
  );
}
