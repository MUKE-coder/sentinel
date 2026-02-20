import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';

export default function RateLimits() {
  const { apiFetch } = useAPI();
  const [config, setConfig] = useState(null);
  const [states, setStates] = useState([]);
  const [newRoute, setNewRoute] = useState('');
  const [newRequests, setNewRequests] = useState('100');
  const [newWindow, setNewWindow] = useState('1m');
  const [error, setError] = useState('');

  const loadData = useCallback(async () => {
    try {
      const [configRes, statesRes] = await Promise.all([
        apiFetch('/rate-limits'),
        apiFetch('/rate-limits/current'),
      ]);
      setConfig(configRes.data);
      setStates(statesRes.data || []);
    } catch {
      // ignore
    }
  }, [apiFetch]);

  useEffect(() => { loadData(); }, [loadData]);

  // Auto-refresh states every 5 seconds
  useEffect(() => {
    const timer = setInterval(async () => {
      try {
        const res = await apiFetch('/rate-limits/current');
        setStates(res.data || []);
      } catch {
        // ignore
      }
    }, 5000);
    return () => clearInterval(timer);
  }, [apiFetch]);

  const handleAddRoute = async () => {
    setError('');
    if (!newRoute.trim()) {
      setError('Route path is required');
      return;
    }
    const requests = parseInt(newRequests, 10);
    if (isNaN(requests) || requests <= 0) {
      setError('Requests must be a positive number');
      return;
    }

    try {
      await apiFetch('/rate-limits', {
        method: 'PUT',
        body: JSON.stringify({
          by_route: { [newRoute]: { requests, window: newWindow } },
        }),
      });
      setNewRoute('');
      setNewRequests('100');
      setNewWindow('1m');
      loadData();
    } catch (err) {
      setError(err.message || 'Failed to update');
    }
  };

  const handleDeleteRoute = async (route) => {
    try {
      await apiFetch('/rate-limits', {
        method: 'PUT',
        body: JSON.stringify({
          by_route: { [route]: { requests: 0, window: '1m' } },
        }),
      });
      loadData();
    } catch {
      // ignore
    }
  };

  const handleReset = async (key) => {
    try {
      await apiFetch(`/rate-limits/reset/${encodeURIComponent(key)}`, { method: 'POST' });
      loadData();
    } catch {
      // ignore
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">Rate Limiting</h2>

      {/* Current Config */}
      {config && (
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Configuration</h3>
          <div className="grid grid-cols-4 gap-4">
            <ConfigCard
              label="Status"
              value={config.enabled ? 'Enabled' : 'Disabled'}
              color={config.enabled ? '#00ff88' : '#8892a0'}
            />
            <ConfigCard
              label="Strategy"
              value={config.strategy || 'sliding_window'}
              color="#00d4ff"
            />
            <ConfigCard
              label="By IP"
              value={config.by_ip ? `${config.by_ip.requests} / ${config.by_ip.window}` : 'Not set'}
              color={config.by_ip ? '#e0e0e0' : '#8892a0'}
            />
            <ConfigCard
              label="Global"
              value={config.global ? `${config.global.requests} / ${config.global.window}` : 'Not set'}
              color={config.global ? '#e0e0e0' : '#8892a0'}
            />
          </div>
        </div>
      )}

      {/* Per-Route Limits */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Per-Route Limits</h3>

        {/* Add route form */}
        <div className="flex gap-2 mb-4">
          <input
            placeholder="/api/endpoint"
            value={newRoute}
            onChange={(e) => setNewRoute(e.target.value)}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none flex-1 font-mono"
          />
          <input
            placeholder="Requests"
            value={newRequests}
            onChange={(e) => setNewRequests(e.target.value)}
            type="number"
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none w-24"
          />
          <select
            value={newWindow}
            onChange={(e) => setNewWindow(e.target.value)}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          >
            <option value="10s">10 seconds</option>
            <option value="30s">30 seconds</option>
            <option value="1m">1 minute</option>
            <option value="5m">5 minutes</option>
            <option value="15m">15 minutes</option>
            <option value="1h">1 hour</option>
          </select>
          <button
            onClick={handleAddRoute}
            className="px-4 py-1.5 bg-[#00d4ff] text-[#0a0f1e] rounded text-sm font-medium hover:bg-[#00bde0]"
          >
            Add
          </button>
        </div>
        {error && <p className="text-[#ff2d55] text-xs mb-3">{error}</p>}

        {/* Routes list */}
        {config?.by_route && Object.keys(config.by_route).length > 0 ? (
          <div className="space-y-2">
            {Object.entries(config.by_route).map(([route, limit]) => (
              <div key={route} className="flex items-center justify-between bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2">
                <div className="flex items-center gap-4 flex-1">
                  <span className="text-[#00d4ff] text-sm font-mono">{route}</span>
                  <span className="text-[#e0e0e0] text-sm">{limit.requests} requests / {limit.window}</span>
                </div>
                <button
                  onClick={() => handleDeleteRoute(route)}
                  className="px-3 py-1 bg-[#ff2d55] text-white rounded text-xs hover:bg-[#e0264d]"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-[#8892a0] text-sm">No per-route limits configured</p>
        )}
      </div>

      {/* Live Rate Limit States */}
      <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0]">
            Live States <span className="text-[#00d4ff]">({states.length} active)</span>
          </h3>
          <button
            onClick={loadData}
            className="px-3 py-1 bg-[#1e2d4a] text-[#00d4ff] rounded text-xs hover:bg-[#2a3d5a]"
          >
            Refresh
          </button>
        </div>

        {states.length > 0 ? (
          <div className="space-y-1">
            <div className="grid grid-cols-4 gap-4 text-xs text-[#8892a0] uppercase tracking-wider pb-1 border-b border-[#1e2d4a]">
              <span>Key</span>
              <span>Count</span>
              <span>Window Expires</span>
              <span>Actions</span>
            </div>
            {states.map((state, i) => {
              const isThrottled = state.count > 50;
              return (
                <div key={i} className="grid grid-cols-4 gap-4 items-center bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-sm">
                  <span className="text-[#00d4ff] font-mono text-xs truncate" title={state.key}>{state.key}</span>
                  <span className={isThrottled ? 'text-[#ff6b35] font-medium' : 'text-[#e0e0e0]'}>
                    {state.count}
                  </span>
                  <span className="text-[#8892a0] text-xs">
                    {new Date(state.window_end).toLocaleTimeString()}
                  </span>
                  <button
                    onClick={() => handleReset(state.key)}
                    className="px-2 py-1 bg-[#1e2d4a] text-[#00d4ff] rounded text-xs hover:bg-[#2a3d5a] w-fit"
                  >
                    Reset
                  </button>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-[#8892a0] text-sm">No active rate limit counters</p>
        )}
      </div>
    </div>
  );
}

function ConfigCard({ label, value, color }) {
  return (
    <div className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-3">
      <div className="text-[#8892a0] text-xs uppercase mb-1">{label}</div>
      <div className="text-sm font-medium" style={{ color }}>{value}</div>
    </div>
  );
}
