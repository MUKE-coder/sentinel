import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';

export default function Performance() {
  const { apiFetch } = useAPI();
  const [overview, setOverview] = useState(null);
  const [routes, setRoutes] = useState([]);

  const loadData = useCallback(async () => {
    try {
      const [overviewRes, routesRes] = await Promise.all([
        apiFetch('/performance/overview'),
        apiFetch('/performance/routes'),
      ]);
      setOverview(overviewRes.data);
      setRoutes(routesRes.data || []);
    } catch {
      // ignore
    }
  }, [apiFetch]);

  useEffect(() => { loadData(); }, [loadData]);

  const routeColumns = [
    { key: 'method', label: 'Method', render: (v) => (
      <span className={`font-mono text-xs px-1.5 py-0.5 rounded ${
        v === 'GET' ? 'bg-[#00d4ff20] text-[#00d4ff]' :
        v === 'POST' ? 'bg-[#00ff8820] text-[#00ff88]' :
        v === 'PUT' ? 'bg-[#ffb02020] text-[#ffb020]' :
        v === 'DELETE' ? 'bg-[#ff2d5520] text-[#ff2d55]' :
        'bg-[#1e2d4a] text-[#8892a0]'
      }`}>{v}</span>
    )},
    { key: 'route', label: 'Route', render: (v) => <span className="font-mono">{v || '—'}</span> },
    { key: 'p50_ms', label: 'P50', render: (v) => v != null ? `${v.toFixed(1)}ms` : '—' },
    { key: 'p95_ms', label: 'P95', render: (v) => v != null ? `${v.toFixed(1)}ms` : '—' },
    { key: 'p99_ms', label: 'P99', render: (v) => v != null ? `${v.toFixed(1)}ms` : '—' },
    {
      key: 'error_rate',
      label: 'Error Rate',
      render: (v) => (
        <span className={v > 5 ? 'text-[#ff2d55]' : v > 1 ? 'text-[#ff6b35]' : 'text-[#00ff88]'}>
          {v != null ? `${v.toFixed(1)}%` : '—'}
        </span>
      ),
    },
    { key: 'request_count', label: 'Requests' },
  ];

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">Performance</h2>

      {/* Overview cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Avg Response Time"
          value={overview ? `${overview.avg_response_time_ms?.toFixed(1)}ms` : '—'}
          color="#00d4ff"
        />
        <StatCard
          label="Error Rate"
          value={overview ? `${overview.error_rate?.toFixed(1)}%` : '—'}
          color={overview?.error_rate > 5 ? '#ff2d55' : '#00ff88'}
        />
        <StatCard
          label="Total Requests"
          value={overview?.total_requests ?? '—'}
          color="#00d4ff"
        />
        <StatCard
          label="DB Query Avg"
          value={overview ? `${overview.db_query_avg_ms?.toFixed(1)}ms` : '—'}
          color="#00d4ff"
        />
      </div>

      {/* Route metrics */}
      <div>
        <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Route Latency</h3>
        <DataTable columns={routeColumns} data={routes} emptyText="No performance data yet" />
      </div>
    </div>
  );
}
