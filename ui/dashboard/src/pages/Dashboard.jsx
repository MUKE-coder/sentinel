import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { useAPI } from '../hooks/useAPI';
import { useWebSocket } from '../hooks/useWebSocket';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import SeverityBadge from '../components/SeverityBadge';
import WorldMap from '../components/WorldMap';

const SCORE_COLORS = ['#00d4ff', '#1e2d4a'];

export default function Dashboard() {
  const { apiFetch } = useAPI();
  const { lastMessage } = useWebSocket('threats');
  const [stats, setStats] = useState(null);
  const [threats, setThreats] = useState([]);
  const [score, setScore] = useState(null);

  const loadData = async () => {
    try {
      const [statsRes, threatsRes, scoreRes] = await Promise.all([
        apiFetch('/analytics/summary?window=24h'),
        apiFetch('/threats?page=1&page_size=10&sort_by=timestamp&sort_order=desc'),
        apiFetch('/score'),
      ]);
      setStats(statsRes.data);
      setThreats(threatsRes.data || []);
      setScore(scoreRes.data);
    } catch {
      // API may not have data yet
    }
  };

  useEffect(() => { loadData(); }, []);

  // Refresh when new threat arrives via WebSocket
  useEffect(() => {
    if (lastMessage?.type === 'threat') loadData();
  }, [lastMessage]);

  const threatColumns = [
    { key: 'ip', label: 'IP' },
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
    {
      key: 'timestamp',
      label: 'Time',
      render: (v) => new Date(v).toLocaleTimeString(),
    },
    {
      key: 'blocked',
      label: 'Status',
      render: (v) => (
        <span className={v ? 'text-[#00ff88]' : 'text-[#ff6b35]'}>
          {v ? 'Blocked' : 'Logged'}
        </span>
      ),
    },
  ];

  const scoreData = score
    ? [
        { value: score.overall, color: '#00d4ff' },
        { value: 100 - score.overall, color: '#1e2d4a' },
      ]
    : [];

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">Security Overview</h2>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Threats (24h)" value={stats?.total_threats ?? 0} color="#ff6b35" />
        <StatCard label="Critical" value={stats?.critical_count ?? 0} color="#ff2d55" />
        <StatCard label="Blocked" value={stats?.blocked_count ?? 0} color="#00ff88" />
        <StatCard label="Unique IPs" value={stats?.unique_ips ?? 0} color="#00d4ff" />
      </div>

      {/* World Map */}
      <WorldMap />

      <div className="grid grid-cols-3 gap-6">
        {/* Recent threats */}
        <div className="col-span-2">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Recent Threats</h3>
          <DataTable columns={threatColumns} data={threats} emptyText="No threats detected" />
        </div>

        {/* Security score */}
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Security Score</h3>
          {score ? (
            <>
              <div className="flex justify-center">
                <div className="relative w-40 h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={scoreData}
                        innerRadius={50}
                        outerRadius={70}
                        startAngle={90}
                        endAngle={-270}
                        dataKey="value"
                        stroke="none"
                      >
                        {scoreData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-bold text-[#00d4ff]">{score.overall}</span>
                    <span className="text-sm text-[#8892a0]">Grade {score.grade}</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 space-y-2">
                {[score.threat_activity, score.auth_security, score.response_posture, score.header_compliance, score.rate_limit_coverage].map(
                  (sub) =>
                    sub && (
                      <div key={sub.label} className="flex justify-between text-xs">
                        <span className="text-[#8892a0]">{sub.label}</span>
                        <span className="text-[#e0e0e0]">{sub.score}/100</span>
                      </div>
                    )
                )}
              </div>
            </>
          ) : (
            <p className="text-[#8892a0] text-sm text-center py-8">No score computed yet</p>
          )}
        </div>
      </div>
    </div>
  );
}
