import { useState, useEffect } from 'react';
import { useAPI } from '../hooks/useAPI';

// Simple mercator projection for lat/lng to SVG coordinates
function project(lat, lng, width, height) {
  const x = ((lng + 180) / 360) * width;
  const latRad = (lat * Math.PI) / 180;
  const mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
  const y = height / 2 - (mercN / Math.PI) * (height / 2);
  return { x, y: Math.max(0, Math.min(height, y)) };
}

const severityColor = {
  Critical: '#ff2d55',
  High: '#ff6b35',
  Medium: '#ffb020',
  Low: '#00d4ff',
};

export default function WorldMap() {
  const { apiFetch } = useAPI();
  const [geoData, setGeoData] = useState([]);
  const width = 700;
  const height = 360;

  useEffect(() => {
    const load = async () => {
      try {
        const res = await apiFetch('/analytics/geographic?window=168h');
        setGeoData(res.data || []);
      } catch {
        // ignore
      }
    };
    load();
  }, [apiFetch]);

  return (
    <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
      <h3 className="text-sm uppercase tracking-wider text-[#8892a0] mb-3">Attack Origins</h3>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        style={{ background: '#0a0f1e', borderRadius: 6 }}
      >
        {/* Grid lines */}
        {[...Array(7)].map((_, i) => (
          <line
            key={`h${i}`}
            x1={0}
            y1={(i * height) / 6}
            x2={width}
            y2={(i * height) / 6}
            stroke="#1e2d4a"
            strokeWidth={0.5}
          />
        ))}
        {[...Array(13)].map((_, i) => (
          <line
            key={`v${i}`}
            x1={(i * width) / 12}
            y1={0}
            x2={(i * width) / 12}
            y2={height}
            stroke="#1e2d4a"
            strokeWidth={0.5}
          />
        ))}

        {/* Attack dots */}
        {geoData.map((point, i) => {
          if (!point.lat && !point.lng) return null;
          const { x, y } = project(point.lat, point.lng, width, height);
          const radius = Math.min(12, Math.max(4, Math.log2(point.count + 1) * 3));
          return (
            <g key={i}>
              <circle
                cx={x}
                cy={y}
                r={radius}
                fill="#ff2d5540"
                stroke="#ff2d55"
                strokeWidth={1}
              />
              <circle cx={x} cy={y} r={2} fill="#ff2d55" />
              <title>
                {point.country} ({point.country_code}): {point.count} attacks
              </title>
            </g>
          );
        })}

        {/* No data message */}
        {geoData.length === 0 && (
          <text
            x={width / 2}
            y={height / 2}
            textAnchor="middle"
            fill="#8892a0"
            fontSize="14"
          >
            No geographic data available
          </text>
        )}
      </svg>
      {geoData.length > 0 && (
        <div className="flex gap-4 mt-3 flex-wrap">
          {geoData.slice(0, 5).map((g) => (
            <span key={g.country_code} className="text-xs text-[#8892a0]">
              <span className="text-[#ff2d55]">{g.country_code}</span>{' '}
              {g.count} attacks
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
