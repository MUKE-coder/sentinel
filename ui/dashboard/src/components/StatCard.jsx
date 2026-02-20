export default function StatCard({ label, value, color = '#00d4ff', subtitle }) {
  return (
    <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg p-4">
      <p className="text-[#8892a0] text-xs uppercase tracking-wider mb-1">{label}</p>
      <p className="text-2xl font-bold" style={{ color }}>{value}</p>
      {subtitle && <p className="text-[#8892a0] text-xs mt-1">{subtitle}</p>}
    </div>
  );
}
