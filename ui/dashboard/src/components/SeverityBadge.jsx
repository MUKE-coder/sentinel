const colors = {
  Critical: { bg: '#ff2d5520', text: '#ff2d55', border: '#ff2d5540' },
  High: { bg: '#ff6b3520', text: '#ff6b35', border: '#ff6b3540' },
  Medium: { bg: '#ffb02020', text: '#ffb020', border: '#ffb02040' },
  Low: { bg: '#00d4ff20', text: '#00d4ff', border: '#00d4ff40' },
};

export default function SeverityBadge({ severity }) {
  const c = colors[severity] || colors.Low;
  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-medium border"
      style={{ backgroundColor: c.bg, color: c.text, borderColor: c.border }}
    >
      {severity}
    </span>
  );
}
