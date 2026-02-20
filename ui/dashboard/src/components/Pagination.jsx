export default function Pagination({ page, pageSize, total, onChange }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="flex items-center justify-between mt-4 text-sm text-[#8892a0]">
      <span>
        Showing {Math.min((page - 1) * pageSize + 1, total)}–{Math.min(page * pageSize, total)} of {total}
      </span>
      <div className="flex gap-2">
        <button
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          className="px-3 py-1 rounded bg-[#0d1526] border border-[#1e2d4a] disabled:opacity-30 hover:border-[#00d4ff] transition-colors"
        >
          Prev
        </button>
        <span className="px-3 py-1">{page} / {totalPages}</span>
        <button
          disabled={page >= totalPages}
          onClick={() => onChange(page + 1)}
          className="px-3 py-1 rounded bg-[#0d1526] border border-[#1e2d4a] disabled:opacity-30 hover:border-[#00d4ff] transition-colors"
        >
          Next
        </button>
      </div>
    </div>
  );
}
