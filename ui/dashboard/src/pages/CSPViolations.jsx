import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import { useWebSocket } from '../hooks/useWebSocket';
import DataTable from '../components/DataTable';
import Pagination from '../components/Pagination';
import StatCard from '../components/StatCard';
import Modal from '../components/Modal';

// CSPViolations renders browser-reported CSP violations as a dedicated view.
// Backend stores them as ThreatEvents with type=CSPViolation; we filter
// the existing threats endpoint and supplement with /csp-violations/stats
// for the grouped "most blocked URIs" panel.
export default function CSPViolations() {
  const { apiFetch } = useAPI();
  const { lastMessage } = useWebSocket('threats');
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [stats, setStats] = useState([]);
  const [selected, setSelected] = useState(null);
  const pageSize = 20;

  const load = useCallback(async () => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
      type: 'CSPViolation',
      sort_by: 'timestamp',
      sort_order: 'desc',
    });
    try {
      const [list, agg] = await Promise.all([
        apiFetch(`/threats?${params}`),
        apiFetch('/csp-violations/stats'),
      ]);
      setRows(list.data || []);
      setTotal(list.meta?.total || 0);
      setStats(agg.data || []);
    } catch {
      // network/auth handled by useAPI
    }
  }, [apiFetch, page]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (lastMessage?.type === 'threat' && lastMessage?.payload?.threat_types?.includes?.('CSPViolation')) {
      load();
    }
  }, [lastMessage, load]);

  // Decode the JSON-encoded violation we tucked into body_snippet at ingest.
  const parseViolation = (row) => {
    if (!row?.body_snippet) return {};
    try { return JSON.parse(row.body_snippet); } catch { return {}; }
  };

  const columns = [
    {
      key: 'violated',
      label: 'Violated Directive',
      render: (_, row) => {
        const v = parseViolation(row);
        return <span className="text-[#ff6b35]">{v.violated_directive || '—'}</span>;
      },
    },
    {
      key: 'blocked',
      label: 'Blocked URI',
      render: (_, row) => {
        const v = parseViolation(row);
        return <span className="font-mono text-xs break-all">{v.blocked_uri || '—'}</span>;
      },
    },
    {
      key: 'document',
      label: 'Document',
      render: (_, row) => {
        const v = parseViolation(row);
        return <span className="text-xs break-all">{v.document_uri || row.path || '—'}</span>;
      },
    },
    { key: 'ip', label: 'Reporter IP' },
    {
      key: 'timestamp',
      label: 'Time',
      render: (v) => new Date(v).toLocaleString(),
    },
  ];

  // Top-of-page stat strip: total, distinct directives, distinct blocked URIs.
  const distinctDirectives = new Set(stats.map((s) => s.violated_directive)).size;
  const distinctBlocked = new Set(stats.map((s) => s.blocked_uri)).size;

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h2 className="text-xl font-semibold text-[#e0e0e0]">CSP Violations</h2>
        <p className="text-xs text-[#8892a0]">
          POST violations to <code className="text-[#00d4ff]">/sentinel/csp-report</code> via the
          <code className="text-[#00d4ff]"> report-uri</code> CSP directive.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <StatCard label="Total Violations" value={total} />
        <StatCard label="Distinct Directives" value={distinctDirectives} color="#ff6b35" />
        <StatCard label="Distinct Blocked URIs" value={distinctBlocked} color="#ff2d55" />
      </div>

      {/* Grouped aggregate — answers "what's actually being blocked?" */}
      {stats.length > 0 && (
        <div className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg overflow-hidden">
          <div className="px-4 py-2 border-b border-[#1e2d4a] text-xs uppercase tracking-wider text-[#8892a0]">
            Top blocked URIs (grouped by directive)
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d4a]">
                <th className="px-4 py-2 text-left text-xs uppercase tracking-wider text-[#8892a0] font-medium">Directive</th>
                <th className="px-4 py-2 text-left text-xs uppercase tracking-wider text-[#8892a0] font-medium">Blocked URI</th>
                <th className="px-4 py-2 text-right text-xs uppercase tracking-wider text-[#8892a0] font-medium">Count</th>
              </tr>
            </thead>
            <tbody>
              {stats.slice(0, 10).map((s, i) => (
                <tr key={i} className="border-b border-[#1e2d4a]/50">
                  <td className="px-4 py-2 text-[#ff6b35]">{s.violated_directive || '—'}</td>
                  <td className="px-4 py-2 font-mono text-xs text-[#e0e0e0] break-all">{s.blocked_uri || '—'}</td>
                  <td className="px-4 py-2 text-right text-[#e0e0e0] font-bold">{s.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <DataTable columns={columns} data={rows} onRowClick={setSelected} emptyText="No CSP violations recorded yet" />
      <Pagination page={page} pageSize={pageSize} total={total} onChange={setPage} />

      <Modal isOpen={!!selected} onClose={() => setSelected(null)} title="CSP Violation Detail">
        {selected && (() => {
          const v = parseViolation(selected);
          return (
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-[#8892a0] text-xs">Document URI</p>
                <p className="text-[#e0e0e0] break-all">{v.document_uri || '—'}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Violated Directive</p>
                <p className="text-[#ff6b35]">{v.violated_directive || '—'}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Effective Directive</p>
                <p className="text-[#e0e0e0]">{v.effective_directive || '—'}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Blocked URI</p>
                <p className="text-[#ff2d55] font-mono text-xs break-all">{v.blocked_uri || '—'}</p>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <p className="text-[#8892a0] text-xs">Source File</p>
                  <p className="text-[#e0e0e0] text-xs break-all">{v.source_file || '—'}</p>
                </div>
                <div>
                  <p className="text-[#8892a0] text-xs">Line</p>
                  <p className="text-[#e0e0e0]">{v.line_number || '—'}</p>
                </div>
                <div>
                  <p className="text-[#8892a0] text-xs">Column</p>
                  <p className="text-[#e0e0e0]">{v.column_number || '—'}</p>
                </div>
              </div>
              {v.script_sample && (
                <div>
                  <p className="text-[#8892a0] text-xs">Script Sample</p>
                  <pre className="bg-[#0a0f1e] border border-[#1e2d4a] rounded p-2 font-mono text-xs text-[#e0e0e0] overflow-x-auto">{v.script_sample}</pre>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-[#1e2d4a]">
                <div>
                  <p className="text-[#8892a0] text-xs">Reporter IP</p>
                  <p className="text-[#e0e0e0]">{selected.ip}</p>
                </div>
                <div>
                  <p className="text-[#8892a0] text-xs">Time</p>
                  <p className="text-[#e0e0e0]">{new Date(selected.timestamp).toLocaleString()}</p>
                </div>
              </div>
            </div>
          );
        })()}
      </Modal>
    </div>
  );
}
