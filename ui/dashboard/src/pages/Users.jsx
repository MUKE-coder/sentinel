import { useState, useEffect, useCallback } from 'react';
import { useAPI } from '../hooks/useAPI';
import DataTable from '../components/DataTable';
import Pagination from '../components/Pagination';
import Modal from '../components/Modal';
import SeverityBadge from '../components/SeverityBadge';

export default function Users() {
  const { apiFetch } = useAPI();
  const [users, setUsers] = useState([]);
  const [selected, setSelected] = useState(null);
  const [activity, setActivity] = useState([]);
  const [activityTotal, setActivityTotal] = useState(0);
  const [activityPage, setActivityPage] = useState(1);
  const [userThreats, setUserThreats] = useState([]);

  const loadUsers = useCallback(async () => {
    try {
      const res = await apiFetch('/users');
      setUsers(res.data || []);
    } catch {
      // ignore
    }
  }, [apiFetch]);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const loadUserDetail = useCallback(async (userId) => {
    try {
      const [actRes, threatRes] = await Promise.all([
        apiFetch(`/users/${userId}/activity?page=${activityPage}&page_size=20`),
        apiFetch(`/users/${userId}/threats?page=1&page_size=10`),
      ]);
      setActivity(actRes.data || []);
      setActivityTotal(actRes.meta?.total || 0);
      setUserThreats(threatRes.data || []);
    } catch {
      // ignore
    }
  }, [apiFetch, activityPage]);

  useEffect(() => {
    if (selected) loadUserDetail(selected.user_id);
  }, [selected, loadUserDetail]);

  const handleSelectUser = (user) => {
    setSelected(user);
    setActivityPage(1);
  };

  const userColumns = [
    { key: 'user_id', label: 'User ID' },
    { key: 'email', label: 'Email', render: (v) => v || '—' },
    { key: 'activity_count', label: 'Activity' },
    { key: 'threat_count', label: 'Threats', render: (v) => (
      <span className={v > 0 ? 'text-[#ff6b35]' : 'text-[#e0e0e0]'}>{v}</span>
    )},
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (v) => v ? new Date(v).toLocaleString() : '—',
    },
  ];

  const activityColumns = [
    {
      key: 'timestamp',
      label: 'Time',
      render: (v) => new Date(v).toLocaleString(),
    },
    { key: 'method', label: 'Method' },
    { key: 'path', label: 'Path' },
    { key: 'status_code', label: 'Status' },
    { key: 'duration_ms', label: 'Duration', render: (v) => `${v}ms` },
    { key: 'ip', label: 'IP' },
    {
      key: 'threat_id',
      label: 'Threat',
      render: (v) => v ? (
        <span className="text-[#ff2d55] text-xs">Linked</span>
      ) : null,
    },
  ];

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-[#e0e0e0]">User Activity</h2>

      <DataTable
        columns={userColumns}
        data={users}
        onRowClick={handleSelectUser}
        emptyText="No user activity recorded"
      />

      <Modal
        isOpen={!!selected}
        onClose={() => setSelected(null)}
        title={`User: ${selected?.user_id || ''}`}
      >
        {selected && (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div>
                <p className="text-[#8892a0] text-xs">Activity Count</p>
                <p className="text-[#e0e0e0] text-lg font-bold">{selected.activity_count}</p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Threat Count</p>
                <p className="text-lg font-bold" style={{ color: selected.threat_count > 0 ? '#ff6b35' : '#00ff88' }}>
                  {selected.threat_count}
                </p>
              </div>
              <div>
                <p className="text-[#8892a0] text-xs">Last Seen</p>
                <p className="text-[#e0e0e0]">{new Date(selected.last_seen).toLocaleString()}</p>
              </div>
            </div>

            {/* Linked threats */}
            {userThreats.length > 0 && (
              <div>
                <p className="text-[#8892a0] text-xs mb-2">Recent Threats</p>
                <div className="space-y-2 max-h-32 overflow-auto">
                  {userThreats.map((t) => (
                    <div key={t.id} className="flex items-center gap-2 bg-[#0a0f1e] border border-[#1e2d4a] rounded px-3 py-2 text-xs">
                      <SeverityBadge severity={t.severity} />
                      <span className="text-[#e0e0e0]">{(t.threat_types || []).join(', ')}</span>
                      <span className="text-[#8892a0] ml-auto">{new Date(t.timestamp).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Activity timeline */}
            <div>
              <p className="text-[#8892a0] text-xs mb-2">Activity Timeline</p>
              <DataTable columns={activityColumns} data={activity} emptyText="No activity" />
              <Pagination
                page={activityPage}
                pageSize={20}
                total={activityTotal}
                onChange={setActivityPage}
              />
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
